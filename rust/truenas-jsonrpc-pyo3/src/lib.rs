//! The PyO3 bridge — runs `truenas-jsonrpc` `python:true` method bodies in an embedded
//! CPython interpreter. It implements the core's [`PyDispatcher`] seam by calling a Python
//! `dispatch(name, params_json, session_json) -> (status, payload, audit)` callable (the
//! contract `api-specs/gen.py --python-out` emits): `status == 0` ⇒ `payload` is the result
//! JSON; a non-zero `status` is the JSON-RPC error code and `payload` is the message;
//! `audit` is the body's audit detail (`b""` for none).
//!
//! The Rust spine still does routing / the session gate / authorization / audit — only the
//! body crosses the FFI. The body runs on the core's blocking pool (the GIL is held only
//! inside [`Python::with_gil`], never across an `.await`), so GIL contention can't stall the
//! async runtime. This crate is **opt-in**: the default workspace build links no libpython.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::value::RawValue;
use truenas_jsonrpc::{ErrorCode, JsonRpcError, PyDispatcher, PyOutcome, PyResult};

/// A [`PyDispatcher`] backed by a Python `dispatch(name, params, session)` callable held as
/// a GIL-independent [`Py<PyAny>`].
pub struct PyBridge {
    dispatch: Py<PyAny>,
}

impl PyBridge {
    /// Wrap an existing Python callable that implements the dispatch contract.
    pub fn new(dispatch: Py<PyAny>) -> Self {
        Self { dispatch }
    }

    /// Import the Python `module` (e.g. the generated `rpc_py`) and wrap its `dispatch`
    /// attribute, initializing the embedded interpreter on first use.
    pub fn import(module: &str) -> Result<Self, BridgeError> {
        Python::with_gil(|py| {
            let m = py.import(module).map_err(|e| BridgeError(e.to_string()))?;
            let f = m.getattr("dispatch").map_err(|e| BridgeError(e.to_string()))?;
            Ok(Self { dispatch: f.unbind() })
        })
    }
}

impl PyDispatcher for PyBridge {
    fn dispatch(&self, name: &str, params_json: &[u8], session_json: &[u8]) -> PyResult {
        Python::with_gil(|py| {
            let callable = self.dispatch.bind(py);
            let args = (name, PyBytes::new(py, params_json), PyBytes::new(py, session_json));
            match callable.call1(args).and_then(|r| r.extract::<(i64, Vec<u8>, Vec<u8>)>()) {
                Ok((status, payload, audit)) => decode_outcome(status, &payload, &audit),
                Err(err) => {
                    // An uncaught Python exception or a bad return tuple → INTERNAL_ERROR; the
                    // traceback goes to stderr (the body owns its own error handling otherwise).
                    err.print(py);
                    PyResult {
                        outcome: PyOutcome::Error(JsonRpcError::new(
                            ErrorCode::InternalError,
                            "Internal error",
                        )),
                        audit_message: None,
                    }
                }
            }
        })
    }
}

/// Map the Python `(status, payload, audit)` tuple onto a [`PyResult`].
fn decode_outcome(status: i64, payload: &[u8], audit: &[u8]) -> PyResult {
    let audit_message = (!audit.is_empty()).then(|| String::from_utf8_lossy(audit).into_owned());
    let outcome = if status == 0 {
        match RawValue::from_string(String::from_utf8_lossy(payload).into_owned()) {
            Ok(raw) => PyOutcome::Ok(raw),
            Err(e) => PyOutcome::Error(JsonRpcError::internal(format!(
                "python result was not valid JSON: {e}"
            ))),
        }
    } else {
        // A non-zero status is the JSON-RPC error code; the payload is the message.
        PyOutcome::Error(JsonRpcError::custom(
            status as i32,
            String::from_utf8_lossy(payload).into_owned(),
        ))
    };
    PyResult { outcome, audit_message }
}

/// An error importing the Python module or its `dispatch` attribute.
#[derive(Debug)]
pub struct BridgeError(String);

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "python bridge error: {}", self.0)
    }
}

impl std::error::Error for BridgeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::Arc;

    use pyo3::types::PyModule;
    use serde_json::Value;
    use truenas_jsonrpc::{Dispatched, JsonRpcProtocol, MethodDef, NullOutbound};

    const ID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

    /// Build a `PyBridge` over an inline Python `dispatch` implementing the contract.
    fn bridge() -> PyBridge {
        let code = CString::new(
            r#"
import json
def dispatch(name, params, session):
    if name == "py.echo":
        p = json.loads(params)
        s = json.loads(session)
        out = {"echoed": p, "lifecycle": s["lifecycle"]}
        return (0, json.dumps(out).encode(), b"echoed in python")
    if name == "py.boom":
        return (-32603, b"boom", b"")
    return (-32601, b"Method not found", b"")
"#,
        )
        .unwrap();
        Python::with_gil(|py| {
            let m = PyModule::from_code(
                py,
                code.as_c_str(),
                &CString::new("bridge.py").unwrap(),
                &CString::new("bridge").unwrap(),
            )
            .unwrap();
            PyBridge::new(m.getattr("dispatch").unwrap().unbind())
        })
    }

    async fn call(proto: &JsonRpcProtocol<()>, method: &str, params: &str) -> Value {
        let s = proto.new_session(Some(()), Arc::new(NullOutbound));
        let wire = format!(r#"{{"jsonrpc":"2.0","method":"{method}","id":"{ID}","params":{params}}}"#);
        match proto.dispatch(wire.as_bytes(), &s).await {
            Dispatched::Reply(b) => serde_json::from_slice(&b).unwrap(),
            Dispatched::Nothing => panic!("expected a reply"),
        }
    }

    #[tokio::test]
    async fn python_body_runs_and_sees_params_and_session() {
        let proto = JsonRpcProtocol::<()>::builder("t", "1")
            .python_method(MethodDef::new("py.echo"))
            .unwrap()
            .python_method(MethodDef::new("py.boom"))
            .unwrap()
            .python_dispatcher(bridge())
            .build();

        // Success: the body received the params + the session view (lifecycle 0 = None).
        let v = call(&proto, "py.echo", r#"{"x": 1}"#).await;
        assert_eq!(v["result"]["echoed"]["x"], 1);
        assert_eq!(v["result"]["lifecycle"], 0);

        // Error: a non-zero status becomes the JSON-RPC error code.
        let v = call(&proto, "py.boom", "{}").await;
        assert_eq!(v["error"]["code"], -32603);
    }

    #[test]
    fn decode_outcome_maps_status_payload_audit() {
        // ok + audit
        let r = decode_outcome(0, br#"{"ok":true}"#, b"did it");
        assert!(matches!(r.outcome, PyOutcome::Ok(_)));
        assert_eq!(r.audit_message.as_deref(), Some("did it"));
        // error, no audit
        let r = decode_outcome(-32602, b"bad", b"");
        assert!(matches!(r.outcome, PyOutcome::Error(e) if e.code == -32602));
        assert_eq!(r.audit_message, None);
        // ok but non-JSON payload → internal error
        let r = decode_outcome(0, b"not json", b"");
        assert!(matches!(r.outcome, PyOutcome::Error(e) if e.code == -32603));
    }

    #[test]
    fn bridge_error_displays() {
        let e = BridgeError("no module".to_string());
        assert!(format!("{e}").contains("no module"));
    }
}
