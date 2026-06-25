//! The embedded-CPython bridge — runs `truenas-jsonrpc` `python:true` method bodies in an
//! embedded CPython interpreter. It implements the core's [`PyDispatcher`] seam by calling a
//! Python `dispatch(name, params_json, session_json) -> (status, payload, audit)` callable (the
//! contract `gen.py --python-out` emits): `status == 0` ⇒ `payload` is the result JSON; a
//! non-zero `status` is the JSON-RPC error code and `payload` is the message; `audit` is the
//! body's audit detail (`b""` for none).
//!
//! It speaks the raw CPython C-API directly through [`pyo3_ffi`] (no pyo3 framework, no
//! proc-macros) — the Rust analogue of Zig's hand-declared `pybridge`. The Rust spine still does
//! routing / the session gate / authorization / audit — only the body crosses the FFI. The body
//! runs on the core's blocking pool (the GIL is held only inside a [`Gil`] guard, never across
//! an `.await`), so GIL contention can't stall the async runtime. This crate is **opt-in**: the
//! default workspace build links no libpython.

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Once;

use pyo3_ffi as ffi;
use serde_json::value::RawValue;
use truenas_jsonrpc::{ErrorCode, JsonRpcError, PyDispatcher, PyOutcome, PyResult};

/// Bring up the embedded interpreter exactly once. After `Py_InitializeEx` the calling thread
/// holds the GIL; `PyEval_SaveThread` releases it (and arms the per-thread GIL-state machinery)
/// so any blocking-pool worker can later acquire it via [`Gil`]. Process-global, like Zig's
/// single `Py_Initialize`; we never finalize (a long-running server), matching pyo3's
/// `auto-initialize`.
#[allow(unsafe_code)]
fn ensure_initialized() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: guarded by `Once`, so `Py_InitializeEx` runs exactly once; `PyEval_SaveThread`
        // is the documented way to release the init thread's GIL for later `PyGILState_Ensure`.
        unsafe {
            ffi::Py_InitializeEx(0); // 0 = don't install signal handlers (we're a guest)
            let _ = ffi::PyEval_SaveThread();
        }
    });
}

/// RAII GIL guard: acquire on construction (initializing the interpreter on first use), release
/// on drop. Held only inside a synchronous dispatch — never across an `.await`.
struct Gil(ffi::PyGILState_STATE);

impl Gil {
    #[allow(unsafe_code)]
    fn acquire() -> Self {
        ensure_initialized();
        // SAFETY: the interpreter is initialized; `PyGILState_Ensure` is valid from any thread
        // and pairs with the `PyGILState_Release` in `Drop`.
        Gil(unsafe { ffi::PyGILState_Ensure() })
    }
}

impl Drop for Gil {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.0` is the state returned by the matching `PyGILState_Ensure`.
        unsafe { ffi::PyGILState_Release(self.0) }
    }
}

/// A [`PyDispatcher`] backed by a Python `dispatch(name, params, session)` callable, held as an
/// owned reference for the bridge's lifetime.
pub struct PyBridge {
    dispatch: *mut ffi::PyObject,
}

// SAFETY: `dispatch` is a CPython object pointer that is only ever dereferenced/called while the
// GIL is held (every access goes through a `Gil` guard), so it is safe to send and share across
// threads — the same justification pyo3 uses for its `Py<T>` smart pointer.
#[allow(unsafe_code)]
unsafe impl Send for PyBridge {}
#[allow(unsafe_code)]
unsafe impl Sync for PyBridge {}

impl PyBridge {
    /// Import the Python `module` (e.g. the generated `rpc_py`) and hold its `dispatch`
    /// attribute, initializing the embedded interpreter on first use.
    #[allow(unsafe_code)]
    pub fn import(module: &str) -> Result<Self, BridgeError> {
        let _gil = Gil::acquire();
        let cmodule = cstring(module)?;
        // SAFETY: GIL held. `PyImport_ImportModule` returns a new ref (or null on error);
        // `PyObject_GetAttrString` returns a new ref we keep; the module ref is released.
        unsafe {
            let m = ffi::PyImport_ImportModule(cmodule.as_ptr());
            if m.is_null() {
                return Err(take_py_err("import"));
            }
            let dispatch = ffi::PyObject_GetAttrString(m, b"dispatch\0".as_ptr().cast::<c_char>());
            ffi::Py_XDECREF(m);
            if dispatch.is_null() {
                return Err(take_py_err("getattr dispatch"));
            }
            Ok(PyBridge { dispatch })
        }
    }

    /// Execute `code` in the interpreter's `__main__` namespace and hold the `dispatch` it
    /// defines. Primarily for tests / simple embedding; production uses [`PyBridge::import`].
    #[allow(unsafe_code)]
    pub fn from_source(code: &str) -> Result<Self, BridgeError> {
        let _gil = Gil::acquire();
        let ccode = cstring(code)?;
        // SAFETY: GIL held. `PyRun_SimpleString` execs `code` in `__main__`; we then import the
        // (already-loaded) `__main__` module and take its `dispatch` (a new ref we keep).
        unsafe {
            if ffi::PyRun_SimpleString(ccode.as_ptr()) != 0 {
                return Err(take_py_err("exec source"));
            }
            let m = ffi::PyImport_ImportModule(b"__main__\0".as_ptr().cast::<c_char>());
            if m.is_null() {
                return Err(take_py_err("import __main__"));
            }
            let dispatch = ffi::PyObject_GetAttrString(m, b"dispatch\0".as_ptr().cast::<c_char>());
            ffi::Py_XDECREF(m);
            if dispatch.is_null() {
                return Err(take_py_err("getattr dispatch"));
            }
            Ok(PyBridge { dispatch })
        }
    }

    /// Build the `(name, params, session)` argument tuple, call the Python `dispatch`, and map
    /// its `(status, payload, audit)` return onto a [`PyResult`]. Mirrors Zig's `callLocked`.
    /// Must run with the GIL held.
    #[allow(unsafe_code)]
    unsafe fn call_locked(&self, name: &str, params: &[u8], session: &[u8]) -> PyResult {
        let args = ffi::PyTuple_New(3);
        if args.is_null() {
            return clear_and_internal();
        }
        // `PyTuple_SetItem` STEALS its item ref, so on success we only DecRef `args` (which frees
        // its items). Build all three items first so a mid-build failure can DecRef cleanly.
        let py_name =
            ffi::PyUnicode_FromStringAndSize(name.as_ptr().cast::<c_char>(), to_ssize(name.len()));
        if py_name.is_null() {
            ffi::Py_XDECREF(args);
            return clear_and_internal();
        }
        let py_params = ffi::PyBytes_FromStringAndSize(
            params.as_ptr().cast::<c_char>(),
            to_ssize(params.len()),
        );
        if py_params.is_null() {
            ffi::Py_XDECREF(py_name);
            ffi::Py_XDECREF(args);
            return clear_and_internal();
        }
        let py_sess = ffi::PyBytes_FromStringAndSize(
            session.as_ptr().cast::<c_char>(),
            to_ssize(session.len()),
        );
        if py_sess.is_null() {
            ffi::Py_XDECREF(py_name);
            ffi::Py_XDECREF(py_params);
            ffi::Py_XDECREF(args);
            return clear_and_internal();
        }
        ffi::PyTuple_SetItem(args, 0, py_name);
        ffi::PyTuple_SetItem(args, 1, py_params);
        ffi::PyTuple_SetItem(args, 2, py_sess);

        let result = ffi::PyObject_CallObject(self.dispatch, args);
        ffi::Py_XDECREF(args);
        if result.is_null() {
            return clear_and_internal(); // the handler raised (uncaught) → INTERNAL_ERROR
        }

        // Expected shape: (status:int, payload:bytes, audit:bytes). `PyTuple_GetItem` borrows.
        let status_obj = ffi::PyTuple_GetItem(result, 0);
        if status_obj.is_null() {
            ffi::Py_XDECREF(result);
            return clear_and_internal();
        }
        let status = ffi::PyLong_AsLong(status_obj);
        if !ffi::PyErr_Occurred().is_null() {
            ffi::Py_XDECREF(result);
            return clear_and_internal();
        }
        let payload = match extract_bytes(ffi::PyTuple_GetItem(result, 1)) {
            Some(p) => p,
            None => {
                ffi::Py_XDECREF(result);
                return clear_and_internal();
            }
        };
        let audit = extract_bytes(ffi::PyTuple_GetItem(result, 2)).unwrap_or_default();
        ffi::Py_XDECREF(result);

        decode_outcome(status as i64, &payload, &audit)
    }
}

impl PyDispatcher for PyBridge {
    #[allow(unsafe_code)]
    fn dispatch(&self, name: &str, params_json: &[u8], session_json: &[u8]) -> PyResult {
        let _gil = Gil::acquire();
        // SAFETY: the GIL is held for the whole call (the guard drops at end of scope), and
        // `self.dispatch` is a live callable held since construction.
        unsafe { self.call_locked(name, params_json, session_json) }
    }
}

impl Drop for PyBridge {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        let _gil = Gil::acquire();
        // SAFETY: GIL held; `self.dispatch` is the owned ref taken at construction.
        unsafe { ffi::Py_XDECREF(self.dispatch) }
    }
}

/// `len as Py_ssize_t`, saturating at `Py_ssize_t::MAX` (our buffers never approach it; this just
/// keeps the cast total).
fn to_ssize(len: usize) -> ffi::Py_ssize_t {
    len.min(ffi::Py_ssize_t::MAX as usize) as ffi::Py_ssize_t
}

/// Copy a Python `bytes` object's contents into an owned `Vec` (so the result is independent of
/// the Python object's lifetime). `None` if `obj` is null / not a `bytes`. Must run with the GIL
/// held. Mirrors Zig's `extractBytes`.
#[allow(unsafe_code)]
unsafe fn extract_bytes(obj: *mut ffi::PyObject) -> Option<Vec<u8>> {
    if obj.is_null() {
        return None;
    }
    let mut buf: *mut c_char = std::ptr::null_mut();
    let mut len: ffi::Py_ssize_t = 0;
    if ffi::PyBytes_AsStringAndSize(obj, &mut buf, &mut len) != 0 {
        ffi::PyErr_Clear();
        return None;
    }
    Some(std::slice::from_raw_parts(buf.cast::<u8>(), len as usize).to_vec())
}

/// Clear any pending Python error (printing the traceback to stderr — a bridge fault is a server
/// bug, not a client one) and return the canonical INTERNAL_ERROR. Must run with the GIL held.
/// Mirrors Zig's `clearAndInternal`.
#[allow(unsafe_code)]
unsafe fn clear_and_internal() -> PyResult {
    if !ffi::PyErr_Occurred().is_null() {
        ffi::PyErr_Print();
        ffi::PyErr_Clear();
    }
    PyResult {
        outcome: PyOutcome::Error(JsonRpcError::new(ErrorCode::InternalError, "Internal error")),
        audit_message: None,
    }
}

/// Print + clear a pending Python error and wrap `context` in a [`BridgeError`]. Must run with
/// the GIL held.
#[allow(unsafe_code)]
unsafe fn take_py_err(context: &str) -> BridgeError {
    if !ffi::PyErr_Occurred().is_null() {
        ffi::PyErr_Print();
        ffi::PyErr_Clear();
    }
    BridgeError(format!("python {context} failed"))
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

/// Build a NUL-terminated C string from `s`, mapping an interior NUL to a [`BridgeError`].
fn cstring(s: &str) -> Result<CString, BridgeError> {
    CString::new(s).map_err(|e| BridgeError(e.to_string()))
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
    use std::sync::Arc;

    use serde_json::Value;
    use truenas_jsonrpc::{Dispatched, JsonRpcProtocol, MethodDef, NullOutbound};

    const ID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

    /// Build a `PyBridge` over an inline Python `dispatch` implementing the contract.
    fn bridge() -> PyBridge {
        PyBridge::from_source(
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
        .unwrap()
    }

    async fn call(proto: &JsonRpcProtocol<()>, method: &str, params: &str) -> Value {
        let s = proto.new_session(Some(()), Arc::new(NullOutbound));
        let wire = format!(r#"{{"jsonrpc":"2.0","method":"{method}","id":"{ID}","params":{params}}}"#);
        match proto.dispatch(wire.as_bytes(), &s).await {
            Dispatched::Reply(b) => serde_json::from_slice(&b).unwrap(),
            Dispatched::Nothing => panic!("expected a reply"),
            Dispatched::Transfer(_) | Dispatched::Passthrough(_) => panic!("unexpected transfer/passthrough"),
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
