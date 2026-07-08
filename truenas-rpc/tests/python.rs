//! The python-method dispatch path (`PyDispatcher` seam) exercised with a **mock**
//! dispatcher — no libpython. Verifies that the spine routes/gates/authorizes/audits a
//! `python:true` method and passes the params + session view to the body, while only the
//! body crosses the seam.

use std::sync::{Arc, Mutex};

use serde_json::value::to_raw_value;
use serde_json::Value;
use truenas_rpc::{
    AuditOutcome, InProcessCaller, JsonRpcError, JsonRpcProtocol, MethodDef, NullOutbound,
    PyOutcome, PyResult, RequestCtx, RequestInfo, Roles, RpcMethod, Session,
};

const ID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

/// Mock Python bridge: `py.echo` returns the params + session view it received (so the
/// test can assert they crossed the seam) with an audit detail; `py.fail` raises; the
/// `py.viacall*` methods reach back into the core through `caller` (the `call` seam).
fn mock(
    name: &str,
    params_json: &[u8],
    session_json: &[u8],
    caller: Arc<dyn InProcessCaller>,
) -> PyResult {
    match name {
        "py.echo" => {
            let echo: Value = serde_json::from_slice(params_json).unwrap();
            let session: Value = serde_json::from_slice(session_json).unwrap();
            let result = serde_json::json!({ "echo": echo, "session": session });
            PyResult {
                outcome: PyOutcome::Ok(to_raw_value(&result).unwrap()),
                audit_message: Some("echoed".to_string()),
            }
        }
        "py.fail" => PyResult {
            outcome: PyOutcome::Error(JsonRpcError::invalid_params("bad params")),
            audit_message: None,
        },
        // A body reaching back into the core via `call`: call another registered method in-process.
        "py.viacall" => via_call(caller.as_ref(), "op_add", false),
        "py.viacall_elev" => via_call(caller.as_ref(), "op_guarded", true),
        "py.viacall_gated" => via_call(caller.as_ref(), "op_guarded", false),
        _ => PyResult {
            outcome: PyOutcome::Error(JsonRpcError::internal("?")),
            audit_message: None,
        },
    }
}

/// A python body's in-process call through the caller (`call`), **byte in/out**: encode a fixed `Pair`
/// to JSON, call `name` (elevated?), and hand back the bare-JSON result — or surface the core's error
/// (e.g. a role-gate denial). The python side owns the types, so `call` is a byte boundary.
fn via_call(caller: &dyn InProcessCaller, name: &str, elevated: bool) -> PyResult {
    let params = serde_json::to_vec(&Pair { a: 2, b: 40 }).unwrap();
    match caller.call_json(name, &params, elevated) {
        Ok(raw) => PyResult {
            outcome: PyOutcome::Ok(raw),
            audit_message: None,
        },
        Err(e) => PyResult {
            outcome: PyOutcome::Error(e),
            audit_message: None,
        },
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Pair {
    a: i64,
    b: i64,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Sum {
    sum: i64,
}

async fn dispatch(proto: &JsonRpcProtocol<()>, wire: &str) -> Value {
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let bytes = proto
        .dispatch(wire.as_bytes(), &s)
        .await
        .into_bytes()
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn python_ok_passes_params_and_session_view_and_audits() {
    let records = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let rec = records.clone();
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .python_method(MethodDef::new("py.echo").audit_message("call"))
        .unwrap()
        .python_dispatcher(mock)
        .audit_sink(
            move |req: &RequestInfo,
                  _outcome: AuditOutcome<'_>,
                  _s: &Session<()>,
                  msg: Option<&str>| {
                rec.lock()
                    .unwrap()
                    .push((req.method.clone(), msg.map(str::to_string)));
            },
        )
        .build();

    let wire = format!(r#"{{"jsonrpc":"2.0","method":"py.echo","id":"{ID}","params":{{"x":1}}}}"#);
    let v = dispatch(&proto, &wire).await;

    // The body received the params and a session view (id + lifecycle 0=None + external null).
    assert_eq!(v["result"]["echo"]["x"], 1);
    assert!(v["result"]["session"]["session_id"].is_string());
    assert_eq!(v["result"]["session"]["lifecycle"], 0);
    assert!(v["result"]["session"]["external"].is_null());

    // Audited: the static `audit_message` joined with the body's runtime detail.
    let recs = records.lock().unwrap();
    assert_eq!(
        recs.as_slice(),
        &[("py.echo".to_string(), Some("call echoed".to_string()))]
    );
}

#[tokio::test]
async fn python_error_is_returned() {
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .python_method(MethodDef::new("py.fail"))
        .unwrap()
        .python_dispatcher(mock)
        .build();
    let wire = format!(r#"{{"jsonrpc":"2.0","method":"py.fail","id":"{ID}","params":{{}}}}"#);
    let v = dispatch(&proto, &wire).await;
    assert_eq!(v["error"]["code"], -32602); // INVALID_PARAMS, raised by the body
}

#[tokio::test]
async fn python_without_dispatcher_is_internal_error() {
    // A python method registered but no `python_dispatcher` set → degrade to INTERNAL_ERROR.
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .python_method(MethodDef::new("py.echo"))
        .unwrap()
        .build();
    let wire = format!(r#"{{"jsonrpc":"2.0","method":"py.echo","id":"{ID}","params":{{}}}}"#);
    let v = dispatch(&proto, &wire).await;
    assert_eq!(v["error"]["code"], -32603); // INTERNAL_ERROR
}

#[tokio::test]
async fn python_respects_authorization() {
    // A method whose required role the session lacks is gated (the dispatcher is never consulted).
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .roles(Roles::new(["AUTH"]))
        .python_method(MethodDef::new("py.echo").roles(["AUTH"]))
        .unwrap()
        .python_dispatcher(mock)
        .build();
    let wire = format!(r#"{{"jsonrpc":"2.0","method":"py.echo","id":"{ID}","params":{{}}}}"#);
    let v = dispatch(&proto, &wire).await;
    assert_eq!(v["error"]["code"], -32000); // NOT_AUTHORIZED
}

#[tokio::test]
async fn python_body_calls_into_the_core_via_the_caller() {
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .roles(Roles::new(["ADMIN"]))
        .method(RpcMethod::new(
            MethodDef::new("op_add"),
            |p: Pair, _c: &RequestCtx<()>| Ok::<_, JsonRpcError>(Sum { sum: p.a + p.b }),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("op_guarded").roles(["ADMIN"]),
            |p: Pair, _c: &RequestCtx<()>| Ok::<_, JsonRpcError>(Sum { sum: p.a + p.b }),
        ))
        .unwrap()
        .python_method(MethodDef::new("py.viacall"))
        .unwrap()
        .python_method(MethodDef::new("py.viacall_elev"))
        .unwrap()
        .python_method(MethodDef::new("py.viacall_gated"))
        .unwrap()
        .python_dispatcher(mock)
        .build();

    let wire = |m: &str| format!(r#"{{"jsonrpc":"2.0","method":"{m}","id":"{ID}","params":{{}}}}"#);

    // The body reaches `op_add` in-process through `call` and returns its typed result.
    assert_eq!(
        dispatch(&proto, &wire("py.viacall")).await["result"]["sum"],
        42
    );
    // An elevated call from the body bypasses the gate (the fresh session lacks ADMIN).
    assert_eq!(
        dispatch(&proto, &wire("py.viacall_elev")).await["result"]["sum"],
        42
    );
    // A non-elevated call is gated as-the-caller — the denial surfaces back to the body.
    assert_eq!(
        dispatch(&proto, &wire("py.viacall_gated")).await["error"]["code"],
        -32000
    );
}
