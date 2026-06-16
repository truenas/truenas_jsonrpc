//! A/B differential conformance test — the gating proof of wire-compatibility.
//!
//! `rust/conformance/generate.py` runs a fixed request corpus through the **Python**
//! reference implementation and records responses + audit records in
//! `conformance/golden.json`. This test builds the **same** two reference protocols
//! (`open` and `gated`) in Rust, replays each corpus request through `dispatch`, and
//! asserts the result matches Python's, structurally.
//!
//! Comparison rule: success responses must match in full; error responses must match
//! on `{jsonrpc, id, error.code, error.message}` — `error.data` (the implementation's
//! free-form decode/validation detail) is stripped before comparison, since msgspec and
//! serde phrase it differently. Audit records (method, redacted params, redacted
//! response, message) must match too.
//!
//! Keep `build_open`/`build_gated` here in sync with the factories in `generate.py`.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_jsonrpc::{
    AuthorizationResponse, CancelTarget, Dispatched, JsonRpcError, JsonRpcMethod, JsonRpcProtocol,
    JsonRpcRequest, MethodDef, NullOutbound, RequestCtx, Session, SessionLifecycle,
};

const GOLDEN: &str = include_str!("conformance/golden.json");

#[derive(Deserialize)]
struct Empty {}
#[derive(Deserialize, Serialize)]
struct EchoArgs {
    msg: String,
}
#[derive(Serialize)]
struct EchoResult {
    echo: String,
}
#[derive(Deserialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Serialize)]
struct AddResult {
    sum: i64,
}
#[derive(Serialize)]
struct OkResult {
    ok: bool,
}
#[derive(Serialize)]
struct PingResult {
    pong: bool,
}
#[derive(Deserialize)]
struct AuditArgs {
    user: String,
    password: String,
}
#[derive(Serialize)]
struct AuditResult {
    user: String,
    password: String,
}
#[derive(Deserialize)]
struct SetupArgs {
    token: String,
}
#[derive(Serialize)]
struct SetupResult {
    welcome: String,
}

type Captured = Arc<Mutex<Vec<Value>>>;

fn build_open() -> (JsonRpcProtocol<()>, Captured) {
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("ref-open", "1.0.0")
        .method(JsonRpcMethod::new(MethodDef::new("echo"), |a: EchoArgs, _c: &RequestCtx<()>| {
            Ok(EchoResult { echo: a.msg })
        }))
        .unwrap()
        .method(JsonRpcMethod::new(MethodDef::new("add"), |a: AddArgs, _c: &RequestCtx<()>| {
            Ok(AddResult { sum: a.a + a.b })
        }))
        .unwrap()
        .method(JsonRpcMethod::new(MethodDef::new("boom"), |_a: Empty, _c: &RequestCtx<()>| {
            Err::<OkResult, _>(JsonRpcError::request_failed("kaboom"))
        }))
        .unwrap()
        .method(JsonRpcMethod::new(
            MethodDef::new("audit_me").audit_message("audited op").secret_fields(["password"]),
            |a: AuditArgs, _c: &RequestCtx<()>| Ok(AuditResult { user: a.user, password: a.password }),
        ))
        .unwrap()
        .server_info(|_s: &Session<()>| Ok(json!({"name": "ref", "version": "1.0.0"})))
        .audit_sink(move |req: &JsonRpcRequest, resp: &Value, _s: &Session<()>, msg: Option<&str>| {
            cap.lock().unwrap().push(json!({
                "method": req.method,
                "params": req.params,
                "response": resp,
                "audit_message": msg,
            }));
        })
        .build();
    (proto, captured)
}

fn build_gated() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("ref-gated", "1.0.0")
        .method(JsonRpcMethod::new(MethodDef::new("ping").pre_auth(), |_a: Empty, _c: &RequestCtx<()>| {
            Ok(PingResult { pong: true })
        }))
        .unwrap()
        .method(JsonRpcMethod::new(MethodDef::new("echo"), |a: EchoArgs, _c: &RequestCtx<()>| {
            Ok(EchoResult { echo: a.msg })
        }))
        .unwrap()
        .method(JsonRpcMethod::new(MethodDef::new("add"), |a: AddArgs, _c: &RequestCtx<()>| {
            Ok(AddResult { sum: a.a + a.b })
        }))
        .unwrap()
        .method(JsonRpcMethod::new(MethodDef::new("boom"), |_a: Empty, _c: &RequestCtx<()>| {
            Err::<OkResult, _>(JsonRpcError::request_failed("kaboom"))
        }))
        .unwrap()
        .method(JsonRpcMethod::new(MethodDef::new("secret_op"), |_a: Empty, _c: &RequestCtx<()>| {
            Ok(OkResult { ok: true })
        }))
        .unwrap()
        .authorizer(|req: &JsonRpcRequest, _s: &Session<()>, _t: Option<CancelTarget>| {
            if req.method == "secret_op" {
                AuthorizationResponse::deny("denied")
            } else {
                AuthorizationResponse::allow()
            }
        })
        .session_setup(MethodDef::new("$/sessionSetup"), |a: SetupArgs, _s: &Session<()>| {
            if a.token == "good" {
                Ok((SessionLifecycle::Established, SetupResult { welcome: "hi".into() }))
            } else {
                Err(JsonRpcError::not_authorized("bad token"))
            }
        })
        .build()
}

/// Strip `error.data` (implementation-specific decode/validation detail) so the
/// comparison rests on `{jsonrpc, id, error.code, error.message}`.
fn strip_data(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(err) = v.get_mut("error").and_then(Value::as_object_mut) {
        err.remove("data");
    }
    v
}

fn strip_audit(rec: &Value) -> Value {
    let mut r = rec.clone();
    if let Some(resp) = r.get_mut("response") {
        *resp = strip_data(resp);
    }
    r
}

async fn run_steps(proto: &JsonRpcProtocol<()>, name: &str, steps: &[Value]) -> usize {
    assert!(!steps.is_empty(), "{name}: case has no steps (nothing would be asserted)");
    let session = proto.new_session(Some(()), Arc::new(NullOutbound));
    for (i, step) in steps.iter().enumerate() {
        let wire = step["wire"].as_str().expect("wire is a string");
        let actual = match proto.dispatch(wire.as_bytes(), &session).await {
            Dispatched::Reply(b) => Some(serde_json::from_slice::<Value>(&b).unwrap()),
            Dispatched::Nothing => None,
        };
        let expected = &step["response"];
        if expected.is_null() {
            assert!(actual.is_none(), "{name} step {i}: expected no reply, got {actual:?}");
        } else {
            let actual = actual.unwrap_or_else(|| panic!("{name} step {i}: expected a reply, got none"));
            assert_eq!(strip_data(expected), strip_data(&actual), "{name} step {i} response mismatch");
        }
    }
    steps.len()
}

#[tokio::test]
async fn differential_against_python_reference() {
    let golden: Value = serde_json::from_str(GOLDEN).expect("golden.json parses");
    let cases = golden["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "golden corpus is empty — run rust/conformance/generate.py");

    // Guards against a silently-vacuous run (empty corpus / audits never exercised).
    let mut total_steps = 0usize;
    let mut total_audit_records = 0usize;

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let proto_name = case["protocol"].as_str().unwrap();
        let steps = case["steps"].as_array().unwrap();
        let expected_audits = case["audits"].as_array().cloned().unwrap_or_default();

        match proto_name {
            "open" => {
                let (proto, captured) = build_open();
                total_steps += run_steps(&proto, name, steps).await;
                let got = captured.lock().unwrap();
                assert_eq!(expected_audits.len(), got.len(), "{name}: audit-record count");
                for (i, (e, g)) in expected_audits.iter().zip(got.iter()).enumerate() {
                    assert_eq!(strip_audit(e), strip_audit(g), "{name} audit {i} mismatch");
                }
                total_audit_records += got.len();
            }
            "gated" => {
                let proto = build_gated();
                total_steps += run_steps(&proto, name, steps).await;
                assert!(expected_audits.is_empty(), "{name}: gated protocol has no audit sink");
            }
            other => panic!("{name}: unknown protocol {other:?}"),
        }
    }

    // The corpus must actually exercise a meaningful number of comparisons, and the
    // audit path must have produced (and matched) at least one record — otherwise the
    // test would be a no-op even while "passing".
    assert!(total_steps >= 25, "suspiciously few request/response comparisons: {total_steps}");
    assert!(total_audit_records >= 1, "audit comparison was never exercised");
}
