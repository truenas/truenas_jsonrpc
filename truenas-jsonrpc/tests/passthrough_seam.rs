//! The session-setup **takeover** seam (passthrough): `session_setup_takeover` lets a handler
//! return [`SetupOutcome::Takeover`], which the core yields as a [`Dispatched::Passthrough`]
//! directive. Running it (with a fake fd) commits the lifecycle + audits — exactly as a synchronous
//! setup would, but deferred to when the server supplies the fd. No sockets here; the server crate
//! owns the real fd handoff + broker.

use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::value::{to_raw_value, RawValue};
use serde_json::{json, Value};
use truenas_jsonrpc::{
    AuditOutcome,
    Dispatched, FileTransfer, JsonRpcError, JsonRpcProtocol, JsonRpcRequest, MethodDef, NullOutbound,
    Session, SessionLifecycle, SetupHandoff, SetupOutcome,
};

const RID: &str = "11111111-2222-3333-4444-555555555555";

#[derive(Deserialize)]
struct Args {
    mode: String,
    #[serde(default)]
    #[allow(dead_code)]
    secret: Option<String>,
}

fn raw(v: Value) -> Box<RawValue> {
    to_raw_value(&v).unwrap()
}

type Captured = Arc<Mutex<Vec<Value>>>;

/// A protocol whose `$/sessionSetup` takes over (or commits) per the `mode` param. `captured`, if
/// set, installs an audit sink recording `{params, error}` — the structured outcome (the success
/// result payload is deliberately not audited) — for each setup.
fn proto(captured: Option<Captured>) -> JsonRpcProtocol<()> {
    let b = JsonRpcProtocol::<()>::builder("p", "1").session_setup_takeover(
        MethodDef::new("$/sessionSetup").secret_fields(["secret"]),
        |a: Args, _s: &Arc<Session<()>>| {
            Ok(match a.mode.as_str() {
                // A takeover handler that finishes synchronously after all.
                "commit" => SetupOutcome::Commit(SessionLifecycle::Established, json!({ "via": "commit" })),
                // Hand off → authenticated (asserts it sees the server-supplied fd).
                "ok" => SetupOutcome::Takeover(SetupHandoff::new(true, |ft: &dyn FileTransfer| {
                    assert_eq!(ft.as_raw_fd(), 42);
                    Ok((SessionLifecycle::Established, raw(json!({ "ident": "alice" }))))
                })),
                // Hand off → established but a null reply (no external identity), and no fd hand-off.
                "null" => SetupOutcome::Takeover(SetupHandoff::new(false, |_ft| {
                    Ok((SessionLifecycle::Established, raw(Value::Null)))
                })),
                // Hand off → the broker refused.
                _ => SetupOutcome::Takeover(SetupHandoff::new(true, |_ft| {
                    Err(JsonRpcError::request_failed("broker refused"))
                })),
            })
        },
    );
    let b = match captured {
        Some(cap) => b.audit_sink(move |r: &JsonRpcRequest, outcome: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
            let error = outcome.error().map(|e| json!({ "code": e.code, "message": e.message }));
            cap.lock().unwrap().push(json!({ "params": r.params, "error": error }));
        }),
        None => b,
    };
    b.build()
}

/// Stand-in for the connection's fd; the core never touches it.
struct FakeFt(i32);
impl FileTransfer for FakeFt {
    fn as_raw_fd(&self) -> i32 {
        self.0
    }
}

fn setup_req(mode: &str) -> Vec<u8> {
    json!({ "jsonrpc": "2.0", "method": "$/sessionSetup", "id": RID, "params": { "mode": mode, "secret": "pw" } })
        .to_string()
        .into_bytes()
}

async fn dispatch_takeover(proto: &JsonRpcProtocol<()>, s: &Arc<Session<()>>, mode: &str) -> truenas_jsonrpc::SetupTakeover {
    match proto.dispatch(&setup_req(mode), s).await {
        Dispatched::Passthrough(t) => t,
        _ => panic!("expected a Dispatched::Passthrough directive"),
    }
}

#[tokio::test]
async fn takeover_commits_after_the_handoff_runs() {
    let proto = proto(None);
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let takeover = dispatch_takeover(&proto, &s, "ok").await;

    assert!(takeover.hands_off_fd());
    assert_eq!(takeover.request_id(), Some(RID));
    assert!(format!("{takeover:?}").contains("SetupTakeover"));
    // Nothing is committed until the server runs the hand-off with the fd.
    assert_eq!(s.lifecycle(), SessionLifecycle::None);

    takeover.run(&FakeFt(42));
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    assert_eq!(s.external(), Some(json!({ "ident": "alice" })));
}

#[tokio::test]
async fn takeover_without_fd_handoff_and_a_null_reply() {
    let proto = proto(None);
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let takeover = dispatch_takeover(&proto, &s, "null").await;
    assert!(!takeover.hands_off_fd());

    takeover.run(&FakeFt(-1));
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    assert_eq!(s.external(), None); // a null reply sets no external identity
}

#[tokio::test]
async fn takeover_error_leaves_the_session_unauthenticated() {
    let proto = proto(None);
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let takeover = dispatch_takeover(&proto, &s, "err").await;
    takeover.run(&FakeFt(42));
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
    assert_eq!(s.external(), None);
}

#[tokio::test]
async fn a_passthrough_directive_has_no_reply_bytes() {
    let proto = proto(None);
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    assert!(proto.dispatch(&setup_req("ok"), &s).await.into_bytes().is_none());
    // dropped without running → still uncommitted
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn a_takeover_handler_may_commit_synchronously() {
    let proto = proto(None);
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let bytes = proto.dispatch(&setup_req("commit"), &s).await.into_bytes().unwrap();
    let reply: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reply["result"], json!({ "via": "commit" }));
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
}

#[tokio::test]
async fn the_deferred_outcome_is_audited_redacted() {
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let proto = proto(Some(captured.clone()));
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let takeover = dispatch_takeover(&proto, &s, "ok").await;
    // The audit record is written when the hand-off runs, not at dispatch.
    assert!(captured.lock().unwrap().is_empty());

    takeover.run(&FakeFt(42));
    let rows = captured.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["params"]["secret"], "********"); // redacted
    assert_eq!(rows[0]["error"], json!(null)); // success — the result payload itself is not audited
}

#[tokio::test]
async fn a_takeover_error_is_audited() {
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let proto = proto(Some(captured.clone()));
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let takeover = dispatch_takeover(&proto, &s, "err").await;
    takeover.run(&FakeFt(42));
    let rows = captured.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["error"]["code"], -32803); // request_failed
    assert_eq!(rows[0]["error"]["message"], "broker refused");
}
