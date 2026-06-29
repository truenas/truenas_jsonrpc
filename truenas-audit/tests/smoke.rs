//! End-to-end smoke test: drive `audit()` through a real `Session` and the drain thread. Exercises
//! the extractor → record-builder → bounded-queue → netlink path. Env-independent: when the kernel
//! audit socket is unavailable or `CAP_AUDIT_WRITE` is missing, the drain thread no-ops the send
//! (records are still consumed, never dropped at this volume) — so the test passes everywhere; an
//! actual on-disk record (verified with `ausearch -m TRUSTED_APP`) needs the cap + a live auditd.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use truenas_audit::{AuditPrincipal, LinuxAuditSink};
use truenas_rpc::{
    AuditOutcome, AuditSink, JsonRpcError, JsonRpcProtocol, JsonRpcRequest, NullOutbound, Session,
};

#[test]
fn audit_drives_through_the_sink_without_panicking() {
    let sink = LinuxAuditSink::<()>::builder("truenas-api-test")
        .identity(|_s: &Session<()>| AuditPrincipal {
            user: Some("admin".into()),
            uid: Some(0),
            origin: Some("unix:uid=0".into()),
            cred_type: Some("API_KEY".into()),
            api_key_id: Some("2".into()),
        })
        .queue_bound(64)
        .build();

    // A real session to feed `audit()`.
    let proto = JsonRpcProtocol::<()>::builder("conf", "1").build();
    let session = proto.new_session(None, Arc::new(NullOutbound));

    let req = JsonRpcRequest {
        method: "pool.query".into(),
        id: Some("id-1".into()),
        params: json!({ "pool": "tank", "recursive": true }),
        roles: vec![],
    };
    let denied = JsonRpcError::not_authorized("Not authorized");

    // Method success, an auth denial, and a control message — none may panic.
    for _ in 0..16 {
        sink.audit(&req, AuditOutcome::Success, &session, Some("query pools"));
    }
    sink.audit(&req, AuditOutcome::Failure(&denied), &session, None);
    let setup = JsonRpcRequest {
        method: "$/sessionSetup".into(),
        id: Some("id-2".into()),
        params: json!({ "mechanism": "********" }),
        roles: vec![],
    };
    sink.audit(&setup, AuditOutcome::Success, &session, None);

    std::thread::sleep(Duration::from_millis(50)); // let the drain thread consume the queue
    assert_eq!(sink.dropped(), 0, "no overflow at this volume");
}
