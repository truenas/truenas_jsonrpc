//! The admin operation dump: `dump_operations_json` returns the live session → operation tree
//! (session **state** + long-lived transfers / passthroughs / cancellable requests), and
//! `write_operations_dump` writes it to a file atomically. Normal method calls are never listed —
//! only genuinely long-running work — so the dump stays small and the dispatch fast path is untouched.
//! Signal policy is the consumer's: the library exposes the dump, not a signal handler.

use std::sync::Arc;

use serde_json::Value;
use truenas_rpc::{
    JsonRpcError, JsonRpcProtocol, MethodDef, NullOutbound, OperationGuard, OperationKind,
    RequestCtx, RpcMethod, Session,
};
use truenas_rpc_server::TruenasRpcServer;

#[derive(serde::Deserialize, serde::Serialize)]
struct Empty {}

fn demo_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(MethodDef::new("ping"), |_a: Empty, _c: &RequestCtx<()>| {
            Ok::<_, JsonRpcError>(serde_json::json!({ "pong": true }))
        }))
        .unwrap()
        .build()
}

/// A server whose one protocol has a live session running an in-flight transfer. Returns the server
/// plus the held session + operation guard (keep them alive for the dump; drop the guard to end the
/// operation).
fn server_with_a_transfer() -> (TruenasRpcServer<()>, Arc<Session<()>>, OperationGuard<()>) {
    let proto = demo_proto();
    // Register the session *before* the protocol moves into the server — the registry (a weak
    // handle) travels with it, and holding the strong `Arc` keeps it live for the dump.
    let session = proto.new_session(Some(()), Arc::new(NullOutbound));
    let op = session.track_operation(OperationKind::Transfer, Arc::from("snapshot.receive"));
    let server = TruenasRpcServer::<()>::builder("test-server").protocol("demo", proto).build();
    (server, session, op)
}

#[test]
fn dump_json_reports_session_state_and_long_lived_operations() {
    let (server, session, _op) = server_with_a_transfer();

    let dump = server.dump_operations_json();
    assert_eq!(dump["server"], "test-server");
    assert!(dump["dumped_at"].as_f64().unwrap() > 0.0);
    assert_eq!(dump["session_count"], 1);

    let s = &dump["sessions"][0];
    // Session state (the "also dump session state" ask): id, protocol, age.
    assert_eq!(s["session_id"], session.id().to_string());
    assert_eq!(s["protocol"], "demo");
    assert!(s["age_seconds"].as_f64().unwrap() >= 0.0);
    // The in-flight transfer — a long-lived operation, listed; a normal `ping` never would be.
    let ops = s["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["kind"], "transfer");
    assert_eq!(ops[0]["method"], "snapshot.receive");
    assert!(ops[0]["age_seconds"].as_f64().unwrap() >= 0.0);
}

#[test]
fn operations_clear_when_the_guard_drops() {
    let (server, _session, op) = server_with_a_transfer();
    let live = |srv: &TruenasRpcServer<()>| {
        srv.dump_operations_json()["sessions"][0]["operations"].as_array().unwrap().len()
    };
    assert_eq!(live(&server), 1);
    drop(op); // the transfer ended
    assert_eq!(live(&server), 0);
}

#[test]
fn write_operations_dump_writes_valid_json_atomically() {
    let (server, _session, _op) = server_with_a_transfer();
    let path = std::env::temp_dir().join(format!("tn-opdump-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);

    server.write_operations_dump(&path).expect("write the dump");
    let dump: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("dump file")).expect("valid JSON");
    assert_eq!(dump["server"], "test-server");
    assert_eq!(dump["sessions"][0]["operations"][0]["kind"], "transfer");
    // The temp file was renamed away, not left behind.
    assert!(!path.with_extension("tmp").exists());

    let _ = std::fs::remove_file(&path);
}
