//! Cross-protocol `$/sessions`: a FULL_ADMIN session on one protocol lists the active sessions of
//! **every** protocol the server offers — the server walks each protocol's registry and concatenates.

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use truenas_rpc::{
    JsonRpcError, RpcMethod, JsonRpcProtocol, MethodDef, RequestCtx, RoleMask, Session,
    SessionLifecycle,
};
use truenas_rpc_server::{framing, TruenasRpcServer, UnixConfig, UnixTrust};

// Bound requests must carry a UUID id (the core envelope parser enforces it; `$/negotiate` is
// exempt, being server-handled). Reused across this connection's sequential, non-cancellable calls.
const RID: &str = "123e4567-e89b-12d3-a456-426614174000";

#[derive(serde::Deserialize, serde::Serialize)]
struct Empty {}

/// A protocol whose `$/sessionSetup` grants FULL_ADMIN, so this connection can call `$/sessions`.
fn admin_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("admin", "1")
        .session_setup(MethodDef::new("$/sessionSetup"), |_a: Empty, s: &Session<()>| {
            s.set_roles(RoleMask::FULL_ADMIN);
            Ok::<_, JsonRpcError>((SessionLifecycle::Established, json!({ "ok": true })))
        })
        .build()
}

/// A second, unrelated protocol — its connections just need to register a session.
fn other_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("other", "1")
        .method(RpcMethod::new(MethodDef::new("ping"), |_a: Empty, _c: &RequestCtx<()>| {
            Ok::<_, JsonRpcError>(json!({ "pong": true }))
        }))
        .unwrap()
        .build()
}

fn server() -> TruenasRpcServer<()> {
    TruenasRpcServer::<()>::builder("test-server")
        .protocol("admin", admin_proto())
        .protocol("other", other_proto())
        .allow_unauthenticated_network()
        .build()
}

async fn call<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, req: Value) -> Value {
    let bytes = serde_json::to_vec(&req).unwrap();
    stream.write_all(&framing::frame(&bytes)).await.unwrap();
    let reply = framing::read_message(stream, framing::DEFAULT_LIMIT).await.unwrap().unwrap();
    serde_json::from_slice(&reply).unwrap()
}

async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, proto: &str) {
    let neg = call(
        stream,
        json!({"jsonrpc":"2.0","method":"$/negotiate","id":"n","params":{"protocol":proto}}),
    )
    .await;
    assert_eq!(neg["result"]["protocol"], proto);
}

async fn list_sessions<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Vec<Value> {
    let resp = call(stream, json!({"jsonrpc":"2.0","method":"$/sessions","id":RID})).await;
    assert_eq!(resp["id"], RID);
    resp["result"].as_array().expect("a sessions array").clone()
}

#[tokio::test]
async fn sessions_lists_every_protocol_server_wide() {
    let path = std::env::temp_dir().join(format!("tn-sessions-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let srv = server();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let handle = tokio::spawn(async move { srv.serve_unix_listener(listener, UnixTrust::Local).await });

    // Connection 1: a live session on `other`.
    let mut c1 = UnixStream::connect(&path).await.unwrap();
    negotiate(&mut c1, "other").await;

    // Connection 2: an admin on `admin` (setup → FULL_ADMIN).
    let mut admin = UnixStream::connect(&path).await.unwrap();
    negotiate(&mut admin, "admin").await;
    let setup =
        call(&mut admin, json!({"jsonrpc":"2.0","method":"$/sessionSetup","id":RID,"params":{}})).await;
    assert_eq!(setup["result"]["ok"], true, "setup → FULL_ADMIN: {setup}");

    // `$/sessions` lists sessions from BOTH protocols.
    let list = list_sessions(&mut admin).await;
    assert_eq!(list.len(), 2, "one session per protocol: {list:?}");
    let protocols: Vec<&str> = list.iter().map(|e| e["protocol"].as_str().unwrap()).collect();
    assert!(protocols.contains(&"admin") && protocols.contains(&"other"), "got {protocols:?}");

    // The enriched default entry, populated server-side from the peer: both sessions arrived over
    // AF_UNIX, so each carries a peer-cred `origin` and a secure transport; `current` marks the
    // admin caller's own entry and only it.
    let admin_entry = list.iter().find(|e| e["protocol"] == "admin").unwrap();
    let other_entry = list.iter().find(|e| e["protocol"] == "other").unwrap();
    assert!(admin_entry["origin"].as_str().unwrap().starts_with("unix:uid="), "got {admin_entry}");
    assert_eq!(admin_entry["secure_transport"], true);
    assert_eq!(other_entry["secure_transport"], true);
    assert_eq!(admin_entry["current"], true, "the caller marks its own entry current");
    assert_eq!(other_entry["current"], false);

    // Drop connection 1 → its session disappears from the listing.
    drop(c1);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await; // let the server reap it
    let list = list_sessions(&mut admin).await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["protocol"], "admin");

    handle.abort();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn sessions_denied_for_non_admin() {
    let path = std::env::temp_dir().join(format!("tn-sessions-deny-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = server();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let handle = tokio::spawn(async move { srv.serve_unix_listener(listener, UnixTrust::Local).await });

    // Negotiate `admin` but DON'T set up → no roles → `$/sessions` is Not authorized.
    let mut c = UnixStream::connect(&path).await.unwrap();
    negotiate(&mut c, "admin").await;
    let denied = call(&mut c, json!({"jsonrpc":"2.0","method":"$/sessions","id":RID})).await;
    assert_eq!(denied["error"]["message"], "Not authorized");

    handle.abort();
    let _ = std::fs::remove_file(&path);
}
