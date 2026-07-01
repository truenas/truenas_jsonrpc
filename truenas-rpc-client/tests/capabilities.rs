//! End-to-end client **capabilities** against a live [`TruenasRpcServer`]: the `Authenticates`
//! ($/sessionSetup) + `GracefulClose` ($/sessionClose) handshake, and server→client pub/sub
//! (subscribe over the call seam, notifications on the engine's [`NotificationStream`], published
//! via the server's `send_notification` handle). See `roundtrip.rs` for the plain call path and
//! `mock_runtime.rs` for the protocol-neutrality (rule-of-two) proof.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, value::to_raw_value, Value};
use truenas_rpc::{
    AsyncRpcMethod, JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RoleMask, RpcMethod,
    Session, SessionLifecycle, SubscriptionDef,
};
use truenas_rpc_client::{CallEngine, ClientConfig, Endpoint, JsonRpcClient, MethodKey};
use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

#[derive(Deserialize, Serialize)]
struct Empty {}

#[derive(Deserialize, Serialize)]
struct Event {
    seq: i64,
    msg: String,
}

// --- 3b: authenticate + graceful close ---------------------------------------

/// A protocol that gates a `secret` method behind `$/sessionSetup` (setup → FULL_ADMIN, Established).
fn auth_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("auth", "1")
        .session_setup(MethodDef::new("$/sessionSetup"), |_a: Empty, s: &Session<()>| {
            s.set_roles(RoleMask::FULL_ADMIN);
            Ok::<_, JsonRpcError>((SessionLifecycle::Established, json!({ "ok": true })))
        })
        .method(RpcMethod::new(MethodDef::new("secret"), |_a: Empty, _cx: &RequestCtx<()>| {
            Ok::<_, JsonRpcError>(json!({ "token": "s3cr3t" }))
        }))
        .unwrap()
        .build()
}

async fn serve(name: &'static str, tag: &str, proto: JsonRpcProtocol<()>) -> (std::path::PathBuf, TruenasRpcServer<()>) {
    let path = std::env::temp_dir().join(format!("tnrpc-cap-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = TruenasRpcServer::<()>::builder("cap-server").protocol(name, proto).build();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let serve = srv.clone();
    tokio::spawn(async move { serve.serve_unix_listener(listener, JsonRpc).await });
    (path, srv)
}

#[tokio::test]
async fn authenticate_gates_the_call_then_graceful_close() {
    let (path, _srv) = serve("auth", "auth", auth_proto()).await;
    let (client, neg, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "auth", ClientConfig::default())
            .await
            .unwrap();
    assert_eq!(neg.protocol, "auth");

    // The gated method is refused before `$/sessionSetup` (session not established).
    let before = CallEngine::call(&client, MethodKey::Name("secret"), b"{}").await;
    assert!(before.is_err(), "gated method must be refused before auth: {before:?}");

    // Authenticate → Established.
    let setup = to_raw_value(&Empty {}).unwrap();
    let out = client.authenticate(Some(&setup)).await.unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&out).unwrap()["ok"], true);

    // Now the gated method runs.
    let after = CallEngine::call(&client, MethodKey::Name("secret"), b"{}").await.unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&after).unwrap()["token"], "s3cr3t");

    // Graceful close ($/sessionClose) succeeds and tears the connection down.
    client.close().await.unwrap();
    let _ = std::fs::remove_file(&path);
}

// --- 3c: subscribe + notify --------------------------------------------------

/// A protocol offering a subscribable `events` topic (no auth — trusted-local AF_UNIX).
fn sub_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("sub", "1")
        .subscription(SubscriptionDef::<Empty, Event>::new(MethodDef::new("events")))
        .unwrap()
        .build()
}

#[tokio::test]
async fn subscribe_then_receive_a_published_notification() {
    let (path, srv) = serve("sub", "sub", sub_proto()).await;
    let (client, _neg, mut notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "sub", ClientConfig::default())
            .await
            .unwrap();

    // Subscribe over the call seam → a sub-id ack (registration is complete once the ack lands).
    let ack = CallEngine::call(&client, MethodKey::Name("events"), b"{}").await.unwrap();
    let sub_id: String = serde_json::from_slice(&ack).unwrap();
    assert!(!sub_id.is_empty(), "subscribe acks with a sub-id");

    // The server publishes; the notification arrives on the engine's stream (topic + payload bytes).
    srv.send_notification("sub", "events", &Event { seq: 7, msg: "hi".into() }).unwrap();
    let (topic, payload) = notifs.recv().await.expect("a notification");
    assert_eq!(topic, "events");
    let ev: Event = serde_json::from_slice(&payload).unwrap();
    assert_eq!((ev.seq, ev.msg.as_str()), (7, "hi"));

    // Publishing to an unknown topic / protocol is a clean error, not a panic.
    assert!(srv.send_notification("sub", "nope", &Event { seq: 0, msg: String::new() }).is_err());
    assert!(srv.send_notification("nope", "events", &Event { seq: 0, msg: String::new() }).is_err());

    let _ = std::fs::remove_file(&path);
}

// --- 3d: cancel-on-drop ------------------------------------------------------

/// A cancellable async method that loops until it observes cancellation (recording it) or times out.
fn cancel_proto(observed: Arc<AtomicBool>) -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("cancel", "1")
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("slow").cancellable(),
            move |_a: Empty, cx: RequestCtx<()>| {
                let observed = observed.clone();
                async move {
                    for _ in 0..400 {
                        if cx.is_cancelled() {
                            observed.store(true, Ordering::SeqCst);
                            return Err(JsonRpcError::internal("cancelled"));
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Ok::<_, JsonRpcError>(json!({ "done": true }))
                }
            },
        ))
        .unwrap()
        .build()
}

#[tokio::test]
async fn dropping_a_call_cancels_it_server_side() {
    let observed = Arc::new(AtomicBool::new(false));
    let (path, _srv) = serve("cancel", "cancel", cancel_proto(observed.clone())).await;
    let (client, _neg, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "cancel", ClientConfig::default())
            .await
            .unwrap();
    let client = Arc::new(client);

    // Fire the slow call in a task; let it reach the server and start the handler.
    let c = client.clone();
    let handle = tokio::spawn(async move { CallEngine::call(&*c, MethodKey::Name("slow"), b"{}").await });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Drop the call future (abort the task) → cancel-on-drop fires a `$/cancelRequest`.
    handle.abort();

    // The server processes the cancel while the handler is in flight; the handler then bails.
    for _ in 0..100 {
        if observed.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(observed.load(Ordering::SeqCst), "dropping the call must cancel the handler server-side");
    let _ = std::fs::remove_file(&path);
}
