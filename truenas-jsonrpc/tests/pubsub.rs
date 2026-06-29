//! Pub/Sub (SERVER_CLIENT) mechanics: registering a topic, subscribe → sub-id ack,
//! `send_notification` fan-out via the per-connection [`Outbound`] sink, unsubscribe via
//! `$/cancelRequest`, `unsubscribe_all`/`close_session`, and the publish/authz error paths.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_jsonrpc::{
    AuditOutcome,
    Dispatched, IdGen, JsonRpcError, JsonRpcMethod, JsonRpcProtocol, JsonRpcRequest, MethodDef,
    NullOutbound, Outbound, RequestCtx, Roles, Session, SessionId, SubscriptionDef,
};

const SID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"; // a subscribe-request id
const CID: &str = "00000000-0000-0000-0000-000000000002"; // a cancel-request id
const PINNED: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"; // a pinned sub/session id

#[derive(Deserialize, Serialize)]
struct NoArgs {}
#[derive(Serialize, Deserialize)]
struct Event {
    seq: i64,
    msg: String,
}

/// Captures the bytes pushed to a connection's back-channel as decoded JSON.
#[derive(Clone)]
struct VecSink(Arc<Mutex<Vec<Value>>>);
impl Outbound for VecSink {
    fn send(&self, message: Vec<u8>) {
        self.0.lock().unwrap().push(serde_json::from_slice(&message).unwrap());
    }
}
fn sink() -> (Arc<dyn Outbound>, Arc<Mutex<Vec<Value>>>) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    (Arc::new(VecSink(buf.clone())), buf)
}

#[derive(Clone, Copy)]
struct FixedId(SessionId);
impl IdGen for FixedId {
    fn new_id(&self) -> SessionId {
        self.0
    }
}

fn req(method: &str, params: Option<Value>, id: Option<&str>) -> Vec<u8> {
    let mut m = serde_json::Map::new();
    m.insert("jsonrpc".into(), json!("2.0"));
    m.insert("method".into(), json!(method));
    if let Some(id) = id {
        m.insert("id".into(), json!(id));
    }
    if let Some(p) = params {
        m.insert("params".into(), p);
    }
    serde_json::to_vec(&Value::Object(m)).unwrap()
}

async fn call<S: Send + Sync + 'static>(
    proto: &JsonRpcProtocol<S>,
    s: &Arc<Session<S>>,
    wire: &[u8],
) -> Value {
    match proto.dispatch(wire, s).await {
        Dispatched::Reply(b) => serde_json::from_slice(&b).unwrap(),
        Dispatched::Nothing => panic!("expected a reply"),
        Dispatched::Transfer(_) | Dispatched::Passthrough(_) | Dispatched::Sessions { .. } => unreachable!("transfer/passthrough directive unexpected in this test"),
    }
}

async fn subscribe(proto: &JsonRpcProtocol<()>, s: &Arc<Session<()>>, topic: &str, id: &str) -> String {
    let r = call(proto, s, &req(topic, Some(json!({})), Some(id))).await;
    r["result"].as_str().expect("subscribe acks with a sub-id string").to_string()
}

fn events_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("t", "1")
        .subscription(SubscriptionDef::<NoArgs, Event>::new(MethodDef::new("events")))
        .unwrap()
        .build()
}

// --- subscribe ---------------------------------------------------------------

#[tokio::test]
async fn subscribe_returns_pinned_id() {
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .subscription(SubscriptionDef::<NoArgs, Event>::new(MethodDef::new("events")))
        .unwrap()
        .id_gen(FixedId(PINNED.parse().unwrap()))
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let r = call(&proto, &s, &req("events", Some(json!({})), Some(SID))).await;
    assert_eq!(r["result"], json!(PINNED));
    assert_eq!(r["id"], SID);
}

#[tokio::test]
async fn subscribe_without_id_is_invalid_request() {
    let proto = events_proto();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    // A subscribe must carry an id (so the ack can return the sub-id); a notification is rejected.
    let r = call(&proto, &s, &req("events", Some(json!({})), None)).await;
    assert_eq!(r["error"]["code"], -32600);
}

#[tokio::test]
async fn subscribe_bad_params_is_invalid_params() {
    // A topic whose subscribe params require fields (reusing Event); `{}` is missing them,
    // so INVALID_PARAMS — and it precedes authorization.
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .subscription(SubscriptionDef::<Event, Event>::new(MethodDef::new("strict")))
        .unwrap()
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let r = call(&proto, &s, &req("strict", Some(json!({})), Some(SID))).await;
    assert_eq!(r["error"]["code"], -32602);
}

#[tokio::test]
async fn subscribe_denied_by_authz_registers_nothing() {
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .roles(Roles::new(["AUTH"]))
        .subscription(SubscriptionDef::<NoArgs, Event>::new(MethodDef::new("events").roles(["AUTH"])))
        .unwrap()
        .build();
    let (out, buf) = sink();
    let s = proto.new_session(Some(()), out);
    let r = call(&proto, &s, &req("events", Some(json!({})), Some(SID))).await;
    assert_eq!(r["error"]["code"], -32000);
    // Nothing was registered, so a publish reaches no one.
    proto.send_notification("events", &Event { seq: 1, msg: "x".into() }).unwrap();
    assert!(buf.lock().unwrap().is_empty());
}

#[tokio::test]
async fn subscribe_is_audited() {
    let captured: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .subscription(SubscriptionDef::<NoArgs, Event>::new(
            MethodDef::new("events").audit_message("subscribed"),
        ))
        .unwrap()
        .audit_sink(move |r: &JsonRpcRequest, _outcome: AuditOutcome<'_>, _s: &Session<()>, msg: Option<&str>| {
            cap.lock().unwrap().push(json!({ "method": r.method, "msg": msg }));
        })
        .id_gen(FixedId(PINNED.parse().unwrap()))
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    call(&proto, &s, &req("events", Some(json!({})), Some(SID))).await;
    let rows = captured.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["method"], "events");
    assert_eq!(rows[0]["msg"], json!("subscribed"));
}

// --- publish (fan-out) -------------------------------------------------------

#[tokio::test]
async fn fan_out_to_each_subscriber() {
    let proto = events_proto();
    let (o1, b1) = sink();
    let (o2, b2) = sink();
    let s1 = proto.new_session(Some(()), o1);
    let s2 = proto.new_session(Some(()), o2);
    subscribe(&proto, &s1, "events", SID).await;
    subscribe(&proto, &s2, "events", SID).await;

    proto.send_notification("events", &Event { seq: 1, msg: "hi".into() }).unwrap();
    let want = json!({"jsonrpc": "2.0", "method": "events", "params": {"seq": 1, "msg": "hi"}});
    assert_eq!(*b1.lock().unwrap(), vec![want.clone()]);
    assert_eq!(*b2.lock().unwrap(), vec![want]);
}

#[tokio::test]
async fn publish_no_subscribers_is_ok() {
    let proto = events_proto();
    // No subscribers registered → Ok, nothing delivered.
    proto.send_notification("events", &Event { seq: 1, msg: "x".into() }).unwrap();
}

#[tokio::test]
async fn publish_unknown_topic_errors() {
    let proto = events_proto();
    assert!(proto.send_notification("nope", &Event { seq: 1, msg: "x".into() }).is_err());
}

#[tokio::test]
async fn publish_to_client_server_method_errors() {
    let proto = JsonRpcProtocol::<()>::builder("t", "1")
        .method(JsonRpcMethod::new(MethodDef::new("ping"), |_a: NoArgs, _c: &RequestCtx<()>| {
            Ok::<Value, JsonRpcError>(json!(null))
        }))
        .unwrap()
        .build();
    // "ping" is a normal CLIENT_SERVER method, not a subscribable topic.
    assert!(proto.send_notification("ping", &Event { seq: 1, msg: "x".into() }).is_err());
}

#[tokio::test]
async fn publish_invalid_payload_errors() {
    let proto = events_proto();
    let (out, buf) = sink();
    let s = proto.new_session(Some(()), out);
    subscribe(&proto, &s, "events", SID).await;
    // Payload doesn't match the topic's `notifies` type (missing `seq`) → error, and nothing
    // is delivered (validation precedes fan-out).
    assert!(proto.send_notification("events", &json!({ "msg": "x" })).is_err());
    assert!(buf.lock().unwrap().is_empty());
}

#[tokio::test]
async fn publish_unserializable_payload_errors() {
    let proto = events_proto();
    // A map with non-string keys can't serialize to JSON → invalid params.
    let bad: HashMap<i32, i32> = HashMap::from([(1, 2)]);
    assert!(proto.send_notification("events", &bad).is_err());
}

// --- unsubscribe / cancel / close --------------------------------------------

#[tokio::test]
async fn unsubscribe_returns_true_then_false() {
    let proto = events_proto();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let sub_id = subscribe(&proto, &s, "events", SID).await;
    assert!(proto.unsubscribe(&sub_id)); // existed
    assert!(!proto.unsubscribe(&sub_id)); // already gone
}

#[tokio::test]
async fn unsubscribe_via_cancel_stops_delivery() {
    let proto = events_proto();
    let (out, buf) = sink();
    let s = proto.new_session(Some(()), out);
    let sub_id = subscribe(&proto, &s, "events", SID).await;

    let c = call(&proto, &s, &req("$/cancelRequest", Some(json!({ "target_id": sub_id })), Some(CID))).await;
    assert_eq!(c["result"], json!(true));

    proto.send_notification("events", &Event { seq: 1, msg: "x".into() }).unwrap();
    assert!(buf.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancelling_another_sessions_subscription_is_denied() {
    // Cancel is owner-or-FULL_ADMIN: a *different*, non-admin session cannot cancel A's sub.
    let proto = events_proto();
    let (out_a, buf_a) = sink();
    let a = proto.new_session(Some(()), out_a);
    let b = proto.new_session(Some(()), Arc::new(NullOutbound));
    let sub_id = subscribe(&proto, &a, "events", SID).await;

    let c = call(&proto, &b, &req("$/cancelRequest", Some(json!({ "target_id": sub_id })), Some(CID))).await;
    assert_eq!(c["error"]["code"], -32000);

    // A's subscription is still active → the publish is delivered to A.
    proto.send_notification("events", &Event { seq: 7, msg: "still".into() }).unwrap();
    assert_eq!(buf_a.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn unsubscribe_all_returns_count() {
    let proto = events_proto();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    subscribe(&proto, &s, "events", SID).await;
    subscribe(&proto, &s, "events", SID).await;
    assert_eq!(proto.unsubscribe_all(&s), 2);
}

#[tokio::test]
async fn close_session_drops_only_that_sessions_subs() {
    use truenas_jsonrpc::SessionLifecycle;
    let proto = events_proto();
    let (o1, b1) = sink();
    let (o2, b2) = sink();
    let s1 = proto.new_session(Some(()), o1);
    let s2 = proto.new_session(Some(()), o2);
    subscribe(&proto, &s1, "events", SID).await; // two subs on s1
    subscribe(&proto, &s1, "events", SID).await;
    subscribe(&proto, &s2, "events", SID).await; // one on s2

    proto.close_session(&s1);
    assert_eq!(s1.lifecycle(), SessionLifecycle::Closed);

    proto.send_notification("events", &Event { seq: 1, msg: "x".into() }).unwrap();
    assert!(b1.lock().unwrap().is_empty()); // s1's subs were dropped
    assert_eq!(b2.lock().unwrap().len(), 1); // s2 still subscribed
}

// --- concurrency -------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_subscribe_then_publish() {
    // N connections subscribe concurrently (contending on the registry mutex); one publish
    // must then reach all N. Here
    // every connection shares one sink, so the delivered count is the observable proxy for
    // "all N registered". (Default UuidGen → distinct sub-ids; pinning would collide.)
    let proto = Arc::new(events_proto());
    let (out, buf) = sink();
    let n = 20;
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let (p, o) = (proto.clone(), out.clone());
        handles.push(tokio::spawn(async move {
            let s = p.new_session(Some(()), o);
            p.dispatch(&req("events", Some(json!({})), Some(SID)), &s).await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    proto.send_notification("events", &Event { seq: 1, msg: "x".into() }).unwrap();
    assert_eq!(buf.lock().unwrap().len(), n);
}
