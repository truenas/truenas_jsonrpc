//! JSON-RPC 2.0 **batch** (<https://www.jsonrpc.org/specification#batch>) — always-on for the
//! JSON wire. A top-level array of request objects dispatches to an array of response objects, in
//! request order; notification elements draw no response; an empty array is `INVALID_REQUEST` and
//! an all-notification batch draws no reply at all. The batch lives in the Envelope layer
//! (`protocol::dispatch_batch`) — each element runs the ordinary single-request path.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_rpc::{
    Dispatched, JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx, RoleMask, RpcMethod, Session,
};

const ID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
const ID2: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf7";

#[derive(Deserialize, Serialize)]
struct EchoArgs {
    msg: String,
}
#[derive(Serialize)]
struct EchoResult {
    echo: String,
}
#[derive(Deserialize, Serialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Serialize)]
struct AddResult {
    sum: i64,
}

/// One request object as a `Value`, so several can be composed into a batch array.
fn obj(method: &str, params: Option<Value>, id: Option<&str>) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("jsonrpc".into(), json!("2.0"));
    m.insert("method".into(), json!(method));
    if let Some(id) = id {
        m.insert("id".into(), json!(id));
    }
    if let Some(p) = params {
        m.insert("params".into(), p);
    }
    Value::Object(m)
}

fn batch(elements: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&Value::Array(elements)).unwrap()
}

async fn call(proto: &JsonRpcProtocol<()>, s: &Arc<Session<()>>, wire: &[u8]) -> Option<Value> {
    match proto.dispatch(wire, s).await {
        Dispatched::Reply(b) => Some(serde_json::from_slice(&b).unwrap()),
        Dispatched::Nothing => None,
        _ => panic!("unexpected connection-level directive at the top level"),
    }
}

fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .method(RpcMethod::new(
            MethodDef::new("echo"),
            |a: EchoArgs, _c: &RequestCtx<()>| Ok(EchoResult { echo: a.msg }),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("add"),
            |a: AddArgs, _c: &RequestCtx<()>| Ok(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build()
}

fn session(proto: &JsonRpcProtocol<()>) -> Arc<Session<()>> {
    proto.new_session(Some(()), Arc::new(NullOutbound))
}

#[tokio::test]
async fn two_requests_reply_in_request_order() {
    let proto = proto();
    let s = session(&proto);
    let wire = batch(vec![
        obj("echo", Some(json!({"msg": "hi"})), Some(ID)),
        obj("add", Some(json!({"a": 2, "b": 3})), Some(ID2)),
    ]);
    let resp = call(&proto, &s, &wire).await.unwrap();
    let arr = resp.as_array().expect("a batch replies with an array");
    assert_eq!(arr.len(), 2);
    // Response order follows request order (v1 is sequential; the client could also match by id).
    assert_eq!(
        arr[0],
        json!({"jsonrpc": "2.0", "result": {"echo": "hi"}, "id": ID})
    );
    assert_eq!(
        arr[1],
        json!({"jsonrpc": "2.0", "result": {"sum": 5}, "id": ID2})
    );
}

#[tokio::test]
async fn notification_element_is_omitted() {
    let proto = proto();
    let s = session(&proto);
    // A request + a notification (no id): only the request draws a response.
    let wire = batch(vec![
        obj("echo", Some(json!({"msg": "x"})), Some(ID)),
        obj("echo", Some(json!({"msg": "fire-and-forget"})), None),
    ]);
    let arr = call(&proto, &s, &wire).await.unwrap();
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 1, "the notification produces no response object");
    assert_eq!(arr[0]["id"], ID);
}

#[tokio::test]
async fn all_notifications_draw_no_reply() {
    let proto = proto();
    let s = session(&proto);
    let wire = batch(vec![
        obj("echo", Some(json!({"msg": "a"})), None),
        obj("add", Some(json!({"a": 1, "b": 1})), None),
    ]);
    // Per spec: the server MUST NOT return an empty array — it returns nothing at all.
    assert!(call(&proto, &s, &wire).await.is_none());
}

#[tokio::test]
async fn empty_batch_is_invalid_request() {
    let proto = proto();
    let s = session(&proto);
    // An empty array is itself an invalid request — a single error object (not an array), id null.
    let resp = call(&proto, &s, b"[]").await.unwrap();
    assert!(
        resp.is_object(),
        "the empty-batch error is a single object, not an array"
    );
    assert_eq!(resp["error"]["code"], -32600);
    assert_eq!(resp["id"], Value::Null);
}

#[tokio::test]
async fn leading_whitespace_array_is_a_batch() {
    let proto = proto();
    let s = session(&proto);
    // Insignificant leading whitespace before `[` is tolerated (same as a `{` object).
    let mut wire = b"  \n\t".to_vec();
    wire.extend_from_slice(&batch(vec![obj(
        "echo",
        Some(json!({"msg": "ws"})),
        Some(ID),
    )]));
    let arr = call(&proto, &s, &wire).await.unwrap();
    let arr = arr
        .as_array()
        .expect("still a batch despite the leading whitespace");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["result"], json!({"echo": "ws"}));
}

#[tokio::test]
async fn invalid_non_object_element_yields_error_object() {
    let proto = proto();
    let s = session(&proto);
    // A primitive element (not a request object) → an INVALID_REQUEST error object in its slot.
    let wire = batch(vec![
        obj("echo", Some(json!({"msg": "ok"})), Some(ID)),
        json!(42),
    ]);
    let arr = call(&proto, &s, &wire).await.unwrap();
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["result"], json!({"echo": "ok"}));
    assert_eq!(arr[1]["error"]["code"], -32600);
    assert_eq!(arr[1]["id"], Value::Null);
}

#[tokio::test]
async fn mixed_request_notfound_and_notification() {
    let proto = proto();
    let s = session(&proto);
    let wire = batch(vec![
        obj("add", Some(json!({"a": 4, "b": 5})), Some(ID)),
        obj("nope", Some(json!({})), Some(ID2)), // unregistered → METHOD_NOT_FOUND
        obj("add", Some(json!({"a": 0, "b": 0})), None), // notification → omitted
    ]);
    let arr = call(&proto, &s, &wire).await.unwrap();
    let arr = arr.as_array().unwrap();
    assert_eq!(
        arr.len(),
        2,
        "two responses: the result and the error; the notification is omitted"
    );
    assert_eq!(
        arr[0],
        json!({"jsonrpc": "2.0", "result": {"sum": 9}, "id": ID})
    );
    assert_eq!(arr[1]["error"]["code"], -32601);
    assert_eq!(arr[1]["id"], ID2);
}

#[tokio::test]
async fn malformed_batch_json_is_a_single_parse_error() {
    let proto = proto();
    let s = session(&proto);
    // A leading `[` that is not a well-formed JSON array → one Parse-error reply for the whole batch.
    let resp = call(&proto, &s, b"[ {\"jsonrpc\"").await.unwrap();
    assert!(
        resp.is_object(),
        "a malformed batch yields a single error object"
    );
    assert_eq!(resp["error"]["code"], -32700);
    assert_eq!(resp["id"], Value::Null);
}

#[tokio::test]
async fn connection_directive_element_is_invalid_in_a_batch() {
    let proto = proto();
    let s = session(&proto);
    s.set_roles(RoleMask::FULL_ADMIN); // authorizes `$/sessions` (which would yield a Sessions directive)
                                       // `$/sessions` is a server-assembled listing with no inline reply — it has no meaning inside a
                                       // batch, so it is surfaced as an INVALID_REQUEST element rather than the directive.
    let wire = batch(vec![
        obj("echo", Some(json!({"msg": "ok"})), Some(ID)),
        obj("$/sessions", None, Some(ID2)),
    ]);
    let arr = call(&proto, &s, &wire).await.unwrap();
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["result"], json!({"echo": "ok"}));
    assert_eq!(arr[1]["error"]["code"], -32600);
}
