//! Filterable (query) method mechanics at the protocol level: augment-defaults, narrowing,
//! `count`/`get` finalize, error mapping (bad operator → INVALID_PARAMS, get-no-match →
//! REQUEST_FAILED, incomparable → INTERNAL_ERROR), authz-before-compile, and auditing.
//!
//! The engine itself is proven byte-identical to the C oracle in `truenas-filter`; here we
//! only check the *plumbing*. Handlers are named fns (push-down via `tnfilter`).

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_jsonrpc::{
    tnfilter, AuthorizationResponse, CancelTarget, CompiledFilters, CompiledOptions, Dispatched,
    FilterableJsonRpcMethod, Filtered, JsonRpcError, JsonRpcProtocol, JsonRpcRequest, MethodDef,
    NullOutbound, RequestCtx, Session,
};

const RID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

#[derive(Deserialize, Serialize)]
struct NoArgs {}

/// The fixed source a query streams through `tnfilter` (mirrors `test_filterable.py`'s `_DATA`).
fn data() -> Vec<Value> {
    vec![
        json!({"id": 1, "name": "a"}),
        json!({"id": 2, "name": "b"}),
        json!({"id": 3, "name": "a"}),
    ]
}

/// Push-down handler: apply the compiled query at the source.
fn query(
    _a: NoArgs,
    _cx: &RequestCtx<()>,
    f: &CompiledFilters,
    o: &CompiledOptions,
) -> Result<Filtered<Value>, JsonRpcError> {
    Ok(tnfilter(data(), f, o)?)
}

fn deny(_r: &JsonRpcRequest, _s: &Session<()>, _t: Option<CancelTarget>) -> AuthorizationResponse {
    AuthorizationResponse::deny("nope")
}

fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("t", "1.0.0")
        .filterable(FilterableJsonRpcMethod::<NoArgs, Value, _>::new(
            MethodDef::new("x.query"),
            query,
        ))
        .unwrap()
        .build()
}

fn session(p: &JsonRpcProtocol<()>) -> Arc<Session<()>> {
    p.new_session(Some(()), Arc::new(NullOutbound))
}

async fn call(p: &JsonRpcProtocol<()>, params: Value) -> Value {
    let req = json!({"jsonrpc": "2.0", "method": "x.query", "id": RID, "params": params});
    let s = session(p);
    match p.dispatch(req.to_string().as_bytes(), &s).await {
        Dispatched::Reply(b) => serde_json::from_slice(&b).unwrap(),
        Dispatched::Nothing => panic!("expected a reply"),
        Dispatched::Transfer(_) | Dispatched::Passthrough(_) => unreachable!("transfer/passthrough directive unexpected in this test"),
    }
}

fn result(v: &Value) -> Value {
    v.get("result").cloned().unwrap_or_else(|| panic!("expected result, got {v}"))
}

fn err_code(v: &Value) -> i64 {
    v["error"]["code"].as_i64().unwrap_or_else(|| panic!("expected error, got {v}"))
}

#[tokio::test]
async fn no_filter_returns_all() {
    let r = call(&proto(), json!({})).await;
    assert_eq!(result(&r), Value::Array(data()));
}

#[tokio::test]
async fn filter_narrows() {
    let r = call(&proto(), json!({"query-filters": [["name", "=", "a"]]})).await;
    let ids: Vec<i64> = result(&r).as_array().unwrap().iter().map(|x| x["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![1, 3]);
}

#[tokio::test]
async fn count_returns_int() {
    let r = call(
        &proto(),
        json!({"query-filters": [["name", "=", "a"]], "query-options": {"count": true}}),
    )
    .await;
    assert_eq!(result(&r), json!(2));
}

#[tokio::test]
async fn get_returns_single_record() {
    let r = call(
        &proto(),
        json!({"query-filters": [["name", "=", "a"]], "query-options": {"get": true}}),
    )
    .await;
    assert_eq!(result(&r), json!({"id": 1, "name": "a"}));
}

#[tokio::test]
async fn get_no_match_is_request_failed() {
    let r = call(
        &proto(),
        json!({"query-filters": [["name", "=", "zzz"]], "query-options": {"get": true}}),
    )
    .await;
    assert_eq!(err_code(&r), -32803); // REQUEST_FAILED
}

#[tokio::test]
async fn invalid_operator_is_invalid_params() {
    let r = call(&proto(), json!({"query-filters": [["name", "??", "a"]]})).await;
    assert_eq!(err_code(&r), -32602); // INVALID_PARAMS
}

#[tokio::test]
async fn incomparable_is_internal_error() {
    // "a" > 5 → Python TypeError → engine Eval → INTERNAL_ERROR (handler's tnfilter `?`).
    let r = call(&proto(), json!({"query-filters": [["name", ">", 5]]})).await;
    assert_eq!(err_code(&r), -32603); // INTERNAL_ERROR
}

#[tokio::test]
async fn authz_denied_before_compile() {
    // A structurally-valid but semantically-bad filter; authz denies first, so the compile
    // (which would be INVALID_PARAMS) never runs — proving INVALID_PARAMS precedes nothing
    // here and NOT_AUTHORIZED wins.
    let p = JsonRpcProtocol::<()>::builder("t", "1.0.0")
        .filterable(FilterableJsonRpcMethod::<NoArgs, Value, _>::new(
            MethodDef::new("x.query"),
            query,
        ))
        .unwrap()
        .authorizer(deny)
        .build();
    let r = call(&p, json!({"query-filters": [["name", "??", "a"]]})).await;
    assert_eq!(err_code(&r), -32000); // NOT_AUTHORIZED
}

#[tokio::test]
async fn filterable_is_audited() {
    let captured: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let p = JsonRpcProtocol::<()>::builder("t", "1.0.0")
        .filterable(FilterableJsonRpcMethod::<NoArgs, Value, _>::new(
            MethodDef::new("x.query").audit_message("queried"),
            query,
        ))
        .unwrap()
        .audit_sink(move |req: &JsonRpcRequest, _resp: &Value, _s: &Session<()>, msg: Option<&str>| {
            cap.lock().unwrap().push(json!({"method": req.method, "msg": msg}));
        })
        .build();
    let _ = call(&p, json!({"query-filters": [["name", "=", "a"]]})).await;
    let got = captured.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0], json!({"method": "x.query", "msg": "queried"}));
}
