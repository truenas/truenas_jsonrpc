//! End-to-end: the `JsonRpcClient` engine against a live `TruenasRpcServer` over AF_UNIX — connect,
//! `$/negotiate`, then call a registered method over the rich `Client::call`, the object-safe
//! `CallEngine` seam the codegen targets, AND the TXDR binary sub-wire (proc-id) on the *same*
//! connection.

use serde::{Deserialize, Serialize};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_client::{
    CallEngine, ClientConfig, Endpoint, JsonRpcClient, JsonRpcMethod, MethodKey,
};
use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

#[derive(Deserialize, Serialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Deserialize, Serialize)]
struct AddResult {
    sum: i64,
}

/// A no-auth protocol with `math.add` (reachable from NONE — no `$/sessionSetup`), served over BOTH
/// the JSON name and the TXDR proc-id 1001, so one connection answers either wire.
fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add").xdr(1001),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build()
}

async fn serve(tag: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("tnrpc-client-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = TruenasRpcServer::<()>::builder("demo-server").protocol("demo", proto()).build();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    tokio::spawn(async move { srv.serve_unix_listener(listener, JsonRpc).await });
    path
}

#[tokio::test]
async fn negotiate_then_call_both_seams() {
    let path = serve("call").await;

    let (client, negotiated, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "demo", ClientConfig::default())
            .await
            .unwrap();
    assert_eq!(negotiated.protocol, "demo");

    // The rich engine call (a method key + raw wire bytes, rich `ClientError`).
    let out = client.call(&JsonRpcMethod::Name("math.add".to_string()), br#"{"a":20,"b":22}"#).await.unwrap();
    assert_eq!(serde_json::from_slice::<AddResult>(&out).unwrap().sum, 42);

    // The `CallEngine` seam the codegen sits on: serialized params in, serialized result out.
    let bytes = serde_json::to_vec(&AddArgs { a: 2, b: 40 }).unwrap();
    let out = CallEngine::call(&client, MethodKey::Name("math.add"), &bytes).await.unwrap();
    assert_eq!(serde_json::from_slice::<AddResult>(&out).unwrap().sum, 42);

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn xdr_proc_call_over_the_same_connection() {
    let path = serve("xdr").await;
    let (client, _n, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "demo", ClientConfig::default())
            .await
            .unwrap();

    // Negotiated over JSON, but call the xdr-declared method over the TXDR sub-wire (proc 1001):
    // XDR-encode the params, address by proc-id, decode the XDR reply — the generated-client path.
    let params = truenas_rpc_client::to_xdr(&AddArgs { a: 30, b: 12 }).unwrap();
    let out = CallEngine::call(&client, MethodKey::Proc(1001), &params).await.unwrap();
    let result: AddResult = truenas_rpc_client::from_xdr(&out).unwrap();
    assert_eq!(result.sum, 42);

    // A JSON call still works on the same client (mixed wires, one connection).
    let json = serde_json::to_vec(&AddArgs { a: 1, b: 1 }).unwrap();
    let jout = CallEngine::call(&client, MethodKey::Name("math.add"), &json).await.unwrap();
    assert_eq!(serde_json::from_slice::<AddResult>(&jout).unwrap().sum, 2);

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn unknown_method_is_an_rpc_error() {
    let path = serve("unknown").await;
    let (client, _n, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "demo", ClientConfig::default())
            .await
            .unwrap();
    let err = client.call(&JsonRpcMethod::Name("math.nope".to_string()), b"").await.unwrap_err();
    // METHOD_NOT_FOUND surfaces as a server Rpc error, flattened by the codegen seam.
    assert_eq!(err.into_jsonrpc().code, -32601);
    let _ = std::fs::remove_file(&path);
}
