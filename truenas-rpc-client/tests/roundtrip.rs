//! End-to-end: the `JsonRpcClient` engine against a live `TruenasRpcServer` over AF_UNIX — connect,
//! `$/negotiate`, then call a registered method over both the rich `Client::call` and the
//! object-safe `CallEngine` seam the codegen targets.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_client::{CallEngine, ClientConfig, Endpoint, JsonRpcClient, MethodKey};
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

/// A no-auth protocol with `math.add` (reachable from NONE — no `$/sessionSetup` configured).
fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add"),
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

    // The rich engine call (typed-ish: a method key + raw params, rich `ClientError`).
    let params = RawValue::from_string(r#"{"a":20,"b":22}"#.to_string()).unwrap();
    let raw = client.call(&"math.add".to_string(), Some(&params)).await.unwrap();
    assert_eq!(serde_json::from_str::<AddResult>(raw.get()).unwrap().sum, 42);

    // The `CallEngine` seam the codegen sits on: serialized params in, serialized result out.
    let bytes = serde_json::to_vec(&AddArgs { a: 2, b: 40 }).unwrap();
    let out = CallEngine::call(&client, MethodKey::Name("math.add"), &bytes).await.unwrap();
    assert_eq!(serde_json::from_slice::<AddResult>(&out).unwrap().sum, 42);

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn unknown_method_is_an_rpc_error() {
    let path = serve("unknown").await;
    let (client, _n, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "demo", ClientConfig::default())
            .await
            .unwrap();
    let err = client.call(&"math.nope".to_string(), None).await.unwrap_err();
    // METHOD_NOT_FOUND surfaces as a server Rpc error, flattened by the codegen seam.
    assert_eq!(err.into_jsonrpc().code, -32601);
    let _ = std::fs::remove_file(&path);
}
