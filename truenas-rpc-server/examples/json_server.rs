//! Example: a minimal **JSON-RPC** server — the default engine — with an in-process client that
//! drives one session so the example runs to completion (rather than serving forever).
//!
//! The wire, bottom to top:
//!   - **Transport (1):** an AF_UNIX stream.
//!   - **Framing (2):** each message is a 4-byte big-endian length prefix followed by that many
//!     bytes of compact JSON (see [`truenas_rpc_server::framing`]).
//!   - **Codec (3) + Envelope (4):** JSON-RPC 2.0 — `{"jsonrpc":"2.0","id":..,"method":..,"params":..}`.
//!   - **Dispatch (5):** the client first binds a named protocol with `$/negotiate`, then calls the
//!     protocol's typed methods.
//!
//! Run: `cargo run -p truenas-rpc-server --example json_server`

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use truenas_rpc::{JsonRpcError, RpcMethod, JsonRpcProtocol, MethodDef, RequestCtx};
use truenas_rpc_server::{framing, JsonRpc, TruenasRpcServer, UnixConfig};

#[derive(Deserialize, Serialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Serialize)]
struct AddResult {
    sum: i64,
}

#[derive(Deserialize, Serialize)]
struct HelloArgs {
    name: String,
}
#[derive(Serialize)]
struct HelloResult {
    greeting: String,
}

/// The demo protocol: two typed methods under one protocol name. Each handler takes a typed,
/// deserialized argument struct and returns a serializable result (or a [`JsonRpcError`]); the
/// framework handles parsing, routing, and the reply envelope.
fn demo_protocol() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("greeting.hello"),
            |a: HelloArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(HelloResult { greeting: format!("hello, {}!", a.name) })
            },
        ))
        .unwrap()
        .build()
}

/// Frame `req` (4-byte length prefix), write it, read the single framed reply, and parse it as JSON.
async fn call<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, req: Value) -> Value {
    let bytes = serde_json::to_vec(&req).unwrap();
    stream.write_all(&framing::frame(&bytes)).await.unwrap();
    let reply = framing::read_message(stream, framing::DEFAULT_LIMIT).await.unwrap().unwrap();
    serde_json::from_slice(&reply).unwrap()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    let path = std::env::temp_dir().join(format!("jsonrpc-example-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path); // bind fails if the path already exists

    // 1. Build the server: register one named protocol; it is served by the default JSON-RPC engine.
    let server = TruenasRpcServer::<()>::builder("example-server")
        .protocol("demo", demo_protocol())
        .build();

    // 2. Bind a Unix socket and serve the `JsonRpc` wire on it in the background. `serve_unix_listener`
    //    is trusted-local — the peer is a genuinely-local process (its `SO_PEERCRED` is the caller, not
    //    a reverse proxy); a proxied socket would use `serve_proxied_unix_listener`.
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path))?;
    let server_task =
        tokio::spawn(async move { server.serve_unix_listener(listener, JsonRpc).await });

    // 3. A client. Bind the protocol with `$/negotiate`, then call its methods.
    let mut client = UnixStream::connect(&path).await?;

    let neg = call(
        &mut client,
        json!({"jsonrpc": "2.0", "id": "1", "method": "$/negotiate", "params": {"protocol": "demo"}}),
    )
    .await;
    println!("$/negotiate     -> {neg}");

    // Method-call ids are UUID strings (a request-correlation convention; `$/negotiate` is exempt).
    let add = call(
        &mut client,
        json!({"jsonrpc": "2.0", "id": "00000000-0000-0000-0000-000000000002",
               "method": "math.add", "params": {"a": 2, "b": 40}}),
    )
    .await;
    println!("math.add(2, 40) -> {add}");

    let hello = call(
        &mut client,
        json!({"jsonrpc": "2.0", "id": "00000000-0000-0000-0000-000000000003",
               "method": "greeting.hello", "params": {"name": "world"}}),
    )
    .await;
    println!("greeting.hello  -> {hello}");

    server_task.abort();
    let _ = std::fs::remove_file(&path);
    Ok(())
}
