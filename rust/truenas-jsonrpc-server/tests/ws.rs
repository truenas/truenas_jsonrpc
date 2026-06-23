//! WebSocket round-trip (the `websocket` feature): a `tokio-tungstenite` client negotiates +
//! dispatches against the Rust server over `ws://`, each JSON-RPC message carried as one
//! WebSocket text frame.
//!
//! Run with: `cargo test -p truenas-jsonrpc-server --features websocket`
#![cfg(feature = "websocket")]

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use truenas_jsonrpc::{JsonRpcError, JsonRpcMethod, JsonRpcProtocol, MethodDef, RequestCtx};
use truenas_jsonrpc_server::JsonRpcServer;

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

type ClientWs = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Deserialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Serialize)]
struct AddResult {
    sum: i64,
}

fn server() -> JsonRpcServer<()> {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build();
    JsonRpcServer::<()>::builder("ws-server").protocol("main", proto).build()
}

async fn send_json(ws: &mut ClientWs, v: &Value) {
    ws.send(Message::Text(serde_json::to_string(v).unwrap())).await.unwrap();
}

async fn recv_json(ws: &mut ClientWs) -> Value {
    loop {
        match ws.next().await.expect("a ws message").expect("ws ok") {
            Message::Text(t) => return serde_json::from_str(&t).unwrap(),
            Message::Binary(b) => return serde_json::from_slice(&b).unwrap(),
            _ => continue, // ping/pong/close-frame
        }
    }
}

#[tokio::test]
async fn websocket_round_trip() {
    let srv = server();
    let (listener, addr) = JsonRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_websocket_listener(listener).await })
    };

    let (mut ws, _resp) = connect_async(format!("ws://{addr}")).await.unwrap();

    send_json(&mut ws, &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}})).await;
    let neg = recv_json(&mut ws).await;
    assert_eq!(neg["result"]["protocol"], "main");
    assert_eq!(neg["result"]["server"], "ws-server");

    send_json(&mut ws, &json!({"jsonrpc":"2.0","method":"math.add","id":UUID,"params":{"a":2,"b":40}})).await;
    let add = recv_json(&mut ws).await;
    assert_eq!(add["result"]["sum"], 42);
    assert_eq!(add["id"], UUID);

    task.abort();
}
