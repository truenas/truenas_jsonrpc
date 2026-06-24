//! WebSocket round-trip (the `websocket` feature): a `tokio-tungstenite` client negotiates +
//! dispatches against the Rust server over `ws://`, each JSON-RPC message carried as one
//! WebSocket text frame.
//!
//! Run with: `cargo test -p truenas-jsonrpc-server --features websocket`
#![cfg(feature = "websocket")]

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, WebSocketStream};
use truenas_jsonrpc::{JsonRpcError, JsonRpcMethod, JsonRpcProtocol, MethodDef, RequestCtx};
use truenas_jsonrpc_server::JsonRpcServer;

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

#[derive(Deserialize, Serialize)]
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

async fn send_json<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>, v: &Value) {
    ws.send(Message::Text(serde_json::to_string(v).unwrap())).await.unwrap();
}

async fn recv_json<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>) -> Value {
    loop {
        match ws.next().await.expect("a ws message").expect("ws ok") {
            Message::Text(t) => return serde_json::from_str(&t).unwrap(),
            Message::Binary(b) => return serde_json::from_slice(&b).unwrap(),
            _ => continue, // ping/pong/close-frame
        }
    }
}

/// A throwaway self-signed cert + key (PEM), for the `wss` test acceptor.
#[cfg(feature = "tls")]
fn self_signed_pem() -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509};

    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        bn.to_asn1_integer().unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build().to_pem().unwrap(), key.private_key_to_pem_pkcs8().unwrap())
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

/// WebSocket over TLS (`wss://`): TLS handshake (userspace) then a WebSocket handshake over the
/// encrypted stream, then negotiate + dispatch. Requires both `tls` and `websocket`.
#[cfg(feature = "tls")]
#[tokio::test]
async fn wss_round_trip() {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use truenas_jsonrpc_server::{TlsConfig, TlsMode};

    let (cert, key) = self_signed_pem();
    let tls = TlsConfig::from_pem(&cert, &key, TlsMode::Userspace).unwrap();
    let srv = server();
    let (listener, addr) = JsonRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_wss_listener(listener, tls).await })
    };

    // Client: a userspace TLS stream (self-signed → no verify), then a WS handshake over it.
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let ssl = builder.build().configure().unwrap().into_ssl("localhost").unwrap();
    let mut tls_stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
    std::pin::Pin::new(&mut tls_stream).connect().await.unwrap();
    let (mut ws, _resp) = tokio_tungstenite::client_async("wss://localhost/", tls_stream).await.unwrap();

    send_json(&mut ws, &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}})).await;
    let neg = recv_json(&mut ws).await;
    assert_eq!(neg["result"]["protocol"], "main");

    send_json(&mut ws, &json!({"jsonrpc":"2.0","method":"math.add","id":UUID,"params":{"a":2,"b":40}})).await;
    let add = recv_json(&mut ws).await;
    assert_eq!(add["result"]["sum"], 42);

    task.abort();
}
