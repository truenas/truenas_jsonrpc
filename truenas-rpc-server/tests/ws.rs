//! WebSocket round-trip (the `websocket` feature): a `tokio-tungstenite` client negotiates +
//! dispatches against the Rust server over `ws://`, each JSON-RPC message carried as one
//! WebSocket text frame.
//!
//! Run with: `cargo test -p truenas-rpc-server --features websocket`
#![cfg(feature = "websocket")]

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, WebSocketStream};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_server::TruenasRpcServer;

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

fn server() -> TruenasRpcServer<()> {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build();
    TruenasRpcServer::<()>::builder("ws-server")
        .protocol("main", proto)
        .allow_unauthenticated_network() // transport test: the protocol has no $/sessionSetup
        .build()
}

async fn send_json<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>, v: &Value) {
    ws.send(Message::Text(serde_json::to_string(v).unwrap()))
        .await
        .unwrap();
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
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (
        b.build().to_pem().unwrap(),
        key.private_key_to_pem_pkcs8().unwrap(),
    )
}

#[tokio::test]
async fn websocket_round_trip() {
    let srv = server();
    let (listener, addr) = TruenasRpcServer::<()>::bind_tcp("127.0.0.1:0")
        .await
        .unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_websocket_listener(listener).await })
    };

    let (mut ws, _resp) = connect_async(format!("ws://{addr}")).await.unwrap();

    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}),
    )
    .await;
    let neg = recv_json(&mut ws).await;
    assert_eq!(neg["result"]["protocol"], "main");
    assert_eq!(neg["result"]["server"], "ws-server");

    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"math.add","id":UUID,"params":{"a":2,"b":40}}),
    )
    .await;
    let add = recv_json(&mut ws).await;
    assert_eq!(add["result"]["sum"], 42);
    assert_eq!(add["id"], UUID);

    task.abort();
}

/// WebSocket over AF_UNIX (the nginx→ws-over-unix path): a `tokio-tungstenite` client over a
/// `UnixStream` negotiates + dispatches. `serve_ws` is generic over the stream, so the unix-backed
/// listener reuses it. The listener is declared trusted-local here (an unauthenticated transport test).
#[tokio::test]
async fn websocket_over_unix_round_trip() {
    use truenas_rpc_server::{UnixConfig, UnixTrust};

    let srv = server();
    let path = std::env::temp_dir().join(format!("tn-ws-unix-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move {
            srv.serve_websocket_unix_listener(listener, UnixTrust::Local)
                .await
        })
    };

    let unix = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (mut ws, _resp) = tokio_tungstenite::client_async("ws://localhost/", unix)
        .await
        .unwrap();

    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}),
    )
    .await;
    let neg = recv_json(&mut ws).await;
    assert_eq!(neg["result"]["protocol"], "main");

    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"math.add","id":UUID,"params":{"a":2,"b":40}}),
    )
    .await;
    let add = recv_json(&mut ws).await;
    assert_eq!(add["result"]["sum"], 42);

    task.abort();
    let _ = std::fs::remove_file(&path);
}

/// A **Proxied** ws-over-unix listener with a `forwarded_extractor`: the upgrade carries nginx's
/// `X-Real-Remote-*` headers, so `$/sessions` shows the real client — not the unix peer.
#[tokio::test]
async fn websocket_unix_forwarded_origin_surfaces_the_real_client() {
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;
    use truenas_rpc::{RoleMask, Session, SessionLifecycle};
    use truenas_rpc_server::{ForwardedOrigin, UnixConfig, UnixTrust};

    #[derive(serde::Deserialize, serde::Serialize)]
    struct Empty {}

    // $/sessionSetup grants FULL_ADMIN so this connection may call $/sessions.
    let proto = JsonRpcProtocol::<()>::builder("main", "1")
        .session_setup(
            MethodDef::new("$/sessionSetup"),
            |_a: Empty, s: &Session<()>| {
                s.set_roles(RoleMask::FULL_ADMIN);
                Ok::<_, JsonRpcError>((SessionLifecycle::Established, json!({ "ok": true })))
            },
        )
        .build();
    let srv = TruenasRpcServer::<()>::builder("fwd-server")
        .protocol("main", proto)
        .forwarded_extractor(|_peer, headers| ForwardedOrigin::from_real_remote_headers(headers))
        .build();

    let path = std::env::temp_dir().join(format!("tn-ws-fwd-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move {
            srv.serve_websocket_unix_listener(listener, UnixTrust::Proxied)
                .await
        })
    };

    // A ws client over unix whose upgrade carries the nginx-style forwarded headers.
    let unix = tokio::net::UnixStream::connect(&path).await.unwrap();
    let req = http::Request::builder()
        .uri("ws://localhost/")
        .header("Host", "localhost")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .header("X-Real-Remote-Addr", "203.0.113.7")
        .header("X-Real-Remote-Port", "54321")
        .header("X-Https", "on")
        .body(())
        .unwrap();
    let (mut ws, _resp) = tokio_tungstenite::client_async(req, unix).await.unwrap();

    let uuid = "123e4567-e89b-12d3-a456-426614174000";
    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["result"]["protocol"], "main");
    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"$/sessionSetup","id":uuid,"params":{}}),
    )
    .await;
    assert_eq!(recv_json(&mut ws).await["result"]["ok"], true);

    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"$/sessions","id":uuid}),
    )
    .await;
    let list = recv_json(&mut ws).await;
    let entry = &list["result"][0];
    assert_eq!(entry["origin"], "203.0.113.7:54321"); // the real client, not the unix peer
    assert_eq!(entry["secure_transport"], true); // X-Https: on

    task.abort();
    let _ = std::fs::remove_file(&path);
}

/// WebSocket over TLS (`wss://`): TLS handshake (userspace) then a WebSocket handshake over the
/// encrypted stream, then negotiate + dispatch. Requires both `tls` and `websocket`.
#[cfg(feature = "tls")]
#[tokio::test]
async fn wss_round_trip() {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use truenas_rpc_server::{TlsConfig, TlsMode};

    let (cert, key) = self_signed_pem();
    let tls = TlsConfig::from_pem(&cert, &key, TlsMode::Userspace).unwrap();
    let srv = server();
    let (listener, addr) = TruenasRpcServer::<()>::bind_tcp("127.0.0.1:0")
        .await
        .unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_wss_listener(listener, tls).await })
    };

    // Client: a userspace TLS stream (self-signed → no verify), then a WS handshake over it.
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let ssl = builder
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    let mut tls_stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
    std::pin::Pin::new(&mut tls_stream).connect().await.unwrap();
    let (mut ws, _resp) = tokio_tungstenite::client_async("wss://localhost/", tls_stream)
        .await
        .unwrap();

    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}),
    )
    .await;
    let neg = recv_json(&mut ws).await;
    assert_eq!(neg["result"]["protocol"], "main");

    send_json(
        &mut ws,
        &json!({"jsonrpc":"2.0","method":"math.add","id":UUID,"params":{"a":2,"b":40}}),
    )
    .await;
    let add = recv_json(&mut ws).await;
    assert_eq!(add["result"]["sum"], 42);

    task.abort();
}
