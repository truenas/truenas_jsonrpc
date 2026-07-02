//! WebSocket client transport (the `websocket` feature): the client negotiates + dispatches against a
//! live server over `ws://` (and `wss://` with `tls`), each JSON-RPC frame carried as one WebSocket
//! message. A raw-fd transfer is refused over WebSocket (the library owns the wire).
//!
//! Run with: `cargo test -p truenas-rpc-client --features websocket,tls`
#![cfg(feature = "websocket")]

use serde::{Deserialize, Serialize};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_client::{ClientConfig, ClientError, Endpoint, JsonRpcClient, JsonRpcMethod};
use truenas_rpc_server::TruenasRpcServer;

#[derive(Deserialize, Serialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Deserialize, Serialize)]
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

async fn add(client: &JsonRpcClient, a: i64, b: i64) -> i64 {
    let bytes = client
        .call(
            &JsonRpcMethod::Name("math.add".into()),
            &serde_json::to_vec(&AddArgs { a, b }).unwrap(),
        )
        .await
        .unwrap();
    serde_json::from_slice::<AddResult>(&bytes).unwrap().sum
}

#[tokio::test]
async fn ws_round_trip_and_transfer_refused() {
    let srv = server();
    let (listener, addr) = TruenasRpcServer::<()>::bind_tcp("127.0.0.1:0")
        .await
        .unwrap();
    let task = tokio::spawn(async move { srv.serve_websocket_listener(listener).await });

    let (client, neg, _notifs) = JsonRpcClient::connect_negotiate(
        &Endpoint::ws(addr.to_string(), "/"),
        "main",
        ClientConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(neg.protocol, "main");
    assert!(
        client.channel_binding().is_none(),
        "plain ws has no TLS channel binding"
    );
    assert_eq!(add(&client, 2, 40).await, 42);

    // A raw-fd transfer is refused over WebSocket — no plaintext fd to lend. The client bails before
    // sending anything, so the callback never runs.
    let err = client
        .transfer(&JsonRpcMethod::Name("x.download".into()), b"{}", |_ht| {
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, ClientError::NoTransfer),
        "expected NoTransfer, got {err:?}"
    );

    task.abort();
}

#[tokio::test]
async fn ws_over_unix_round_trip() {
    use truenas_rpc_server::{UnixConfig, UnixTrust};

    let path = std::env::temp_dir().join(format!("tnrpc-wsunix-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = server();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    // The `nginx -> ws-over-unix` path: a trusted-local AF_UNIX WebSocket listener.
    let task = tokio::spawn(async move {
        srv.serve_websocket_unix_listener(listener, UnixTrust::Local)
            .await
    });

    let (client, neg, _notifs) = JsonRpcClient::connect_negotiate(
        &Endpoint::ws_unix(path.clone()),
        "main",
        ClientConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(neg.protocol, "main");
    assert!(
        client.channel_binding().is_none(),
        "ws-over-unix has no TLS channel binding"
    );
    assert_eq!(add(&client, 20, 22).await, 42);

    task.abort();
    let _ = std::fs::remove_file(&path);
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn wss_round_trip() {
    use truenas_rpc_client::ClientTls;
    use truenas_rpc_server::{TlsConfig, TlsMode};

    let (cert, key) = self_signed_pem();
    // `wss` is always userspace TLS on the server (the WebSocket library owns the stream).
    let tls = TlsConfig::from_pem(&cert, &key, TlsMode::Userspace).unwrap();
    let srv = server();
    let (listener, addr) = TruenasRpcServer::<()>::bind_tcp("127.0.0.1:0")
        .await
        .unwrap();
    let task = tokio::spawn(async move { srv.serve_wss_listener(listener, tls).await });

    let (client, neg, _notifs) = JsonRpcClient::connect_negotiate(
        &Endpoint::wss(addr.to_string(), "localhost", "/", ClientTls::insecure()),
        "main",
        ClientConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(neg.protocol, "main");
    // `wss` surfaces the channel binding from its userspace TLS (SHA-256 of the sha256-signed cert).
    assert_eq!(client.channel_binding().map(<[u8]>::len), Some(32));
    assert_eq!(add(&client, 20, 22).await, 42);

    task.abort();
}

/// A throwaway self-signed cert + key (PEM), for the `wss` acceptor.
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
