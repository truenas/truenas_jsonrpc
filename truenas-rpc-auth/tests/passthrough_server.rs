//! Passthrough wired end to end through a **real** `TruenasRpcServer` over AF_UNIX: a client
//! negotiates and sends `$/sessionSetup{PASSTHROUGH}`; the server's connection loop runs the
//! takeover (`run_passthrough`), handing the live client fd to a broker, which conducts its
//! exchange directly on that fd. Receiving the broker's bytes on the client connection proves the
//! whole chain — dispatch → `Dispatched::Passthrough` → reader-paused takeover → SCM_RIGHTS
//! hand-off — works over a genuine socket.
#![cfg(feature = "passthrough")]

use std::io::Write as _;
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use truenas_rpc::JsonRpcProtocol;
use truenas_rpc_auth::{
    install, AuthSession, AuthStack, BrokerContext, BrokerServer, BrokerVerdict, Principal,
};
use truenas_rpc_server::{framing, TruenasRpcServer, UnixConfig, UnixTrust};

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tn-pt-srv-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

async fn send(client: &mut UnixStream, v: serde_json::Value) {
    client.write_all(&framing::frame(&serde_json::to_vec(&v).unwrap())).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passthrough_over_a_real_unix_server_hands_off_to_the_broker() {
    let broker_path = tmp("broker");
    let server_path = tmp("server");

    // The broker: on hand-off it holds the *real* client connection — it writes a line the client
    // will read, then authenticates by the peer creds the context carried.
    let broker_listener = StdUnixListener::bind(&broker_path).unwrap();
    let broker = thread::spawn(move || {
        let server = BrokerServer::new(|ctx: BrokerContext, fd| {
            let mut client = StdUnixStream::from(fd);
            let _ = client.write_all(b"BROKER-AUTHED\n");
            BrokerVerdict::Authenticated {
                identity: json!({ "via": "broker", "uid": ctx.peercred.map(|p| p.uid) }),
                mechanism: "SCRAM".into(),
                principal: Principal::None,
                user_info: None,
            }
        });
        if let Ok((conn, _)) = broker_listener.accept() {
            let _ = server.serve_conn(&conn);
        }
    });

    // The server: an auth protocol offering passthrough, served over AF_UNIX.
    let stack = AuthStack::builder().passthrough(&broker_path).build();
    let proto = install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack).build();
    let srv = TruenasRpcServer::<AuthSession>::builder("srv")
        .state_from_peer(AuthSession::from_peer)
        .protocol("main", proto)
        .build();
    let listener = TruenasRpcServer::<AuthSession>::bind_unix(&UnixConfig::new(&server_path)).unwrap();
    let task = tokio::spawn(async move { srv.serve_unix_listener(listener, UnixTrust::Local).await });

    let got = tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = UnixStream::connect(&server_path).await.unwrap();
        // Negotiate the protocol (framed reply). Request ids must be UUID strings.
        let id = "123e4567-e89b-12d3-a456-426614174000";
        send(&mut client, json!({"jsonrpc":"2.0","method":"$/negotiate","id":id,"params":{"protocol":"main"}})).await;
        framing::read_message(&mut client, framing::DEFAULT_LIMIT).await.unwrap().unwrap();
        // Ask for passthrough: the server hands our fd to the broker and sends no reply itself.
        send(&mut client, json!({
            "jsonrpc":"2.0","method":"$/sessionSetup","id":id,
            "params":{"mechanism":{"mechanism":"PASSTHROUGH"}},
        }))
        .await;
        // The broker now owns our fd (reader paused server-side) and writes a raw line — read it.
        let mut buf = vec![0u8; b"BROKER-AUTHED\n".len()];
        client.read_exact(&mut buf).await.unwrap();
        buf
    })
    .await;

    task.abort();
    broker.join().unwrap();
    let _ = std::fs::remove_file(&broker_path);
    let _ = std::fs::remove_file(&server_path);

    assert_eq!(got.expect("timed out waiting for the broker"), b"BROKER-AUTHED\n");
}
