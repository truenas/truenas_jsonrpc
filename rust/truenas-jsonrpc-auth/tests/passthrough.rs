//! Passthrough + broker (the `passthrough` feature). Two halves:
//!
//! - the **broker wire** end to end: [`Passthrough::handoff`] passes a real client socket fd
//!   (`SCM_RIGHTS`) + context to a [`BrokerServer`], which reads/writes that very fd and returns a
//!   verdict — proving the broker receives a working dup of the client connection;
//! - the **mechanism** through the real `$/sessionSetup` dispatch: it is registered, gated on a
//!   local (AF_UNIX) channel, and (until the connection-takeover seam lands) refuses in `step`.
#![cfg(feature = "passthrough")]

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use serde_json::{json, Value};
use truenas_jsonrpc::{JsonRpcProtocol, NullOutbound, Session, SessionLifecycle};
use truenas_jsonrpc_auth::{
    install, AuthSession, AuthStack, BrokerContext, BrokerServer, BrokerVerdict, Channel, Outcome,
    Passthrough, RejectKind,
};
use truenas_jsonrpc_server::{Peer, Ucred};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn sock_path(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("tn-passthrough-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn unix_channel(uid: u32) -> Channel {
    Channel::from_peer(&Peer::unix(Some(Ucred { pid: 1000, uid, gid: uid })))
}

// --- the broker wire, end to end ----------------------------------------------------------------

/// The hand-off passes the *actual* client socket: the broker reads a byte the client wrote on it,
/// writes a reply back over it, and authenticates as the uid that byte encodes. A working dup of
/// the client connection is the only way that round-trips.
#[test]
fn passthrough_hands_the_real_client_fd_to_the_broker() {
    let path = sock_path("auth");
    let listener = UnixListener::bind(&path).unwrap();

    let broker = thread::spawn(move || {
        let server = BrokerServer::new(|ctx: BrokerContext, fd| {
            assert_eq!(ctx.transport, "unix");
            assert_eq!(ctx.protocol.as_deref(), Some("main"));
            let mut client = UnixStream::from(fd);
            let mut byte = [0u8; 1];
            if client.read_exact(&mut byte).is_err() {
                return BrokerVerdict::AuthErr;
            }
            client.write_all(b"ok").unwrap(); // talk back on the passed fd
            BrokerVerdict::Authenticated { identity: json!({ "uid": byte[0] }), user_info: None }
        });
        let (conn, _) = listener.accept().unwrap();
        server.serve_conn(&conn).unwrap();
    });

    // The client connection the server would hand off: one end of a socketpair. `client_end` plays
    // the remote client; `conn_fd` is what we pass to the broker.
    let (conn_fd, mut client_end) = UnixStream::pair().unwrap();
    client_end.write_all(&[7u8]).unwrap(); // the "client" sends a byte the broker will read

    let ctx = BrokerContext::from_channel(&unix_channel(7)).with_protocol("main");
    let outcome = Passthrough::new(&path).handoff(conn_fd.as_raw_fd(), &ctx);

    match outcome {
        Outcome::Authenticated { identity, .. } => assert_eq!(identity, json!({ "uid": 7 })),
        _ => panic!("expected Authenticated"),
    }
    // The broker replied over the passed fd — the client end receives it.
    let mut reply = [0u8; 2];
    client_end.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"ok");

    broker.join().unwrap();
    let _ = std::fs::remove_file(&path);
}

/// A broker `Denied` verdict maps to `Reject(Denied)`.
#[test]
fn broker_denial_maps_to_reject() {
    let path = sock_path("deny");
    let listener = UnixListener::bind(&path).unwrap();
    let broker = thread::spawn(move || {
        let server = BrokerServer::new(|_ctx, _fd| BrokerVerdict::Denied);
        let (conn, _) = listener.accept().unwrap();
        server.serve_conn(&conn).unwrap();
    });

    let (conn_fd, _client_end) = UnixStream::pair().unwrap();
    let ctx = BrokerContext::from_channel(&unix_channel(0));
    let outcome = Passthrough::new(&path).handoff(conn_fd.as_raw_fd(), &ctx);
    assert!(matches!(outcome, Outcome::Reject(RejectKind::Denied)));

    broker.join().unwrap();
    let _ = std::fs::remove_file(&path);
}

/// No broker listening → the hand-off fails closed as `Reject(AuthErr)` (not a panic / hang).
#[test]
fn passthrough_with_no_broker_is_auth_err() {
    let (conn_fd, _client_end) = UnixStream::pair().unwrap();
    let ctx = BrokerContext::from_channel(&unix_channel(0));
    let outcome = Passthrough::new("/nonexistent/tn-broker.sock").handoff(conn_fd.as_raw_fd(), &ctx);
    assert!(matches!(outcome, Outcome::Reject(RejectKind::AuthErr)));
}

/// The context derived from a channel survives a serialize → deserialize round-trip (the broker
/// reconstructs exactly what the forwarder sent).
#[test]
fn broker_context_from_channel_round_trips() {
    let unix = BrokerContext::from_channel(&unix_channel(1000)).with_protocol("main");
    assert_eq!(unix.transport, "unix");
    assert_eq!(unix.peercred.unwrap().uid, 1000);
    assert!(unix.encrypted); // AF_UNIX = local trust

    let bytes = serde_json::to_vec(&unix).unwrap();
    let back: BrokerContext = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(unix, back);

    // A plain TCP channel: no peercred, not encrypted.
    let tcp = BrokerContext::from_channel(&Channel::from_peer(&Peer::tcp("127.0.0.1:9000".parse().unwrap())));
    assert_eq!(tcp.transport, "tcp");
    assert!(tcp.peercred.is_none());
    assert!(!tcp.encrypted);
}

// --- the mechanism through the real `$/sessionSetup` dispatch ------------------------------------

fn proto(broker: &Path) -> JsonRpcProtocol<AuthSession> {
    let stack = AuthStack::builder().passthrough(broker).build();
    install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack).build()
}

fn session(proto: &JsonRpcProtocol<AuthSession>, peer: &Peer) -> Arc<Session<AuthSession>> {
    proto.new_session(AuthSession::from_peer(peer), Arc::new(NullOutbound))
}

async fn setup(proto: &JsonRpcProtocol<AuthSession>, s: &Arc<Session<AuthSession>>) -> Value {
    let wire = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "method": "$/sessionSetup", "id": ID,
        "params": { "mechanism": { "mechanism": "PASSTHROUGH" } },
    }))
    .unwrap();
    serde_json::from_slice(&proto.dispatch(&wire, s).await.into_bytes().unwrap()).unwrap()
}

fn rtype(v: &Value) -> &str {
    v["result"]["response"]["response_type"].as_str().unwrap()
}

/// AF_UNIX satisfies the `Local` capability, so dispatch reaches `step` — which refuses (`AUTH_ERR`)
/// until the connection-takeover seam can call `handoff`.
#[tokio::test]
async fn passthrough_over_unix_reaches_step_and_is_stubbed() {
    let path = sock_path("unused");
    let proto = proto(&path);
    let s = session(&proto, &Peer::unix(Some(Ucred { pid: 1, uid: 0, gid: 0 })));
    let r = setup(&proto, &s).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

/// Over TCP the `Local` capability is absent, so the gate refuses (`DENIED`) before `step` runs —
/// SCM_RIGHTS fd-passing is AF_UNIX-only.
#[tokio::test]
async fn passthrough_over_tcp_is_denied_by_the_capability_gate() {
    let path = sock_path("unused2");
    let proto = proto(&path);
    let s = session(&proto, &Peer::tcp("127.0.0.1:9000".parse().unwrap()));
    let r = setup(&proto, &s).await;
    assert_eq!(rtype(&r), "DENIED");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}
