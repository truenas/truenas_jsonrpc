//! The native `GSSAPI` mechanism through the real `$/sessionSetup` dispatch — the reject paths that
//! don't need a live KDC: a non-base64 token, a malformed GSS token, a missing token field, and a
//! postureless connection are each refused. (A full multi-round happy-path exchange requires a
//! Kerberos KDC + keytab + a client TGT, so it lives in a Kerberos integration environment, not
//! here; the principal→account mapping is unit-tested inline in `src/gssapi.rs`.)
#![cfg(feature = "gssapi")]

use std::sync::Arc;

use serde_json::{json, Value};
use truenas_jsonrpc::{JsonRpcProtocol, NullOutbound, Session, SessionLifecycle};
use truenas_jsonrpc_auth::{install, AuthSession, AuthStack};
use truenas_jsonrpc_server::{Peer, TlsPeer, TransportPosture};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn server() -> JsonRpcProtocol<AuthSession> {
    let stack = AuthStack::builder()
        .gssapi()
        .user_resolver(|name| (name == "alice").then_some(1000))
        .build();
    install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack).build()
}

fn tls_session(proto: &JsonRpcProtocol<AuthSession>) -> Arc<Session<AuthSession>> {
    let peer = Peer {
        tls: Some(TlsPeer { peer_cert: None, channel_binding: None }),
        posture: Some(TransportPosture::KernelTls),
        ..Peer::tcp("127.0.0.1:9000".parse().unwrap())
    };
    proto.new_session(AuthSession::from_peer(&peer), Arc::new(NullOutbound))
}

async fn setup(proto: &JsonRpcProtocol<AuthSession>, s: &Arc<Session<AuthSession>>, token: Value) -> Value {
    let mut mechanism = json!({ "mechanism": "GSSAPI" });
    if !token.is_null() {
        mechanism["token"] = token;
    }
    let wire = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "method": "$/sessionSetup", "id": ID,
        "params": { "mechanism": mechanism },
    }))
    .unwrap();
    serde_json::from_slice(&proto.dispatch(&wire, s).await.into_bytes().unwrap()).unwrap()
}

fn rtype(v: &Value) -> &str {
    v["result"]["response"]["response_type"].as_str().unwrap()
}

#[tokio::test]
async fn a_non_base64_token_is_rejected() {
    let proto = server();
    let s = tls_session(&proto);
    let r = setup(&proto, &s, json!("@@@ not base64 @@@")).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn a_malformed_gss_token_is_rejected() {
    // Valid base64 but not a real GSS token → gss_accept_sec_context fails → AUTH_ERR (no KDC needed).
    let proto = server();
    let s = tls_session(&proto);
    let r = setup(&proto, &s, json!("bm90LWEtdmFsaWQtZ3NzLXRva2Vu")).await; // "not-a-valid-gss-token"
    assert_eq!(rtype(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn a_missing_token_field_is_rejected() {
    let proto = server();
    let s = tls_session(&proto);
    let r = setup(&proto, &s, Value::Null).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn a_postureless_connection_is_denied() {
    let proto = server();
    let s = proto.new_session(
        AuthSession::from_peer(&Peer::tcp("127.0.0.1:9000".parse().unwrap())),
        Arc::new(NullOutbound),
    );
    let r = setup(&proto, &s, json!("bm90LWEtdmFsaWQtZ3NzLXRva2Vu")).await;
    assert_eq!(rtype(&r), "DENIED");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}
