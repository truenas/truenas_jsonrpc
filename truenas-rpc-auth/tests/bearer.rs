//! The `GSSAPI_BEARER_TOKEN` mechanism through the real `$/sessionSetup` dispatch: a single-use
//! token (minted by an external SPNEGO edge, here a stub [`BearerTokenSource`]) presented by the
//! client. Asserts success + identity + the resolved `(uid, "GSSAPI_BEARER_TOKEN")` roles, that a
//! consumed token can't be replayed, that an expired/unknown token is refused, and that a
//! postureless connection can't present one at all.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use truenas_rpc::{JsonRpcProtocol, NullOutbound, Roles, Session, SessionLifecycle};
use truenas_rpc_auth::{
    install, AuthSession, AuthStack, BearerCredential, BearerTokenSource, BearerVerdict, Principal,
};
use truenas_rpc_server::{Peer, TlsPeer, TransportPosture};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

/// An in-memory stand-in for the keyring the external edge writes: `token → (username, expired)`.
/// `consume` removes a valid token (single-use) exactly as the keyring-backed source does.
struct Stub(Mutex<HashMap<String, (String, bool)>>);

impl Stub {
    fn with(entries: &[(&str, &str, bool)]) -> Self {
        Stub(Mutex::new(
            entries.iter().map(|(t, u, e)| (t.to_string(), (u.to_string(), *e))).collect(),
        ))
    }
}

impl BearerTokenSource for Stub {
    fn consume(&self, token: &str) -> BearerVerdict {
        let mut m = self.0.lock().unwrap();
        match m.get(token).cloned() {
            None => BearerVerdict::Unknown,
            Some((_, true)) => {
                m.remove(token);
                BearerVerdict::Expired
            }
            Some((user, false)) => {
                m.remove(token); // single-use consume
                BearerVerdict::Valid(BearerCredential {
                    identity: json!({ "username": user }),
                    principal: Principal::User(user),
                })
            }
        }
    }
}

fn server(source: Stub, registry: Roles) -> JsonRpcProtocol<AuthSession> {
    let stack = AuthStack::builder()
        .roles(registry)
        .gssapi_bearer_token(source)
        .user_resolver(|name| (name == "alice").then_some(1000))
        .role_source(|uid, mech| {
            // Assurance-based: roles are granted to (uid, "GSSAPI_BEARER_TOKEN") specifically.
            if uid == 1000 && mech == "GSSAPI_BEARER_TOKEN" {
                vec!["ops".into()]
            } else {
                vec![]
            }
        })
        .build();
    install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack).build()
}

/// A secure (kTLS) channel — the only direct-TLS posture that may authenticate.
fn tls_session(proto: &JsonRpcProtocol<AuthSession>) -> Arc<Session<AuthSession>> {
    let peer = Peer {
        tls: Some(TlsPeer { peer_cert: None, channel_binding: None }),
        posture: Some(TransportPosture::KernelTls),
        ..Peer::tcp("127.0.0.1:9000".parse().unwrap())
    };
    proto.new_session(AuthSession::from_peer(&peer), Arc::new(NullOutbound))
}

async fn setup(
    proto: &JsonRpcProtocol<AuthSession>,
    s: &Arc<Session<AuthSession>>,
    token: Value,
) -> Value {
    let mut mechanism = json!({ "mechanism": "GSSAPI_BEARER_TOKEN" });
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
async fn a_valid_bearer_token_authenticates_resolves_roles_and_is_consumed() {
    let registry = Roles::new(["ops"]);
    let proto = server(Stub::with(&[("tok-alice", "alice", false)]), registry.clone());
    let s = tls_session(&proto);

    let r = setup(&proto, &s, json!("tok-alice")).await;
    assert_eq!(rtype(&r), "SUCCESS", "{r}");
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    assert_eq!(r["result"]["response"]["session_id"].as_str().unwrap(), s.id().to_string());
    assert_eq!(
        s.with_internal(|a| a.unwrap().identity().cloned()),
        Some(json!({ "username": "alice" }))
    );
    // alice → uid 1000 → the (1000, "GSSAPI_BEARER_TOKEN") roles.
    assert_eq!(s.granted_roles(), registry.get("ops").unwrap());
    let cred = s.with_credential(|c| {
        let c = c.unwrap();
        (c.description.clone(), c.uid)
    });
    assert_eq!(cred, ("GSSAPI_BEARER_TOKEN user=alice".to_string(), Some(1000)));

    // Replay: the token was consumed, so a fresh session presenting it again is rejected.
    let s2 = tls_session(&proto);
    let replay = setup(&proto, &s2, json!("tok-alice")).await;
    assert_eq!(rtype(&replay), "AUTH_ERR");
    assert_eq!(s2.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn an_expired_bearer_token_is_rejected() {
    let proto = server(Stub::with(&[("tok-old", "alice", true)]), Roles::new(["ops"]));
    let s = tls_session(&proto);
    let r = setup(&proto, &s, json!("tok-old")).await;
    assert_eq!(rtype(&r), "EXPIRED", "{r}");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn an_unknown_bearer_token_is_auth_err() {
    let proto = server(Stub::with(&[("tok-alice", "alice", false)]), Roles::new(["ops"]));
    let s = tls_session(&proto);
    let r = setup(&proto, &s, json!("nope")).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn a_missing_token_field_is_auth_err() {
    let proto = server(Stub::with(&[("tok-alice", "alice", false)]), Roles::new(["ops"]));
    let s = tls_session(&proto);
    let r = setup(&proto, &s, Value::Null).await; // no "token" field
    assert_eq!(rtype(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn a_postureless_connection_cannot_present_a_bearer_token() {
    // Plain TCP (no declared posture) is refused before the mechanism runs — a bearer secret may
    // only cross a confidential, posture-bearing channel.
    let proto = server(Stub::with(&[("tok-alice", "alice", false)]), Roles::new(["ops"]));
    let s = proto.new_session(
        AuthSession::from_peer(&Peer::tcp("127.0.0.1:9000".parse().unwrap())),
        Arc::new(NullOutbound),
    );
    let r = setup(&proto, &s, json!("tok-alice")).await;
    assert_eq!(rtype(&r), "DENIED");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}
