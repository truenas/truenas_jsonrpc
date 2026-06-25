//! End-to-end auth through the real `$/sessionSetup` / `$/sessionSetupContinue` dispatch: build a
//! protocol with an installed [`AuthStack`], create a session over a fabricated [`Peer`], and
//! drive the handshake, asserting the wire reply + the committed lifecycle + the stored identity.

use std::sync::Arc;

use serde_json::{json, Value};
use truenas_jsonrpc::{JsonRpcProtocol, NullOutbound, Session, SessionLifecycle};
use truenas_jsonrpc_auth::{
    install, AuthProgress, AuthResponse, AuthSession, AuthStack, Channel, Mechanism, Outcome,
};
use truenas_jsonrpc_server::{Peer, TlsPeer, Ucred};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn proto_with(stack: Arc<AuthStack>) -> JsonRpcProtocol<AuthSession> {
    install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack).build()
}

fn unix_peer(uid: u32) -> Peer {
    Peer::unix(Some(Ucred { pid: 1, uid, gid: uid }))
}

fn tcp_peer() -> Peer {
    Peer::tcp("127.0.0.1:9000".parse().unwrap())
}

/// A TLS TCP peer carrying the given (optional) verified client certificate.
fn tls_peer(cert: Option<Vec<u8>>) -> Peer {
    Peer {
        tls: Some(TlsPeer { peer_cert: cert, channel_binding: None }),
        ..Peer::tcp("127.0.0.1:9000".parse().unwrap())
    }
}

fn session(proto: &JsonRpcProtocol<AuthSession>, peer: &Peer) -> Arc<Session<AuthSession>> {
    proto.new_session(AuthSession::from_peer(peer), Arc::new(NullOutbound))
}

/// Dispatch one setup/continue call and return the parsed reply envelope.
async fn call(
    proto: &JsonRpcProtocol<AuthSession>,
    session: &Arc<Session<AuthSession>>,
    method: &str,
    params: Value,
) -> Value {
    let wire = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "method": method, "id": ID, "params": params,
    }))
    .unwrap();
    let reply = proto.dispatch(&wire, session).await.into_bytes().unwrap();
    serde_json::from_slice(&reply).unwrap()
}

fn response_type(reply: &Value) -> &str {
    reply["result"]["response"]["response_type"].as_str().unwrap()
}

#[tokio::test]
async fn peercred_unix_root_establishes() {
    // AF_UNIX with no declared mechanism → peer-cred default; root → authenticated.
    let stack = AuthStack::builder()
        .peercred(|ch| ch.ucred.filter(|c| c.uid == 0).map(|c| (json!({ "uid": c.uid }), vec![])))
        .build();
    let proto = proto_with(stack);
    let s = session(&proto, &unix_peer(0));

    let reply = call(&proto, &s, "$/sessionSetup", json!({})).await;
    assert_eq!(response_type(&reply), "SUCCESS");
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    // the success reply hands the client its session's UUID
    assert_eq!(reply["result"]["response"]["session_id"].as_str().unwrap(), s.id().to_string());
    let id = s.with_internal(|a| a.unwrap().identity().cloned());
    assert_eq!(id, Some(json!({ "uid": 0 })));
}

#[tokio::test]
async fn peercred_non_root_falls_through_to_auth_err() {
    // The verifier returns None for a non-root uid → the connection must use a mechanism.
    let stack = AuthStack::builder()
        .peercred(|ch| ch.ucred.filter(|c| c.uid == 0).map(|c| (json!({ "uid": c.uid }), vec![])))
        .build();
    let proto = proto_with(stack);
    let s = session(&proto, &unix_peer(1000));

    let reply = call(&proto, &s, "$/sessionSetup", json!({})).await;
    assert_eq!(response_type(&reply), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
    assert!(s.with_internal(|a| a.unwrap().identity().is_none()));
}

#[tokio::test]
async fn granted_role_names_become_the_session_mask() {
    // The role *names* a credential grants are interned to the session's `RoleMask` via the stack's
    // registry at `sessionSetup` — `FULL_ADMIN` → all-ones, a registered name → its bit, and an
    // unknown name is dropped (a stale grant doesn't fail the whole authentication).
    use truenas_jsonrpc::{RoleMask, Roles};
    use truenas_jsonrpc_auth::FULL_ADMIN;

    let registry = Roles::new(["readonly", "ops"]);
    let stack = AuthStack::builder()
        .roles(registry.clone())
        .peercred(|ch| {
            let uid = ch.ucred?.uid;
            let roles: Vec<String> = match uid {
                0 => vec![FULL_ADMIN.to_string()],            // → the all-ones mask
                5 => vec!["ops".into()],                      // → exactly the ops bit
                7 => vec!["bogus".into(), "readonly".into()], // unknown name dropped
                _ => return None,
            };
            Some((json!({ "uid": uid }), roles))
        })
        .build();
    let proto = proto_with(stack);

    for (uid, expected) in [
        (0u32, RoleMask::FULL_ADMIN),
        (5, registry.get("ops").unwrap()),
        (7, registry.get("readonly").unwrap()),
    ] {
        let s = session(&proto, &unix_peer(uid));
        assert_eq!(response_type(&call(&proto, &s, "$/sessionSetup", json!({})).await), "SUCCESS");
        assert_eq!(s.granted_roles(), expected, "uid {uid}");
    }
}

#[tokio::test]
async fn tcp_with_no_mechanism_is_denied() {
    // A network client may not use the peer-cred default — it must declare a mechanism.
    let stack = AuthStack::builder().peercred(|_| Some((json!({ "any": true }), vec![]))).build();
    let proto = proto_with(stack);
    let s = session(&proto, &tcp_peer());

    let reply = call(&proto, &s, "$/sessionSetup", json!({})).await;
    assert_eq!(response_type(&reply), "DENIED");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn unsupported_mechanism_is_auth_err() {
    // No mechanism registered under this tag → refused.
    let stack = AuthStack::builder().build();
    let proto = proto_with(stack);
    let s = session(&proto, &unix_peer(0));

    let reply = call(
        &proto,
        &s,
        "$/sessionSetup",
        json!({ "mechanism": { "mechanism": "SCRAM", "scram_type": "CLIENT_FIRST" } }),
    )
    .await;
    assert_eq!(response_type(&reply), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn mtls_maps_verified_client_cert_to_identity() {
    // The transport already verified the cert; the mechanism maps it to an identity.
    let stack = AuthStack::builder()
        .mtls(|der| (der == b"good-cert").then(|| (json!({ "cn": "alice" }), vec![])))
        .build();
    let proto = proto_with(stack);
    let s = session(&proto, &tls_peer(Some(b"good-cert".to_vec())));

    let reply = call(&proto, &s, "$/sessionSetup", json!({ "mechanism": { "mechanism": "CLIENT_CERTIFICATE" } })).await;
    assert_eq!(response_type(&reply), "SUCCESS");
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    assert_eq!(s.with_internal(|a| a.unwrap().identity().cloned()), Some(json!({ "cn": "alice" })));
}

#[tokio::test]
async fn mtls_without_a_client_cert_is_denied() {
    // No client cert on the channel → the CLIENT_CERT capability gate refuses before the policy runs.
    let stack = AuthStack::builder().mtls(|_| Some((json!({ "any": true }), vec![]))).build();
    let proto = proto_with(stack);
    let s = session(&proto, &tls_peer(None)); // TLS but no client cert

    let reply = call(&proto, &s, "$/sessionSetup", json!({ "mechanism": { "mechanism": "CLIENT_CERTIFICATE" } })).await;
    assert_eq!(response_type(&reply), "DENIED");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn mtls_policy_rejection_is_auth_err() {
    // The cert is present (capability met) but the policy maps it to no identity.
    let stack = AuthStack::builder().mtls(|_| None).build();
    let proto = proto_with(stack);
    let s = session(&proto, &tls_peer(Some(b"unknown".to_vec())));

    let reply = call(&proto, &s, "$/sessionSetup", json!({ "mechanism": { "mechanism": "CLIENT_CERTIFICATE" } })).await;
    assert_eq!(response_type(&reply), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

/// A two-round test mechanism: challenge first, authenticated on continue.
struct TwoRound;
impl Mechanism for TwoRound {
    fn step(&self, _payload: &Value, _channel: &Channel, progress: Option<AuthProgress>) -> Outcome {
        match progress {
            None => Outcome::Challenge {
                reply: AuthResponse::Challenge {
                    mechanism: "TEST".into(),
                    data: json!({ "nonce": "abc" }),
                },
                next: AuthProgress::new("TEST", 0u8),
            },
            Some(_carried) => Outcome::Authenticated {
                identity: json!({ "user": "t" }),
                roles: vec![],
                user_info: Some(json!({ "hello": true })),
                extra: None,
            },
        }
    }
}

#[tokio::test]
async fn multi_round_mechanism_challenges_then_establishes() {
    let stack = AuthStack::builder().mechanism("TEST", TwoRound).build();
    let proto = proto_with(stack);
    let s = session(&proto, &tcp_peer());

    // Round 1: setup → CHALLENGE, lifecycle Init.
    let r1 = call(&proto, &s, "$/sessionSetup", json!({ "mechanism": { "mechanism": "TEST" } })).await;
    assert_eq!(response_type(&r1), "CHALLENGE");
    assert_eq!(r1["result"]["response"]["nonce"], "abc"); // flattened mechanism data
    assert_eq!(s.lifecycle(), SessionLifecycle::Init);

    // Round 2: continue → SUCCESS, lifecycle Established, identity stored.
    let r2 = call(&proto, &s, "$/sessionSetupContinue", json!({ "mechanism": { "mechanism": "TEST" } })).await;
    assert_eq!(response_type(&r2), "SUCCESS");
    assert_eq!(r2["result"]["response"]["session_id"].as_str().unwrap(), s.id().to_string());
    assert_eq!(r2["result"]["response"]["user_info"], json!({ "hello": true }));
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    assert_eq!(s.with_internal(|a| a.unwrap().identity().cloned()), Some(json!({ "user": "t" })));
}

#[tokio::test]
async fn continue_cannot_switch_mechanism() {
    let stack = AuthStack::builder().mechanism("TEST", TwoRound).build();
    let proto = proto_with(stack);
    let s = session(&proto, &tcp_peer());

    // Begin TEST (→ Init), then try to continue as a different mechanism.
    call(&proto, &s, "$/sessionSetup", json!({ "mechanism": { "mechanism": "TEST" } })).await;
    let r = call(&proto, &s, "$/sessionSetupContinue", json!({ "mechanism": { "mechanism": "OTHER" } })).await;
    assert_eq!(response_type(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}
