//! Full SCRAM-SHA-512-PLUS exchange through the real `$/sessionSetup` dispatch, driven by an
//! **independent** client (built straight on openssl) so the two implementations meet only on the
//! wire. Plus the security rejects: bad proof, channel-binding downgrade/mismatch, unknown user,
//! and a non-bound channel.
#![cfg(feature = "scram")]

use std::collections::HashMap;
use std::sync::Arc;

use openssl::base64::{decode_block, encode_block};
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkcs5::pbkdf2_hmac;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use serde_json::{json, Value};
use truenas_jsonrpc::{JsonRpcProtocol, NullOutbound, Session, SessionLifecycle};
use truenas_jsonrpc_auth::{
    install, AuthSession, AuthStack, CredentialSource, ScramCredentials,
};
use truenas_jsonrpc_server::{Peer, TlsPeer, TransportPosture};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const BINDING: &[u8] = b"a-32-byte-tls-server-end-point!!";
const GS2: &str = "p=tls-server-end-point,,";

// --- independent client-side crypto (openssl), to forge a correct (or incorrect) proof ----------

fn pbkdf2(key: &[u8], salt: &[u8], iters: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    pbkdf2_hmac(key, salt, iters as usize, MessageDigest::sha512(), &mut out).unwrap();
    out
}
fn hmac(key: &[u8], data: &[u8]) -> [u8; 64] {
    let pkey = PKey::hmac(key).unwrap();
    let mut s = Signer::new(MessageDigest::sha512(), &pkey).unwrap();
    s.update(data).unwrap();
    s.sign_to_vec().unwrap().try_into().unwrap()
}
fn sha512(d: &[u8]) -> [u8; 64] {
    let mut h = Hasher::new(MessageDigest::sha512()).unwrap();
    h.update(d).unwrap();
    h.finish().unwrap().as_ref().try_into().unwrap()
}

struct Client {
    key: Vec<u8>,
    username: String,
    nonce: [u8; 32],
}

impl Client {
    fn first(&self, flag: &str) -> String {
        format!("{flag},,n={},r={}", self.username, encode_block(&self.nonce))
    }
    /// (client-final, expected server-final `v=`) for the given server-first + channel binding.
    fn finalize(&self, server_first: &str, binding: &[u8]) -> (String, String) {
        let mut combined = String::new();
        let mut salt_b64 = String::new();
        let mut iters = 0u32;
        for tok in server_first.split(',') {
            if let Some(v) = tok.strip_prefix("r=") { combined = v.into() }
            else if let Some(v) = tok.strip_prefix("s=") { salt_b64 = v.into() }
            else if let Some(v) = tok.strip_prefix("i=") { iters = v.parse().unwrap() }
        }
        let salt = decode_block(&salt_b64).unwrap();
        let mut cbind = GS2.as_bytes().to_vec();
        cbind.extend_from_slice(binding);
        let c = encode_block(&cbind);
        let bare = format!("n={},r={}", self.username, encode_block(&self.nonce));
        let without_proof = format!("c={c},r={combined}");
        let auth_message = format!("{bare},{server_first},{without_proof}");

        let sp = pbkdf2(&self.key, &salt, iters);
        let client_key = hmac(&sp, b"Client Key");
        let stored_key = sha512(&client_key);
        let client_sig = hmac(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(&client_sig).map(|(a, b)| a ^ b).collect();

        let server_key = hmac(&sp, b"Server Key");
        let v = format!("v={}", encode_block(&hmac(&server_key, auth_message.as_bytes())));
        (format!("{without_proof},p={}", encode_block(&proof)), v)
    }
}

// --- server side ---------------------------------------------------------------------------------

struct InMemory(HashMap<String, ScramCredentials>);
impl CredentialSource for InMemory {
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        self.0.get(username).cloned()
    }
}

fn server(creds: ScramCredentials) -> JsonRpcProtocol<AuthSession> {
    server_with(InMemory(HashMap::from([("alice".to_string(), creds)])))
}

fn server_with<C: CredentialSource + 'static>(source: C) -> JsonRpcProtocol<AuthSession> {
    let stack = AuthStack::builder().scram(source).build();
    install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack).build()
}

fn tls_session(proto: &JsonRpcProtocol<AuthSession>, binding: Option<Vec<u8>>) -> Arc<Session<AuthSession>> {
    let peer = Peer {
        tls: Some(TlsPeer { peer_cert: None, channel_binding: binding }),
        posture: Some(TransportPosture::KernelTls), // a secure (kTLS) channel can authenticate
        ..Peer::tcp("127.0.0.1:9000".parse().unwrap())
    };
    proto.new_session(AuthSession::from_peer(&peer), Arc::new(NullOutbound))
}

async fn call(proto: &JsonRpcProtocol<AuthSession>, s: &Arc<Session<AuthSession>>, method: &str, scram_msg: &str) -> Value {
    let wire = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "method": method, "id": ID,
        "params": { "mechanism": { "mechanism": "SCRAM", "message": scram_msg } },
    }))
    .unwrap();
    serde_json::from_slice(&proto.dispatch(&wire, s).await.into_bytes().unwrap()).unwrap()
}

fn alice() -> (Client, ScramCredentials) {
    let key = b"DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC".to_vec();
    let creds = ScramCredentials::mint(&key, b"0123456789abcdef".to_vec(), 4096, json!({ "user": "alice" }));
    (Client { key, username: "alice".into(), nonce: *b"clientnonce-0123456789012345678!" }, creds)
}

fn rtype(v: &Value) -> &str {
    v["result"]["response"]["response_type"].as_str().unwrap()
}

#[tokio::test]
async fn full_scram_plus_exchange_succeeds() {
    let (client, creds) = alice();
    let proto = server(creds);
    let s = tls_session(&proto, Some(BINDING.to_vec()));

    // client-first → server-first
    let r1 = call(&proto, &s, "$/sessionSetup", &client.first("p=tls-server-end-point")).await;
    assert_eq!(rtype(&r1), "CHALLENGE", "{r1}");
    let server_first = r1["result"]["response"]["message"].as_str().unwrap();
    assert_eq!(s.lifecycle(), SessionLifecycle::Init);

    // client-final → success, and the server-final verifies (mutual auth).
    let (client_final, expected_v) = client.finalize(server_first, BINDING);
    let r2 = call(&proto, &s, "$/sessionSetupContinue", &client_final).await;
    assert_eq!(rtype(&r2), "SUCCESS", "{r2}");
    assert_eq!(r2["result"]["response"]["extra"]["scram"].as_str().unwrap(), expected_v);
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    assert_eq!(s.with_internal(|a| a.unwrap().identity().cloned()), Some(json!({ "user": "alice" })));
}

#[tokio::test]
async fn a_bad_proof_is_rejected() {
    let (client, creds) = alice();
    let proto = server(creds);
    let s = tls_session(&proto, Some(BINDING.to_vec()));
    let r1 = call(&proto, &s, "$/sessionSetup", &client.first("p=tls-server-end-point")).await;
    let server_first = r1["result"]["response"]["message"].as_str().unwrap().to_string();
    // Corrupt the proof (flip the last base64 char's bits by re-encoding a mutated proof).
    let (mut client_final, _) = client.finalize(&server_first, BINDING);
    let p_idx = client_final.rfind(",p=").unwrap() + 3;
    client_final.replace_range(p_idx.., &encode_block(&[0u8; 64])); // an all-zero (wrong) proof
    let r2 = call(&proto, &s, "$/sessionSetupContinue", &client_final).await;
    assert_eq!(rtype(&r2), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn channel_binding_downgrade_is_rejected() {
    let (client, creds) = alice();
    let proto = server(creds);
    let s = tls_session(&proto, Some(BINDING.to_vec()));
    // A client that asks for no binding (`n`) — a downgrade — never gets past client-first.
    let r = call(&proto, &s, "$/sessionSetup", &client.first("n")).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn a_mismatched_binding_is_rejected() {
    let (client, creds) = alice();
    let proto = server(creds);
    let s = tls_session(&proto, Some(BINDING.to_vec()));
    let r1 = call(&proto, &s, "$/sessionSetup", &client.first("p=tls-server-end-point")).await;
    let server_first = r1["result"]["response"]["message"].as_str().unwrap().to_string();
    // The client computes its c= against a *different* binding (a relay on another TLS channel).
    let (client_final, _) = client.finalize(&server_first, b"a-different-binding-value-32bytes");
    let r2 = call(&proto, &s, "$/sessionSetupContinue", &client_final).await;
    assert_eq!(rtype(&r2), "AUTH_ERR");
}

#[tokio::test]
async fn unknown_user_is_rejected() {
    let (_c, creds) = alice();
    let proto = server(creds);
    let s = tls_session(&proto, Some(BINDING.to_vec()));
    let bob = Client { key: b"x".to_vec(), username: "bob".into(), nonce: [7u8; 32] };
    let r = call(&proto, &s, "$/sessionSetup", &bob.first("p=tls-server-end-point")).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
}

#[tokio::test]
async fn scram_without_a_channel_binding_is_denied() {
    let (client, creds) = alice();
    let proto = server(creds);
    // A TLS channel that carries no binding value (so SCRAM-PLUS can't apply).
    let s = tls_session(&proto, None);
    let r = call(&proto, &s, "$/sessionSetup", &client.first("p=tls-server-end-point")).await;
    assert_eq!(rtype(&r), "DENIED");
}

// --- the keyring-backed CredentialSource (the `keyring` feature) ---------------------------------
//
// A verifier stored as a `ScramRecord` in the kernel keyring authenticates the *same* SCRAM client
// when looked up through `KeyringCredentials` — and a revoked record is rejected. Best-effort: the
// kernel keyring may be unavailable in some sandboxes, in which case the test skips.

/// `alice`'s verifier as a base64-encoded keyring record with the given `expiry`.
#[cfg(feature = "keyring")]
fn alice_record(creds: &ScramCredentials, expiry: i64) -> truenas_keyring::ScramRecord {
    truenas_keyring::ScramRecord {
        username: "alice".into(),
        algorithm: "SHA512".into(),
        iterations: creds.iterations,
        salt: encode_block(&creds.salt),
        stored_key: encode_block(&creds.stored_key),
        server_key: encode_block(&creds.server_key),
        expiry,
    }
}

#[cfg(feature = "keyring")]
#[tokio::test]
async fn scram_authenticates_through_a_keyring_record_and_honours_revocation() {
    use truenas_jsonrpc_auth::KeyringCredentials;
    use truenas_keyring::{KeyringConfig, KeyringStore};

    // A **session** keyring (not a thread keyring): the setup handler runs on a `spawn_blocking`
    // worker, so the ring must be possessed from any thread of the process. The session keyring is.
    let config = KeyringConfig::from_json(r#"{ "keyring_type": "session" }"#).unwrap();
    let store = match KeyringStore::open(&config) {
        Ok(s) => s,
        Err(e) => return eprintln!("keyring unavailable ({e}); skipping"),
    };
    let (client, creds) = alice();
    if store.server_keys().put_record("alice", &alice_record(&creds, 0), None).is_err() {
        return eprintln!("keyring put unavailable; skipping");
    }

    // Look credentials up purely through the keyring → a full SCRAM-PLUS exchange succeeds, and the
    // identity is the record-derived default `{ "username": "alice" }`.
    let proto = server_with(KeyringCredentials::new(store.server_keys()));
    let s = tls_session(&proto, Some(BINDING.to_vec()));
    let r1 = call(&proto, &s, "$/sessionSetup", &client.first("p=tls-server-end-point")).await;
    assert_eq!(rtype(&r1), "CHALLENGE", "{r1}");
    let server_first = r1["result"]["response"]["message"].as_str().unwrap().to_string();
    let (client_final, expected_v) = client.finalize(&server_first, BINDING);
    let r2 = call(&proto, &s, "$/sessionSetupContinue", &client_final).await;
    assert_eq!(rtype(&r2), "SUCCESS", "{r2}");
    assert_eq!(r2["result"]["response"]["extra"]["scram"].as_str().unwrap(), expected_v);
    assert_eq!(s.with_internal(|a| a.unwrap().identity().cloned()), Some(json!({ "username": "alice" })));

    // Revoke it (expiry < 0): the same lookup now yields nothing → client-first is refused.
    store.server_keys().put_record("alice", &alice_record(&creds, -1), None).unwrap();
    let s2 = tls_session(&proto, Some(BINDING.to_vec()));
    let r = call(&proto, &s2, "$/sessionSetup", &client.first("p=tls-server-end-point")).await;
    assert_eq!(rtype(&r), "AUTH_ERR", "a revoked record must not authenticate");

    let _ = store.server_keys().remove_record("alice");
}
