//! The `OAUTH` mechanism through the real `$/sessionSetup` dispatch: a presented OIDC ID token
//! (minted here with OpenSSL — no `jsonwebtoken`) verified offline against a static [`JwksProvider`].
//! Asserts a valid RS256/ES256/EdDSA token authenticates + resolves `(uid, "OAUTH")` roles, and that
//! a wrong `aud`/`iss`, an expired token, a tampered signature, a disallowed algorithm (HS256), and a
//! missing account claim are each refused.
#![cfg(feature = "oauth")]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::sha::sha256;
use openssl::sign::Signer;
use serde_json::{json, Value};
use truenas_rpc::{JsonRpcProtocol, NullOutbound, Roles, Session, SessionLifecycle};
use truenas_rpc_auth::{install, AuthSession, AuthStack, JwksProvider, OauthConfig};
use truenas_rpc_server::{Peer, TlsPeer, TransportPosture};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

// A throwaway RSA keypair (generated offline) — the IdP's RS256 signing key for the test.
const PRIV_PEM: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0VM7wk6N0t09N
KACtkhnlPH2DAwcksxm7i+EpBqWwDSQrG4WVWSrQKUCUrkmG6UDyyOmk7/EqLXMA
zmQINCN9FkxxjPWy35kcnt2tQqjcouafvM4spytwVfdc9UyjsKPxjNHG7kTbdlBx
C6LlC25nY9VS+In+fpRe+zRWvCgl2jrpY7S1iIWGyuugG/Qe2pZBC3mny/95eFip
dT3vUF2vqSKFtU0xp51/NCKCIebyuCmVqqhsB+clLaw8RmllCZzCxc3+KUHpb9l9
OBiMYsfS2/i4AXs08UJy/uFXD36VHsiVwjm8KVDoUCCW/bYo/slxxqebWrsERWP8
A85ksdwvAgMBAAECggEAKeKA5lQEZTmmi6886RPEPABezq1HXXjUA0GsHJFUrp1+
xxxvXI8HaK4MN/x7S4Cl+z47Nnocs8U2rvtBNL6Xd5hUTROGhfN1ZrZnmrSe8BBO
LM/3u1tgtYjiGY9IK8T9bz9cAi6Zg7fpWzhur3CGRjFj/Q+JTbks0Rrbv0GYuaGg
OH4/WH2eyDlaQ5DogwI/OSo+TgDIKAYutWZdFferugU658EoBrN+Y3Qp8e1kwayR
nCddAfU0lc5He5Fw4veb+Xmccheen/de5oAuy7bJtP+MjA1bfG54vA7o8nfDTuN1
MzjTdLCy2QhESUyB/pGjfdcabsYKkaeNDB8fxoYtAQKBgQDtlmG1f8HRa8sDrWUA
sYv9DhRh+AC89Crk2G7EMt6qVREjlicO0TymNt8362yKxpx/1r+SQtkqAWJ1T71R
qPly1s/3bH5DKEM1HZZnUh0ikuWTHs+RvYDfluR9F5XcrPlcLQTtnTcv8qQ2Bq0+
jpVRB0qOln3hzJumvb6k3iUAQQKBgQDCTn4l+rrGcH+2fQmxZt6wauBdI9F60CLK
TOuo69LplF0NAzKfyZqtKuQuIJdyUfWZhXPUPySa+5W2Xx3BDItsEIdym/WWME5l
x66E7m5SEqJiCi2l5XYm4PPcrHE6MpGYBeJaMEyVG49fBGkq5WRKG80fAhi7FcpA
w39jFPbAbwKBgQDRLwScbv3RS10VwccaEziz93+OunK76ycRElaEPF28DuXmNT/y
VdtWZR2n+Io6raABFqzZNC5MQ6fSrgB8M5BdwjCdIlMRAhQaYhCYq72nQTsMi6Yq
JXWgZxSJ5wg1ob5zn9ek9jUu7C4Uu1AxsgxZqVfFr07qTeIFry55rnVZgQKBgFz6
9LC176S/9s1bvkSvJkcjjaPkXPy5FrzZ3DdkSfROc8yjSBlgfuz4xmIwZGhnQfCq
BMh/QsQLOhQgJfvYRet7aWV1riqliQ55ZFDmS9Joal4h4sAtMsHeCbQCrNgdlMA7
qJph3HPJ0Wy1jqHhTYGNFjYNaco03ijppE7EnGNvAoGAXniqG6CP1ClQfgxFYIXq
3lZHy9FkbdbLd3ZETuemoHWE7vcnUrSBq6bR3wICzxJnRhMLW/LgSc6LM8//Z895
H9qb2/ozenDLo6FasDfqIl6egB7I24oJlGIedY0sXIXI6A9JE99wZb1SpRhIGAYU
lsiCNBIrInDfpyIINLqlTC0=
-----END PRIVATE KEY-----
";

const PUB_PEM: &[u8] = br"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtFTO8JOjdLdPTSgArZIZ
5Tx9gwMHJLMZu4vhKQalsA0kKxuFlVkq0ClAlK5JhulA8sjppO/xKi1zAM5kCDQj
fRZMcYz1st+ZHJ7drUKo3KLmn7zOLKcrcFX3XPVMo7Cj8YzRxu5E23ZQcQui5Qtu
Z2PVUviJ/n6UXvs0VrwoJdo66WO0tYiFhsrroBv0HtqWQQt5p8v/eXhYqXU971Bd
r6kihbVNMaedfzQigiHm8rgplaqobAfnJS2sPEZpZQmcwsXN/ilB6W/ZfTgYjGLH
0tv4uAF7NPFCcv7hVw9+lR7IlcI5vClQ6FAglv22KP7Jccanm1q7BEVj/APOZLHc
LwIDAQAB
-----END PUBLIC KEY-----
";

/// A static one-key JWKS — the IdP's published verification key, stored as SPKI DER (so each lookup
/// returns a fresh, owned `PKey<Public>`; `PKey` isn't `Clone`).
struct StaticKey(Vec<u8>);

impl StaticKey {
    fn from_pem(spki_pem: &[u8]) -> Self {
        Self(
            PKey::public_key_from_pem(spki_pem)
                .unwrap()
                .public_key_to_der()
                .unwrap(),
        )
    }
    fn from_pkey(key: &PKey<Public>) -> Self {
        Self(key.public_key_to_der().unwrap())
    }
}

impl JwksProvider for StaticKey {
    fn verifying_key(&self, _kid: Option<&str>) -> Option<PKey<Public>> {
        PKey::public_key_from_der(&self.0).ok()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A valid set of ID-token claims (correct iss/aud, alice, unexpired).
fn valid_claims() -> Value {
    json!({
        "iss": "https://idp.example",
        "aud": "truenas-client",
        "sub": "alice-sub-0001",
        "preferred_username": "alice",
        "iat": now(),
        "exp": now() + 3600,
    })
}

// --- token minting over OpenSSL (the IdP side of the test) ---------------------------------------

/// Base64url, unpadded — the JWT segment encoding.
fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        if c.len() > 1 {
            out.push(A[((n >> 6) & 63) as usize] as char);
        }
        if c.len() > 2 {
            out.push(A[(n & 63) as usize] as char);
        }
    }
    out
}

/// Assemble `header.payload.signature` from a signing closure over the `header.payload` bytes.
fn jwt(header: &Value, claims: &Value, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> String {
    let signing_input = format!(
        "{}.{}",
        b64url(&serde_json::to_vec(header).unwrap()),
        b64url(&serde_json::to_vec(claims).unwrap())
    );
    let sig = sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&sig))
}

/// Mint an RS256 ID token with the embedded RSA key.
fn mint(claims: &Value) -> String {
    let pkey = PKey::private_key_from_pem(PRIV_PEM).unwrap();
    jwt(
        &json!({ "alg": "RS256", "typ": "JWT", "kid": "test-key" }),
        claims,
        |input| {
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
            signer.update(input).unwrap();
            signer.sign_to_vec().unwrap()
        },
    )
}

fn es256_keypair() -> (PKey<Private>, PKey<Public>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let public =
        PKey::from_ec_key(EcKey::from_public_key(&group, ec.public_key()).unwrap()).unwrap();
    (PKey::from_ec_key(ec).unwrap(), public)
}

/// Mint an ES256 token: ECDSA sign the SHA-256 of the signing input, emit the raw `r || s` (the JWS
/// form, not DER), each half left-padded to 32 bytes.
fn mint_es256(claims: &Value, key: &PKey<Private>) -> String {
    let ec = key.ec_key().unwrap();
    jwt(
        &json!({ "alg": "ES256", "typ": "JWT" }),
        claims,
        move |input| {
            let sig = EcdsaSig::sign(&sha256(input), &ec).unwrap();
            let (r, s) = (sig.r().to_vec(), sig.s().to_vec());
            let mut raw = vec![0u8; 64];
            raw[32 - r.len()..32].copy_from_slice(&r);
            raw[64 - s.len()..64].copy_from_slice(&s);
            raw
        },
    )
}

fn ed25519_keypair() -> (PKey<Private>, PKey<Public>) {
    let private = PKey::generate_ed25519().unwrap();
    let public =
        PKey::public_key_from_raw_bytes(&private.raw_public_key().unwrap(), Id::ED25519).unwrap();
    (private, public)
}

/// Mint an EdDSA (Ed25519) token via the one-shot signer.
fn mint_eddsa(claims: &Value, key: &PKey<Private>) -> String {
    jwt(&json!({ "alg": "EdDSA", "typ": "JWT" }), claims, |input| {
        let mut signer = Signer::new_without_digest(key).unwrap();
        signer.sign_oneshot_to_vec(input).unwrap()
    })
}

// --- harness -------------------------------------------------------------------------------------

fn server(registry: Roles, provider: StaticKey) -> JsonRpcProtocol<AuthSession> {
    let config = OauthConfig::new("https://idp.example", "truenas-client");
    let stack = AuthStack::builder()
        .roles(registry)
        .oauth(config, provider)
        .user_resolver(|name| (name == "alice").then_some(1000))
        .role_source(|uid, mech| {
            if uid == 1000 && mech == "OAUTH" {
                vec!["ops".into()]
            } else {
                vec![]
            }
        })
        .build();
    install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack).build()
}

/// An RS256 server keyed on the embedded public PEM.
fn rsa_server(registry: Roles) -> JsonRpcProtocol<AuthSession> {
    server(registry, StaticKey::from_pem(PUB_PEM))
}

fn tls_session(proto: &JsonRpcProtocol<AuthSession>) -> Arc<Session<AuthSession>> {
    let peer = Peer {
        tls: Some(TlsPeer {
            peer_cert: None,
            channel_binding: None,
        }),
        posture: Some(TransportPosture::KernelTls),
        ..Peer::tcp("127.0.0.1:9000".parse().unwrap())
    };
    proto.new_session(AuthSession::from_peer(&peer), Arc::new(NullOutbound))
}

async fn setup(
    proto: &JsonRpcProtocol<AuthSession>,
    s: &Arc<Session<AuthSession>>,
    token: &str,
) -> Value {
    let wire = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "method": "$/sessionSetup", "id": ID,
        "params": { "mechanism": { "mechanism": "OAUTH", "token": token } },
    }))
    .unwrap();
    serde_json::from_slice(&proto.dispatch(&wire, s).await.into_bytes().unwrap()).unwrap()
}

fn rtype(v: &Value) -> &str {
    v["result"]["response"]["response_type"].as_str().unwrap()
}

#[tokio::test]
async fn a_valid_id_token_authenticates_and_resolves_roles() {
    let registry = Roles::new(["ops"]);
    let proto = rsa_server(registry.clone());
    let s = tls_session(&proto);

    let r = setup(&proto, &s, &mint(&valid_claims())).await;
    assert_eq!(rtype(&r), "SUCCESS", "{r}");
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    // The stored identity is the verified claim set.
    let id = s.with_internal(|a| a.unwrap().identity().cloned()).unwrap();
    assert_eq!(id["preferred_username"], "alice");
    assert_eq!(id["sub"], "alice-sub-0001");
    // alice → uid 1000 → the (1000, "OAUTH") roles.
    assert_eq!(s.granted_roles(), registry.get("ops").unwrap());
    let cred = s.with_credential(|c| {
        let c = c.unwrap();
        (c.description.clone(), c.uid)
    });
    assert_eq!(cred, ("OAUTH user=alice".to_string(), Some(1000)));
}

#[tokio::test]
async fn a_valid_es256_token_authenticates() {
    let (private, public) = es256_keypair();
    let proto = server(Roles::new(["ops"]), StaticKey::from_pkey(&public));
    let s = tls_session(&proto);
    let r = setup(&proto, &s, &mint_es256(&valid_claims(), &private)).await;
    assert_eq!(rtype(&r), "SUCCESS", "{r}");
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
}

#[tokio::test]
async fn a_valid_eddsa_token_authenticates() {
    let (private, public) = ed25519_keypair();
    let proto = server(Roles::new(["ops"]), StaticKey::from_pkey(&public));
    let s = tls_session(&proto);
    let r = setup(&proto, &s, &mint_eddsa(&valid_claims(), &private)).await;
    assert_eq!(rtype(&r), "SUCCESS", "{r}");
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
}

#[tokio::test]
async fn a_token_for_a_different_audience_is_rejected() {
    let proto = rsa_server(Roles::new(["ops"]));
    let s = tls_session(&proto);
    let mut claims = valid_claims();
    claims["aud"] = json!("some-other-app"); // minted for a different relying party
    let r = setup(&proto, &s, &mint(&claims)).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
}

#[tokio::test]
async fn a_token_from_a_different_issuer_is_rejected() {
    let proto = rsa_server(Roles::new(["ops"]));
    let s = tls_session(&proto);
    let mut claims = valid_claims();
    claims["iss"] = json!("https://evil.example");
    let r = setup(&proto, &s, &mint(&claims)).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
}

#[tokio::test]
async fn an_expired_token_is_rejected() {
    let proto = rsa_server(Roles::new(["ops"]));
    let s = tls_session(&proto);
    let mut claims = valid_claims();
    claims["exp"] = json!(now() - 3600); // expired an hour ago (beyond the 60s leeway)
    let r = setup(&proto, &s, &mint(&claims)).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
}

#[tokio::test]
async fn a_tampered_signature_is_rejected() {
    let proto = rsa_server(Roles::new(["ops"]));
    let s = tls_session(&proto);
    let mut token = mint(&valid_claims());
    // Flip the last base64url char of the signature → the signature no longer verifies.
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });
    let r = setup(&proto, &s, &token).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
}

#[tokio::test]
async fn a_disallowed_algorithm_is_rejected() {
    // An HS256 token (symmetric) — our config pins asymmetric algs, so the `alg` is refused before
    // any verification (defeating the public-key-as-HMAC-secret confusion attack).
    let proto = rsa_server(Roles::new(["ops"]));
    let s = tls_session(&proto);
    let mac = PKey::hmac(b"a-shared-secret").unwrap();
    let token = jwt(
        &json!({ "alg": "HS256", "typ": "JWT" }),
        &valid_claims(),
        |input| {
            let mut signer = Signer::new(MessageDigest::sha256(), &mac).unwrap();
            signer.update(input).unwrap();
            signer.sign_to_vec().unwrap()
        },
    );
    let r = setup(&proto, &s, &token).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
}

#[tokio::test]
async fn a_token_with_no_account_claim_is_rejected() {
    let proto = rsa_server(Roles::new(["ops"]));
    let s = tls_session(&proto);
    let mut claims = valid_claims();
    claims.as_object_mut().unwrap().remove("preferred_username");
    let r = setup(&proto, &s, &mint(&claims)).await;
    assert_eq!(rtype(&r), "AUTH_ERR");
}
