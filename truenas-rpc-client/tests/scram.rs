//! SCRAM-SHA-512-PLUS client login end-to-end: the client authenticates over a live kTLS connection
//! against a server running a real SCRAM auth stack. The channel binding the client derives from the
//! server cert must match the server's, and the server's mutual-auth `v=` must verify — else the
//! handshake fails. A wrong password is a server refusal (`AuthErr`). Requires kTLS (kernel `tls`
//! module + OpenSSL kTLS).
//!
//! Run with: `cargo test -p truenas-rpc-client --features scram`
#![cfg(feature = "scram")]

use std::collections::HashMap;

use serde_json::json;
use truenas_rpc::JsonRpcProtocol;
use truenas_rpc_auth::{install, AuthSession, AuthStack, CredentialSource, ScramCredentials};
use truenas_rpc_client::{AuthOutcome, ClientConfig, ClientTls, Endpoint, JsonRpcClient};
use truenas_rpc_server::{JsonRpc, TlsConfig, TlsMode, TruenasRpcServer};

// `alice`'s raw key material (mirrors truenas-rpc-auth's own SCRAM test vector).
const ALICE_KEY: &[u8] = b"DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC";

struct InMemory(HashMap<String, ScramCredentials>);
impl CredentialSource for InMemory {
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        self.0.get(username).cloned()
    }
}

/// A protocol whose `$/sessionSetup` runs a SCRAM stack with a single account, `alice`.
fn proto() -> JsonRpcProtocol<AuthSession> {
    let creds = ScramCredentials::mint(
        ALICE_KEY,
        b"0123456789abcdef".to_vec(),
        4096,
        json!({ "user": "alice" }),
    );
    let stack = AuthStack::builder()
        .scram(InMemory(HashMap::from([("alice".to_string(), creds)])))
        .build();
    install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack).build()
}

async fn serve() -> std::net::SocketAddr {
    let (cert, key) = self_signed_pem();
    let tls = TlsConfig::from_pem(&cert, &key, TlsMode::Kernel).unwrap();
    let srv = TruenasRpcServer::<AuthSession>::builder("scram-server")
        .state_from_peer(AuthSession::from_peer)
        .protocol("main", proto())
        .build();
    let (listener, addr) = TruenasRpcServer::<AuthSession>::bind_tcp("127.0.0.1:0")
        .await
        .unwrap();
    tokio::spawn(async move { srv.serve_tls_listener(listener, tls, JsonRpc).await });
    addr
}

async fn connect(addr: std::net::SocketAddr) -> JsonRpcClient {
    let (client, neg, _notifs) = JsonRpcClient::connect_negotiate(
        &Endpoint::tls(addr.to_string(), "localhost", ClientTls::insecure()),
        "main",
        ClientConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(neg.protocol, "main");
    // SCRAM-PLUS needs a channel binding — the kTLS transport surfaced one.
    assert!(client.channel_binding().is_some());
    client
}

#[tokio::test]
async fn scram_plus_login_succeeds_over_ktls() {
    let addr = serve().await;
    let client = connect(addr).await;

    // Established means the full SCRAM-PLUS exchange completed — including the client's verification
    // of the server's mutual-auth `v=` (a wrong server signature would have been a `ClientError`).
    match client.authenticate_scram("alice", ALICE_KEY).await.unwrap() {
        AuthOutcome::Established { session_id, .. } => assert!(!session_id.is_empty()),
        other => panic!("expected Established, got {other:?}"),
    }
}

#[tokio::test]
async fn scram_wrong_password_is_refused() {
    let addr = serve().await;
    let client = connect(addr).await;

    // A wrong key → a wrong client proof → the server refuses (mutual auth never reached).
    let outcome = client
        .authenticate_scram("alice", b"not-the-right-key")
        .await
        .unwrap();
    assert!(
        matches!(outcome, AuthOutcome::AuthErr),
        "expected AuthErr, got {outcome:?}"
    );
}

/// A throwaway self-signed server cert + key (PEM), `CN=localhost`, sha256-signed.
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
