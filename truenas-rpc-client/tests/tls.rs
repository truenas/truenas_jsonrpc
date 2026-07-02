//! kTLS client transport (the `tls` feature): the client connects to a live kTLS server over an
//! encrypted TCP link, negotiates, makes a plain call, and — the headline — drives a **raw-fd
//! transfer over the encrypted connection** (the fd is plaintext to us / kernel-encrypted on the
//! wire). Plus mTLS: a client certificate that chains to the server's client-CA is accepted; one that
//! doesn't is rejected at the handshake. Requires the kernel `tls` module + an OpenSSL built with
//! kTLS (else the connection fails closed — the intended behaviour).
//!
//! Run with: `cargo test -p truenas-rpc-client --features tls`
#![cfg(feature = "tls")]

use serde::{Deserialize, Serialize};
use truenas_rpc::{
    FileTransfer, JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcFdTransferMethod,
    RpcMethod, TransferDirection,
};
use truenas_rpc_client::{ClientConfig, ClientTls, Endpoint, JsonRpcClient, JsonRpcMethod};
use truenas_rpc_server::{FileTransferExt, JsonRpc, TlsConfig, TlsMode, TruenasRpcServer};

const N: usize = 4096;

fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

#[derive(Deserialize, Serialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Deserialize, Serialize)]
struct AddResult {
    sum: i64,
}
#[derive(Deserialize, Serialize)]
struct DlArgs {
    n: usize,
}
#[derive(Serialize)]
struct DlReady {
    size: usize,
}
#[derive(Deserialize, Serialize)]
struct DlDone {
    sent: usize,
}

/// A server with a plain `math.add` and a `x.download` transfer (streams `n` pattern bytes on the fd).
fn server() -> TruenasRpcServer<()> {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .fd_transfer_method(RpcFdTransferMethod::<DlArgs, DlReady, DlDone, _, _>::new(
            MethodDef::new("x.download"),
            TransferDirection::Download,
            |a: &DlArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(DlReady { size: a.n }),
            |a: DlArgs, ft: &dyn FileTransfer| {
                let buf: Vec<u8> = (0..a.n).map(pattern).collect();
                ft.write_all(&buf).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                Ok(DlDone { sent: a.n })
            },
        ))
        .unwrap()
        .build();
    TruenasRpcServer::<()>::builder("tls-server")
        .protocol("main", proto)
        .allow_unauthenticated_network() // transport test: the protocol has no $/sessionSetup
        .build()
}

#[tokio::test]
async fn ktls_round_trip_and_transfer() {
    let (cert, key) = self_signed_pem();
    let tls = TlsConfig::from_pem(&cert, &key, TlsMode::Kernel).unwrap();
    let srv = server();
    let (listener, addr) = TruenasRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = tokio::spawn(async move { srv.serve_tls_listener(listener, tls, JsonRpc).await });

    let (client, neg, _notifs) = JsonRpcClient::connect_negotiate(
        &Endpoint::tls(addr.to_string(), "localhost", ClientTls::insecure()),
        "main",
        ClientConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(neg.protocol, "main");

    // A plain call over the encrypted link.
    let bytes = client
        .call(&JsonRpcMethod::Name("math.add".into()), &serde_json::to_vec(&AddArgs { a: 2, b: 40 }).unwrap())
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<AddResult>(&bytes).unwrap().sum, 42);

    // The headline: a raw-fd transfer over kTLS. The callback reads the bulk stream straight off the
    // plaintext (kernel-encrypted) fd and verifies it byte-for-byte.
    let params = serde_json::to_vec(&DlArgs { n: N }).unwrap();
    let reply = client
        .transfer(&JsonRpcMethod::Name("x.download".into()), &params, move |ht| {
            let mut buf = vec![0u8; N];
            ht.read_exact(&mut buf)?;
            if buf.iter().enumerate().any(|(i, &b)| b != pattern(i)) {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt download"));
            }
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<DlDone>(&reply).unwrap().sent, N);

    task.abort();
}

#[tokio::test]
async fn mtls_valid_client_cert_is_accepted() {
    let (scert, skey) = self_signed_pem();
    let (ca, ca_key) = make_ca();
    let (ccert, ckey) = make_client(&ca, &ca_key, "client-1");
    let tls =
        TlsConfig::from_pem_with_client_ca(&scert, &skey, &ca.to_pem().unwrap(), TlsMode::Kernel).unwrap();
    let srv = server();
    let (listener, addr) = TruenasRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = tokio::spawn(async move { srv.serve_tls_listener(listener, tls, JsonRpc).await });

    // The client presents a cert that chains to the server's client-CA → the handshake completes.
    let client_tls =
        ClientTls::builder().danger_accept_invalid_certs().client_cert_pem(&ccert, &ckey).build().unwrap();
    let (client, neg, _notifs) = JsonRpcClient::connect_negotiate(
        &Endpoint::tls(addr.to_string(), "localhost", client_tls),
        "main",
        ClientConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(neg.protocol, "main");
    let bytes = client
        .call(&JsonRpcMethod::Name("math.add".into()), &serde_json::to_vec(&AddArgs { a: 1, b: 2 }).unwrap())
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<AddResult>(&bytes).unwrap().sum, 3);
    task.abort();
}

#[tokio::test]
async fn mtls_untrusted_client_cert_is_rejected() {
    let (scert, skey) = self_signed_pem();
    let (ca, _ca_key) = make_ca();
    let (other_ca, other_key) = make_ca(); // a different CA the server does NOT trust
    let (ccert, ckey) = make_client(&other_ca, &other_key, "rogue");
    let tls =
        TlsConfig::from_pem_with_client_ca(&scert, &skey, &ca.to_pem().unwrap(), TlsMode::Kernel).unwrap();
    let srv = server();
    let (listener, addr) = TruenasRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = tokio::spawn(async move { srv.serve_tls_listener(listener, tls, JsonRpc).await });

    // The presented cert does not chain to the server's client-CA → the handshake must fail.
    let client_tls =
        ClientTls::builder().danger_accept_invalid_certs().client_cert_pem(&ccert, &ckey).build().unwrap();
    let result = JsonRpcClient::connect_negotiate(
        &Endpoint::tls(addr.to_string(), "localhost", client_tls),
        "main",
        ClientConfig::default(),
    )
    .await;
    assert!(result.is_err(), "a client cert not chaining to the server's client-CA must be rejected");
    task.abort();
}

// --- test certificate generation (mirrors the server's tls test) --------------------------------

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

/// A throwaway self-signed server cert + key (PEM), `CN=localhost`.
fn self_signed_pem() -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    let key = rsa_key();
    let name = cn("localhost");
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&rand_serial()).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build().to_pem().unwrap(), key.private_key_to_pem_pkcs8().unwrap())
}

fn rsa_key() -> PKey<Private> {
    PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap()
}

fn cn(name: &str) -> openssl::x509::X509Name {
    let mut n = openssl::x509::X509NameBuilder::new().unwrap();
    n.append_entry_by_text("CN", name).unwrap();
    n.build()
}

fn rand_serial() -> openssl::asn1::Asn1Integer {
    use openssl::bn::{BigNum, MsbOption};
    let mut bn = BigNum::new().unwrap();
    bn.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    bn.to_asn1_integer().unwrap()
}

/// A self-signed CA (`CA:TRUE`).
fn make_ca() -> (X509, PKey<Private>) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::x509::extension::BasicConstraints;
    let key = rsa_key();
    let name = cn("Test CA");
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&rand_serial()).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}

/// A leaf client cert (`CN=<name>`, `clientAuth`) signed by `ca`. Returns (cert_pem, key_pem).
fn make_client(ca: &X509, ca_key: &PKey<Private>, name: &str) -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::x509::extension::ExtendedKeyUsage;
    let key = rsa_key();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&rand_serial()).unwrap();
    b.set_subject_name(&cn(name)).unwrap();
    b.set_issuer_name(ca.subject_name()).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    b.append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap()).unwrap();
    b.sign(ca_key, MessageDigest::sha256()).unwrap();
    (b.build().to_pem().unwrap(), key.private_key_to_pem_pkcs8().unwrap())
}
