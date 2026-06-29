//! kTLS round-trip (the `tls` feature): a kTLS-enabled server negotiates + dispatches over an
//! encrypted TCP connection. The server's data path is the raw kernel-encrypted fd (no
//! userspace TLS pump); the client is an ordinary blocking OpenSSL TLS client. Requires the
//! kernel `tls` module + an OpenSSL built with kTLS (else the server fails closed and the
//! round-trip won't complete — which is the intended behaviour).
//!
//! Run with: `cargo test -p truenas-rpc-server --features tls`
#![cfg(feature = "tls")]

use std::io::{Read, Write};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_rpc::{
    FileTransfer, JsonRpcError, JsonRpcFdTransferMethod, JsonRpcMethod, JsonRpcProtocol, MethodDef,
    RequestCtx, TransferDirection,
};
use truenas_rpc_server::{FileTransferExt, JsonRpcServer, TlsConfig, TlsMode};

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

#[derive(Deserialize, Serialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Serialize)]
struct AddResult {
    sum: i64,
}
#[derive(Deserialize)]
struct DlArgs {
    n: usize,
}
#[derive(Serialize)]
struct DlReady {
    size: usize,
}
#[derive(Serialize)]
struct DlDone {
    sent: usize,
}

fn pattern_byte(i: usize) -> u8 {
    (i % 251) as u8
}

fn server() -> JsonRpcServer<()> {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        // A download transfer: the server streams `n` pattern bytes over the (kTLS) fd.
        .fd_transfer_method(JsonRpcFdTransferMethod::<DlArgs, DlReady, DlDone, _, _>::new(
            MethodDef::new("x.download"),
            TransferDirection::Download,
            |a: &DlArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(DlReady { size: a.n }),
            |a: DlArgs, ft: &dyn FileTransfer| {
                let buf: Vec<u8> = (0..a.n).map(pattern_byte).collect();
                ft.write_all(&buf).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                Ok(DlDone { sent: a.n })
            },
        ))
        .unwrap()
        .build();
    JsonRpcServer::<()>::builder("tls-server")
        .protocol("main", proto)
        .allow_unauthenticated_network() // transport test: the protocol has no $/sessionSetup
        .build()
}

/// A throwaway self-signed cert + key (PEM), for the test acceptor.
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
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build().to_pem().unwrap(), key.private_key_to_pem_pkcs8().unwrap())
}

fn send<W: Write>(w: &mut W, v: &Value) {
    let bytes = serde_json::to_vec(v).unwrap();
    w.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
    w.write_all(&bytes).unwrap();
    w.flush().unwrap();
}

fn recv<R: Read>(r: &mut R) -> Value {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
    r.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Blocking OpenSSL TLS client connection (accepts the self-signed cert).
fn connect_tls(addr: SocketAddr) -> openssl::ssl::SslStream<std::net::TcpStream> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE);
    let tcp = std::net::TcpStream::connect(addr).unwrap();
    b.build().connect("localhost", tcp).unwrap()
}

/// Connect, negotiate `main`, then `math.add`.
fn client_roundtrip(addr: SocketAddr) -> (Value, Value) {
    let mut s = connect_tls(addr);
    send(&mut s, &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}));
    let neg = recv(&mut s);
    send(&mut s, &json!({"jsonrpc":"2.0","method":"math.add","id":UUID,"params":{"a":2,"b":40}}));
    let add = recv(&mut s);
    (neg, add)
}

/// Connect, negotiate, run an `x.download` transfer, and read the raw stream off the *TLS*
/// connection (so the client must decrypt it). Returns whether the bytes matched + the final
/// response.
fn client_download(addr: SocketAddr, n: usize) -> (bool, Value) {
    let mut s = connect_tls(addr);
    send(&mut s, &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}));
    let _ = recv(&mut s);
    send(&mut s, &json!({"jsonrpc":"2.0","method":"x.download","id":UUID,"params":{"n":n}}));
    let ready = recv(&mut s);
    assert_eq!(ready["params"]["direction"], "download");
    assert_eq!(ready["params"]["result"]["size"], n);

    send(&mut s, &json!({"jsonrpc":"2.0","method":"$/transferGo"}));
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).unwrap(); // TLS-decrypted bulk stream
    let matched = buf.iter().enumerate().all(|(i, &b)| b == pattern_byte(i));
    let fin = recv(&mut s);
    (matched, fin)
}

async fn round_trip(mode: TlsMode) {
    let (cert, key) = self_signed_pem();
    let tls = TlsConfig::from_pem(&cert, &key, mode).unwrap();
    let srv = server();
    let (listener, addr) = JsonRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_tls_listener(listener, tls).await })
    };

    let (neg, add) = tokio::task::spawn_blocking(move || client_roundtrip(addr)).await.unwrap();
    assert_eq!(neg["result"]["protocol"], "main");
    assert_eq!(neg["result"]["server"], "tls-server");
    assert_eq!(add["result"]["sum"], 42);

    task.abort();
}

#[tokio::test]
async fn userspace_tls_round_trip() {
    round_trip(TlsMode::Userspace).await;
}

#[tokio::test]
async fn kernel_tls_round_trip() {
    round_trip(TlsMode::Kernel).await;
}

/// The headline case: a bulk transfer over a kTLS connection. The server `write`s the stream
/// on the raw (kernel-encrypted) fd; the client gets the right bytes only by TLS-decrypting
/// them — so the stream really is encrypted on the wire while never entering the server's
/// userspace.
#[tokio::test]
async fn kernel_tls_transfer_is_encrypted() {
    const N: usize = 4096;
    let (cert, key) = self_signed_pem();
    let tls = TlsConfig::from_pem(&cert, &key, TlsMode::Kernel).unwrap();
    let srv = server();
    let (listener, addr) = JsonRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_tls_listener(listener, tls).await })
    };

    let (matched, fin) = tokio::task::spawn_blocking(move || client_download(addr, N)).await.unwrap();
    assert!(matched, "the TLS-decrypted download stream didn't match the pattern");
    assert_eq!(fin["result"]["sent"], N);
    assert_eq!(fin["id"], UUID);

    task.abort();
}

// --- mTLS: the verified client certificate is surfaced on `Peer::tls` ---------------------------

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

/// `S` = the client cert DER the server observed for this connection (`None` if the client sent none).
type CertState = Option<Vec<u8>>;

#[derive(Deserialize, Serialize)]
struct NoArgs {}
#[derive(Serialize)]
struct CertLen {
    len: usize,
}

/// A server whose `cert.len` returns the length of the client cert the transport surfaced.
fn mtls_server() -> JsonRpcServer<CertState> {
    let proto = JsonRpcProtocol::<CertState>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("cert.len"),
            |_a: NoArgs, cx: &RequestCtx<CertState>| {
                let len = cx.session().with_internal(|s| s.and_then(|c| c.as_ref()).map_or(0, Vec::len));
                Ok::<_, JsonRpcError>(CertLen { len })
            },
        ))
        .unwrap()
        .build();
    JsonRpcServer::<CertState>::builder("mtls-server")
        .allow_unauthenticated_network() // this transport test serves no $/sessionSetup
        // capture the verified client cert (if any) into the session state
        .state_from_peer(|peer| Some(peer.tls.as_ref().and_then(|t| t.peer_cert.clone())))
        .protocol("main", proto)
        .build()
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

/// Connect (optionally presenting a client cert), negotiate, call `cert.len`, return the length.
fn mtls_cert_len(addr: SocketAddr, client: Option<(Vec<u8>, Vec<u8>)>) -> usize {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE); // accept the self-signed server cert
    if let Some((cert_pem, key_pem)) = client {
        b.set_certificate(&X509::from_pem(&cert_pem).unwrap()).unwrap();
        b.set_private_key(&PKey::private_key_from_pem(&key_pem).unwrap()).unwrap();
    }
    let tcp = std::net::TcpStream::connect(addr).unwrap();
    let mut s = b.build().connect("localhost", tcp).unwrap();
    send(&mut s, &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}));
    let _ = recv(&mut s);
    send(&mut s, &json!({"jsonrpc":"2.0","method":"cert.len","id":UUID,"params":{}}));
    recv(&mut s)["result"]["len"].as_u64().unwrap() as usize
}

#[tokio::test]
async fn mtls_surfaces_verified_client_cert() {
    let (server_cert, server_key) = self_signed_pem();
    let (ca, ca_key) = make_ca();
    let (client_cert, client_key) = make_client(&ca, &ca_key, "client-alice");
    let ca_pem = ca.to_pem().unwrap();

    let tls = TlsConfig::from_pem_with_client_ca(&server_cert, &server_key, &ca_pem, TlsMode::Userspace).unwrap();
    let srv = mtls_server();
    let (listener, addr) = JsonRpcServer::<CertState>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_tls_listener(listener, tls).await })
    };

    // A CA-signed client cert is verified by the handshake and surfaces on the Peer.
    let with = tokio::task::spawn_blocking(move || mtls_cert_len(addr, Some((client_cert, client_key))))
        .await
        .unwrap();
    assert!(with > 0, "the verified client cert should surface on Peer::tls");

    // No client cert → the handshake still succeeds (PEER, not fail-if-absent) and nothing surfaces,
    // so SCRAM / other mechanisms remain usable over the same listener.
    let without = tokio::task::spawn_blocking(move || mtls_cert_len(addr, None)).await.unwrap();
    assert_eq!(without, 0, "no client cert → none surfaced, connection still works");

    task.abort();
}

// --- tls-server-end-point channel binding (RFC 5929), for SCRAM-SHA-512-PLUS --------------------

#[derive(Serialize)]
struct BindingResult {
    binding: String,
}

/// A server that reports this connection's `tls-server-end-point` binding (base64) to the client.
/// `S` carries the binding the transport surfaced on `Peer::tls`.
fn binding_server() -> JsonRpcServer<CertState> {
    let proto = JsonRpcProtocol::<CertState>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("binding.get"),
            |_a: NoArgs, cx: &RequestCtx<CertState>| {
                let binding = cx.session().with_internal(|s| {
                    s.and_then(|c| c.as_ref()).map(|c| openssl::base64::encode_block(c))
                });
                Ok::<_, JsonRpcError>(BindingResult { binding: binding.unwrap_or_default() })
            },
        ))
        .unwrap()
        .build();
    JsonRpcServer::<CertState>::builder("binding-server")
        .allow_unauthenticated_network() // transport test: the protocol has no $/sessionSetup
        .state_from_peer(|peer| Some(peer.tls.as_ref().and_then(|t| t.channel_binding.clone())))
        .protocol("main", proto)
        .build()
}

/// SHA-256 of a cert's DER, base64 — the expected binding for a SHA-256-signed certificate.
fn sha256_der_b64(cert_der: &[u8]) -> String {
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), cert_der).unwrap();
    openssl::base64::encode_block(&digest)
}

/// Connect, derive the binding *client-side* from the server cert we receive, then ask the server
/// what binding it computed. Returns `(server_reported, client_derived)`.
fn client_get_binding(addr: SocketAddr) -> (String, String) {
    let s = connect_tls(addr);
    // What a SCRAM client would independently derive from the server's leaf cert.
    let server_cert_der = s.ssl().peer_certificate().unwrap().to_der().unwrap();
    let client_derived = sha256_der_b64(&server_cert_der);

    let mut s = s;
    send(&mut s, &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}));
    let _ = recv(&mut s);
    send(&mut s, &json!({"jsonrpc":"2.0","method":"binding.get","id":UUID,"params":{}}));
    let reported = recv(&mut s)["result"]["binding"].as_str().unwrap().to_string();
    (reported, client_derived)
}

/// The server's `tls-server-end-point` binding (a) is surfaced on the connection, (b) equals
/// `SHA-256(server-cert-DER)` for our SHA-256-signed cert, and (c) is byte-identical to what the
/// client independently derives from the cert it received — i.e. the two ends agree on the binding
/// without ever exchanging it. Both TLS modes compute it through the same `tls_facts` helper.
#[tokio::test]
async fn tls_surfaces_server_end_point_binding() {
    let (cert, key) = self_signed_pem();
    let expected = sha256_der_b64(&X509::from_pem(&cert).unwrap().to_der().unwrap());

    for mode in [TlsMode::Userspace, TlsMode::Kernel] {
        let tls = TlsConfig::from_pem(&cert, &key, mode).unwrap();
        let srv = binding_server();
        let (listener, addr) = JsonRpcServer::<CertState>::bind_tcp("127.0.0.1:0").await.unwrap();
        let task = {
            let srv = srv.clone();
            tokio::spawn(async move { srv.serve_tls_listener(listener, tls).await })
        };

        let (reported, client_derived) =
            tokio::task::spawn_blocking(move || client_get_binding(addr)).await.unwrap();
        assert!(!reported.is_empty(), "{mode:?}: no binding surfaced on the connection");
        assert_eq!(reported, expected, "{mode:?}: binding != SHA-256(server cert DER)");
        assert_eq!(reported, client_derived, "{mode:?}: server and client disagree on the binding");

        task.abort();
    }
}
