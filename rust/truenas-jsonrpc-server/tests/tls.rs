//! kTLS round-trip (the `tls` feature): a kTLS-enabled server negotiates + dispatches over an
//! encrypted TCP connection. The server's data path is the raw kernel-encrypted fd (no
//! userspace TLS pump); the client is an ordinary blocking OpenSSL TLS client. Requires the
//! kernel `tls` module + an OpenSSL built with kTLS (else the server fails closed and the
//! round-trip won't complete — which is the intended behaviour).
//!
//! Run with: `cargo test -p truenas-jsonrpc-server --features tls`
#![cfg(feature = "tls")]

use std::io::{Read, Write};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_jsonrpc::{
    FileTransfer, JsonRpcError, JsonRpcFdTransferMethod, JsonRpcMethod, JsonRpcProtocol, MethodDef,
    RequestCtx, TransferDirection,
};
use truenas_jsonrpc_server::{FileTransferExt, JsonRpcServer, TlsConfig, TlsMode};

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

#[derive(Deserialize)]
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
    JsonRpcServer::<()>::builder("tls-server").protocol("main", proto).build()
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
