//! TLS transport (the **Transport** layer, layer 1) over the **system** OpenSSL (the opt-in `tls`
//! feature), in two configurable modes (see [`TlsMode`]) — kernel TLS plus the
//! ordinary userspace-TLS path.
//!
//! - **Kernel TLS** ([`TlsMode::Kernel`]): only the *handshake* touches userspace OpenSSL
//!   (over a socket BIO, so OpenSSL holds the fd and can install kTLS). We then confirm the
//!   kernel actually installed the record crypto for both directions and that an
//!   AES-GCM/ChaCha20 cipher was negotiated, and run the whole connection — control messages
//!   *and* the bulk transfer — over the raw fd: plaintext to us, kernel-encrypted on the wire.
//!   So a zfs-replication stream is `splice`/`write`n straight on the fd and never enters
//!   userspace, and raw-fd transfer works over the encrypted link. kTLS is best-effort in
//!   OpenSSL, so if it doesn't engage we **fail closed** (refuse the connection) rather than
//!   leak plaintext on the wire.
//! - **Userspace TLS** ([`TlsMode::Userspace`]): an ordinary `tokio-openssl` `SslStream` pump.
//!   Works on any kernel / OpenSSL, but the fd carries ciphertext, so raw-fd transfer is
//!   refused on these connections.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use foreign_types::ForeignType;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod, SslOptions, SslRef, SslVerifyMode};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509Ref, X509};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_openssl::SslStream;

use crate::peer::{Peer, TlsPeer, TransportPosture};
use crate::server::JsonRpcServer;

// Linux kTLS confirmation: getsockopt(SOL_TLS, TLS_TX/TLS_RX) returns the 4-byte
// `struct tls_crypto_info` header once that direction's crypto is installed, else errors.
// SOL_TLS=282 (linux/socket.h), TLS_TX=1 / TLS_RX=2 (uapi/linux/tls.h).
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
// SSL_OP_ENABLE_KTLS = SSL_OP_BIT(3) = 1<<3 (the openssl crate has no named constant for it).
const SSL_OP_ENABLE_KTLS: u64 = 1 << 3;
// BIO_new_socket close flag: BIO_NOCLOSE = 0 (the BIO does not own/close the fd).
const BIO_NOCLOSE: libc::c_int = 0;

/// How a TLS listener carries records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsMode {
    /// Kernel TLS: handshake in userspace, then the raw kernel-encrypted fd. Transfer-capable;
    /// **fails closed** if kTLS does not engage.
    Kernel,
    /// Userspace TLS: a `tokio-openssl` pump. Works anywhere; raw-fd transfer is refused.
    Userspace,
}

/// TLS configuration: the OpenSSL acceptor + the [`TlsMode`].
pub struct TlsConfig {
    acceptor: Arc<SslAcceptor>,
    mode: TlsMode,
}

impl TlsConfig {
    /// Wrap a fully-configured [`SslAcceptor`] with a mode. For [`TlsMode::Kernel`] the caller
    /// must have set `SSL_OP_ENABLE_KTLS` on the context (a connection whose kTLS doesn't
    /// engage is refused).
    pub fn new(acceptor: SslAcceptor, mode: TlsMode) -> Self {
        TlsConfig { acceptor: Arc::new(acceptor), mode }
    }

    /// Build an acceptor for `mode` from a PEM certificate (chain) + private key, using
    /// Mozilla's intermediate profile. In [`TlsMode::Kernel`] this enables kTLS and disables
    /// session tickets (so the handshake needs no post-handshake server write).
    pub fn from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
        mode: TlsMode,
    ) -> Result<Self, openssl::error::ErrorStack> {
        Ok(TlsConfig { acceptor: Arc::new(build_acceptor(cert_pem, key_pem, mode, None)?), mode })
    }

    /// Like [`from_pem`](Self::from_pem) but also requests + verifies a **client** certificate
    /// (mTLS) against `client_ca_pem`. Verification is `PEER` (not fail-if-absent): a client that
    /// sends no certificate still completes the handshake (and may use another mechanism), while a
    /// presented certificate must chain to `client_ca_pem` or the handshake fails. The verified
    /// client cert is surfaced on [`Peer::tls`](crate::Peer::tls) for the auth stack.
    pub fn from_pem_with_client_ca(
        cert_pem: &[u8],
        key_pem: &[u8],
        client_ca_pem: &[u8],
        mode: TlsMode,
    ) -> Result<Self, openssl::error::ErrorStack> {
        let acceptor = build_acceptor(cert_pem, key_pem, mode, Some(client_ca_pem))?;
        Ok(TlsConfig { acceptor: Arc::new(acceptor), mode })
    }

    /// The configured acceptor — used by the WebSocket-over-TLS (`wss`) path, which always
    /// does a userspace handshake (the `mode` is irrelevant there, since the WebSocket library
    /// reads/writes the stream rather than a detached kTLS fd).
    #[cfg(feature = "websocket")]
    pub(crate) fn acceptor(&self) -> Arc<SslAcceptor> {
        self.acceptor.clone()
    }
}

impl<S: Send + Sync + 'static> JsonRpcServer<S> {
    /// Accept TLS connections on a bound TCP `listener` until an accept error occurs, per the
    /// config's [`TlsMode`]. A handshake failure (or kTLS not engaging, in kernel mode) drops
    /// just that connection.
    pub async fn serve_tls_listener(
        &self,
        listener: TcpListener,
        tls: TlsConfig,
    ) -> std::io::Result<()> {
        self.require_network_auth()?;
        let acceptor = tls.acceptor;
        let mode = tls.mode;
        loop {
            let (tcp, addr) = listener.accept().await?;
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let shared = self.shared.clone();
            tokio::spawn(async move {
                match mode {
                    TlsMode::Kernel => {
                        let Ok(std_tcp) = tcp.into_std() else { return };
                        // Handshake + kTLS probe blocks; run it off the reactor. Returns the kTLS
                        // socket plus the TLS facts (client cert + channel binding).
                        let (kfd, (cert, binding)) = match tokio::task::spawn_blocking(move || {
                            ktls_accept(&acceptor, std_tcp)
                        })
                        .await
                        {
                            Ok(Ok(pair)) => pair,
                            _ => return, // fail closed
                        };
                        if kfd.set_nonblocking(true).is_err() {
                            return;
                        }
                        let fd = kfd.as_raw_fd();
                        let Ok(stream) = TcpStream::from_std(kfd) else { return };
                        // kTLS: the fd is plaintext to us / kernel-encrypted → transfer works.
                        let engine = shared.engine.clone();
                        engine.serve(Box::new(stream), Some(fd), tls_peer(addr, cert, binding, Some(TransportPosture::KernelTls)), shared).await;
                    }
                    TlsMode::Userspace => {
                        let Some(stream) = userspace_accept(&acceptor, tcp).await else { return };
                        let (cert, binding) = tls_facts(stream.ssl());
                        // Userspace TLS: ciphertext on the fd → no raw-fd transfer (None).
                        let engine = shared.engine.clone();
                        engine.serve(Box::new(stream), None, tls_peer(addr, cert, binding, None), shared).await;
                    }
                }
            });
        }
    }

    /// Bind a TCP `addr` and serve TLS on it (bind + accept loop). Runs forever on the happy
    /// path — spawn it to run alongside other transports.
    pub async fn serve_tls(&self, addr: impl ToSocketAddrs, tls: TlsConfig) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve_tls_listener(listener, tls).await
    }
}

/// Userspace TLS handshake (a `tokio-openssl` `SslStream`) — the data path stays in userspace
/// (ciphertext on the fd). Returns the handshaked stream, or `None` on failure. Used by
/// [`TlsMode::Userspace`] and, with the `websocket` feature, the `wss` path.
pub(crate) async fn userspace_accept(
    acceptor: &SslAcceptor,
    tcp: TcpStream,
) -> Option<SslStream<TcpStream>> {
    let ssl = Ssl::new(acceptor.context()).ok()?;
    let mut stream = SslStream::new(ssl, tcp).ok()?;
    std::pin::Pin::new(&mut stream).accept().await.ok()?;
    Some(stream)
}

/// Blocking kTLS handshake on `tcp` over a socket BIO (so OpenSSL holds the fd and installs
/// kTLS). Returns the raw kTLS socket on success; refuses the connection (`Err`) on a non-kTLS
/// cipher or if kTLS didn't engage for both directions. The BIO is `BIO_NOCLOSE`, so freeing
/// the `Ssl` leaves the kernel kTLS state on `tcp`.
fn ktls_accept(
    acceptor: &SslAcceptor,
    tcp: std::net::TcpStream,
) -> std::io::Result<(std::net::TcpStream, TlsFacts)> {
    tcp.set_nonblocking(false)?;
    let fd = tcp.as_raw_fd();
    let ssl = Ssl::new(acceptor.context()).map_err(|e| io_other(e.to_string()))?;

    // SAFETY: a socket BIO over `fd` with BIO_NOCLOSE does not own/close the fd; SSL takes
    // ownership of the BIO (freed on SSL_free). `fd` (owned by `tcp`) outlives `ssl` here.
    #[allow(unsafe_code)]
    let rc = unsafe {
        let bio = openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE);
        if bio.is_null() {
            return Err(io_other("BIO_new_socket failed".to_string()));
        }
        openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
        openssl_sys::SSL_accept(ssl.as_ptr())
    };
    if rc != 1 {
        // SAFETY: reading the error code for the just-used SSL object.
        #[allow(unsafe_code)]
        let err = unsafe { openssl_sys::SSL_get_error(ssl.as_ptr(), rc) };
        return Err(io_other(format!("TLS handshake failed (SSL_accept={rc}, ssl_error={err})")));
    }

    let cipher = ssl.current_cipher().map(|c| c.name()).unwrap_or("");
    if !cipher.contains("GCM") && !cipher.contains("CHACHA20") {
        return Err(io_other(format!("kTLS requires an AES-GCM/ChaCha20 cipher; got {cipher:?}")));
    }
    confirm_ktls(fd)?;
    // The verified client cert (mTLS) + this connection's channel binding, read before SSL_free.
    let facts = tls_facts(&ssl);
    drop(ssl); // SSL_free frees the BIO (BIO_NOCLOSE → fd not closed); kTLS stays on the socket
    Ok((tcp, facts))
}

/// Build a server [`SslAcceptor`] from PEM cert+key (Mozilla intermediate profile), optionally
/// requesting + verifying a client certificate against `client_ca`, and enabling kTLS for
/// [`TlsMode::Kernel`].
fn build_acceptor(
    cert_pem: &[u8],
    key_pem: &[u8],
    mode: TlsMode,
    client_ca: Option<&[u8]>,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let key = PKey::private_key_from_pem(key_pem)?;
    builder.set_private_key(&key)?;
    let cert = X509::from_pem(cert_pem)?;
    builder.set_certificate(&cert)?;
    builder.check_private_key()?;
    if let Some(ca_pem) = client_ca {
        let ca = X509::from_pem(ca_pem)?;
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(ca.clone())?;
        builder.set_verify_cert_store(store.build())?;
        builder.add_client_ca(&ca)?;
        builder.set_verify(SslVerifyMode::PEER);
    }
    if mode == TlsMode::Kernel {
        builder.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
        builder.set_num_tickets(0)?;
    }
    Ok(builder.build())
}

/// The TLS facts a completed handshake surfaces to the auth stack: `(verified client cert DER,
/// tls-server-end-point channel binding)` — either may be `None`.
type TlsFacts = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Read the [`TlsFacts`] from a live `SslRef`:
///
/// - The **client cert** is `Some` only if the peer presented one (the acceptor was built with
///   [`from_pem_with_client_ca`](TlsConfig::from_pem_with_client_ca)) — for mTLS.
/// - The **channel binding** is computed from the server's *own* leaf certificate
///   ([`tls_server_end_point`]); `None` if the server cert's signature uses no single hash (e.g.
///   Ed25519), where RFC 5929 leaves the binding undefined.
pub(crate) fn tls_facts(ssl: &SslRef) -> TlsFacts {
    let peer_cert = ssl.peer_certificate().and_then(|c| c.to_der().ok());
    let binding = ssl.certificate().and_then(tls_server_end_point);
    (peer_cert, binding)
}

/// RFC 5929 §4.1 `tls-server-end-point`: the hash of the server certificate (octet-for-octet as it
/// appears in the Certificate message) under the hash of the cert's own signature algorithm —
/// except MD5/SHA-1 are upgraded to SHA-256, and a signature with no single hash yields `None`
/// (the binding is undefined there, e.g. Ed25519). Counterpart to the C
/// `scram_compute_tls_server_end_point`, so a binding either side computes for the same cert is
/// byte-identical.
///
/// The digest comes from `OBJ_find_sigid_algs` (via [`Nid::signature_algorithms`]), which resolves
/// the hash for the PKCS#1-v1.5 and ECDSA signatures TrueNAS issues. It returns `undef` for the
/// few schemes that carry the hash in the algorithm *parameters* rather than the OID (RSASSA-PSS),
/// where the C falls back to `X509_get_signature_info`; such a cert yields `None` here, so the
/// connection simply can't offer SCRAM-PLUS — it never produces a wrong binding.
fn tls_server_end_point(cert: &X509Ref) -> Option<Vec<u8>> {
    let sig_nid = cert.signature_algorithm().object().nid();
    let digest_nid = sig_nid.signature_algorithms()?.digest;
    let md = match digest_nid {
        Nid::UNDEF => return None,                       // no single hash → undefined
        Nid::MD5 | Nid::SHA1 => MessageDigest::sha256(), // RFC 5929: weak hash → SHA-256
        nid => MessageDigest::from_nid(nid)?,
    };
    cert.digest(md).ok().map(|d| d.to_vec())
}

/// A TLS [`Peer`] at `addr` carrying the (optional) verified client cert and channel binding.
pub(crate) fn tls_peer(
    addr: SocketAddr,
    peer_cert: Option<Vec<u8>>,
    channel_binding: Option<Vec<u8>>,
    posture: Option<TransportPosture>,
) -> Peer {
    Peer { tls: Some(TlsPeer { peer_cert, channel_binding }), posture, ..Peer::tcp(addr) }
}

/// Refuse unless the kernel installed TLS crypto for both directions on `fd`.
fn confirm_ktls(fd: RawFd) -> std::io::Result<()> {
    for (dir, label) in [(TLS_TX, "TX"), (TLS_RX, "RX")] {
        let mut buf = [0u8; 4];
        let mut len = buf.len() as libc::socklen_t;
        // SAFETY: `getsockopt` writes up to `len` bytes into `buf` and updates `len`.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::getsockopt(fd, SOL_TLS, dir, buf.as_mut_ptr().cast(), &mut len) };
        if rc != 0 {
            let errno = std::io::Error::last_os_error();
            return Err(io_other(format!(
                "kTLS did not engage for {label} ({errno}); refusing userspace-TLS fallback"
            )));
        }
    }
    Ok(())
}

fn io_other(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}
