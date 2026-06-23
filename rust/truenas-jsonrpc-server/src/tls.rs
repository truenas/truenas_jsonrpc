//! TLS transport over the **system** OpenSSL (the opt-in `tls` feature), in two configurable
//! modes (see [`TlsMode`]) — a port of Python's `_ktls` plus the ordinary userspace-TLS path.
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

use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use foreign_types::ForeignType;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod, SslOptions};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_openssl::SslStream;

use crate::connection;
use crate::peer::{Peer, Transport};
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
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let key = openssl::pkey::PKey::private_key_from_pem(key_pem)?;
        builder.set_private_key(&key)?;
        let cert = openssl::x509::X509::from_pem(cert_pem)?;
        builder.set_certificate(&cert)?;
        builder.check_private_key()?;
        if mode == TlsMode::Kernel {
            builder.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
            builder.set_num_tickets(0)?;
        }
        Ok(TlsConfig { acceptor: Arc::new(builder.build()), mode })
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
        let acceptor = tls.acceptor;
        let mode = tls.mode;
        loop {
            let (tcp, addr) = listener.accept().await?;
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let shared = self.shared.clone();
            let peer = Peer { transport: Transport::Tcp, ucred: None, addr: Some(addr) };
            tokio::spawn(async move {
                match mode {
                    TlsMode::Kernel => {
                        let Ok(std_tcp) = tcp.into_std() else { return };
                        // Handshake + kTLS probe blocks; run it off the reactor.
                        let kfd = match tokio::task::spawn_blocking(move || {
                            ktls_accept(&acceptor, std_tcp)
                        })
                        .await
                        {
                            Ok(Ok(s)) => s,
                            _ => return, // fail closed
                        };
                        if kfd.set_nonblocking(true).is_err() {
                            return;
                        }
                        let fd = kfd.as_raw_fd();
                        let Ok(stream) = TcpStream::from_std(kfd) else { return };
                        // kTLS: the fd is plaintext to us / kernel-encrypted → transfer works.
                        connection::serve(stream, Some(fd), peer, shared).await;
                    }
                    TlsMode::Userspace => {
                        let Some(stream) = userspace_accept(&acceptor, tcp).await else { return };
                        // Userspace TLS: ciphertext on the fd → no raw-fd transfer (None).
                        connection::serve(stream, None, peer, shared).await;
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
) -> std::io::Result<std::net::TcpStream> {
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
    drop(ssl); // SSL_free frees the BIO (BIO_NOCLOSE → fd not closed); kTLS stays on the socket
    Ok(tcp)
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
