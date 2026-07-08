//! TLS **client** transport over the **system** OpenSSL (the opt-in `tls` feature) — the mirror of
//! the server's `tls` module.
//!
//! A direct `tls://` connection uses **kernel TLS**: only the handshake touches userspace OpenSSL
//! (over a socket BIO, so OpenSSL holds the fd and installs kTLS), then the whole connection —
//! control messages *and* a raw-fd transfer — runs over the raw fd: plaintext to us,
//! kernel-encrypted on the wire. So a bulk transfer works over the encrypted link (the fd is lent to
//! the handler exactly as for a plaintext socket). kTLS is best-effort in OpenSSL, so if it does not
//! engage we **fail closed** (refuse the connection) rather than fall back to a userspace pump whose
//! fd would carry ciphertext.
//!
//! The userspace path ([`userspace_connect`]) is used **only** to back `wss` (WebSocket-over-TLS),
//! where the WebSocket library owns the stream and a detached kTLS fd does not apply — and where a
//! raw-fd transfer is refused anyway. It is the analogue of the server's userspace `SslStream`.

use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use foreign_types::ForeignType;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509Ref, X509};

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

/// TLS material for a client connection: the OpenSSL connector (trust roots, optional mTLS client
/// certificate) plus whether to verify the server's hostname. Build one with [`ClientTls::insecure`]
/// (self-signed servers / tests) or [`ClientTls::builder`] (custom roots + mTLS), then pass it to
/// [`Endpoint::tls`](crate::Endpoint::tls).
#[derive(Clone)]
pub struct ClientTls {
    connector: Arc<SslConnector>,
    verify_hostname: bool,
}

impl std::fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connector holds key material — keep it opaque.
        f.debug_struct("ClientTls")
            .field("verify_hostname", &self.verify_hostname)
            .finish_non_exhaustive()
    }
}

impl ClientTls {
    /// **No** server-certificate verification — accept any certificate, skip hostname checks. For a
    /// self-signed server or tests **only**; never use it against an untrusted network. For real
    /// verification use [`builder`](Self::builder).
    pub fn insecure() -> Self {
        let mut b = SslConnector::builder(SslMethod::tls()).expect("openssl TLS connector");
        b.set_verify(SslVerifyMode::NONE);
        b.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
        ClientTls {
            connector: Arc::new(b.build()),
            verify_hostname: false,
        }
    }

    /// A builder for a verifying client: custom trust roots and/or an mTLS client certificate.
    pub fn builder() -> ClientTlsBuilder {
        ClientTlsBuilder::default()
    }
}

/// Builder for a verifying [`ClientTls`]. With no roots set, the system trust store is used; add a
/// client certificate with [`client_cert_pem`](Self::client_cert_pem) for mTLS.
#[derive(Default)]
pub struct ClientTlsBuilder {
    roots_pem: Option<Vec<u8>>,
    client_cert: Option<(Vec<u8>, Vec<u8>)>,
    accept_invalid: bool,
}

impl ClientTlsBuilder {
    /// Verify the server against these PEM CA certificate(s), **replacing** the system trust store
    /// (so only this CA is trusted — e.g. an appliance's own CA).
    pub fn roots_pem(mut self, ca_pem: &[u8]) -> Self {
        self.roots_pem = Some(ca_pem.to_vec());
        self
    }

    /// Present this PEM client certificate + private key for mTLS (the server verifies it against its
    /// configured client CA).
    pub fn client_cert_pem(mut self, cert_pem: &[u8], key_pem: &[u8]) -> Self {
        self.client_cert = Some((cert_pem.to_vec(), key_pem.to_vec()));
        self
    }

    /// Disable certificate + hostname verification (self-signed servers / tests). **Dangerous** on an
    /// untrusted network — prefer [`roots_pem`](Self::roots_pem).
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.accept_invalid = true;
        self
    }

    /// Build the [`ClientTls`]. Errors if any PEM fails to parse or the client key doesn't match its
    /// certificate.
    pub fn build(self) -> Result<ClientTls, openssl::error::ErrorStack> {
        let mut b = SslConnector::builder(SslMethod::tls())?;
        // Enable kTLS on the context: it engages for the direct `tls://` (socket-BIO) handshake and
        // is inert for the userspace `wss` pump (no raw socket fd for the kernel to attach to).
        b.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
        if let Some(ca_pem) = &self.roots_pem {
            let mut store = X509StoreBuilder::new()?;
            for cert in X509::stack_from_pem(ca_pem)? {
                store.add_cert(cert)?;
            }
            b.set_cert_store(store.build());
        }
        if let Some((cert_pem, key_pem)) = &self.client_cert {
            let cert = X509::from_pem(cert_pem)?;
            let key = PKey::private_key_from_pem(key_pem)?;
            b.set_certificate(&cert)?;
            b.set_private_key(&key)?;
            b.check_private_key()?;
        }
        let verify_hostname = if self.accept_invalid {
            b.set_verify(SslVerifyMode::NONE);
            false
        } else {
            true
        };
        Ok(ClientTls {
            connector: Arc::new(b.build()),
            verify_hostname,
        })
    }
}

/// Blocking kTLS handshake on `tcp` over a socket BIO (so OpenSSL holds the fd and installs kTLS).
/// Returns the raw kTLS socket **and the `tls-server-end-point` channel binding** on success; refuses
/// the connection (`Err`) on a non-kTLS cipher or if kTLS didn't engage for both directions. The BIO
/// is `BIO_NOCLOSE`, so freeing the `Ssl` leaves the kernel kTLS state on `tcp`. Mirror of the
/// server's `ktls_accept`.
pub(crate) fn ktls_connect(
    tls: &ClientTls,
    server_name: &str,
    tcp: std::net::TcpStream,
) -> std::io::Result<(std::net::TcpStream, Option<Vec<u8>>)> {
    tcp.set_nonblocking(false)?;
    let fd = tcp.as_raw_fd();
    let mut config = tls
        .connector
        .configure()
        .map_err(|e| io_other(e.to_string()))?;
    config.set_verify_hostname(tls.verify_hostname);
    let ssl = config
        .into_ssl(server_name)
        .map_err(|e| io_other(e.to_string()))?;

    // SAFETY: a socket BIO over `fd` with BIO_NOCLOSE does not own/close the fd; SSL takes ownership
    // of the BIO (freed on SSL_free). `fd` (owned by `tcp`) outlives `ssl` here.
    #[allow(unsafe_code)]
    let rc = unsafe {
        let bio = openssl_sys::BIO_new_socket(fd, BIO_NOCLOSE);
        if bio.is_null() {
            return Err(io_other("BIO_new_socket failed".to_string()));
        }
        openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
        openssl_sys::SSL_connect(ssl.as_ptr())
    };
    if rc != 1 {
        // SAFETY: reading the error code for the just-used SSL object.
        #[allow(unsafe_code)]
        let err = unsafe { openssl_sys::SSL_get_error(ssl.as_ptr(), rc) };
        return Err(io_other(format!(
            "TLS handshake failed (SSL_connect={rc}, ssl_error={err})"
        )));
    }

    let cipher = ssl.current_cipher().map(|c| c.name()).unwrap_or("");
    if !cipher.contains("GCM") && !cipher.contains("CHACHA20") {
        return Err(io_other(format!(
            "kTLS requires an AES-GCM/ChaCha20 cipher; got {cipher:?}"
        )));
    }
    confirm_ktls(fd)?;
    // The `tls-server-end-point` channel binding, from the server's cert — read before `SSL_free`.
    let binding = channel_binding(&ssl);
    drop(ssl); // SSL_free frees the BIO (BIO_NOCLOSE → fd not closed); kTLS stays on the socket
    Ok((tcp, binding))
}

/// The RFC 5929 `tls-server-end-point` channel binding for a handshaked connection: the hash of the
/// **server's** certificate (the peer cert the client received) under that cert's own signature-
/// algorithm digest (MD5/SHA-1 upgraded to SHA-256; a signature with no single hash → `None`). The
/// counterpart of the server's `tls_server_end_point`, so both sides compute a byte-identical value.
fn channel_binding(ssl: &openssl::ssl::SslRef) -> Option<Vec<u8>> {
    let cert = ssl.peer_certificate()?;
    tls_server_end_point(&cert)
}

fn tls_server_end_point(cert: &X509Ref) -> Option<Vec<u8>> {
    let sig_nid = cert.signature_algorithm().object().nid();
    let digest_nid = sig_nid.signature_algorithms()?.digest;
    let md = match digest_nid {
        Nid::UNDEF => return None, // no single hash → undefined
        Nid::MD5 | Nid::SHA1 => MessageDigest::sha256(), // RFC 5929: weak hash → SHA-256
        nid => MessageDigest::from_nid(nid)?,
    };
    cert.digest(md).ok().map(|d| d.to_vec())
}

/// Userspace TLS handshake (a `tokio-openssl` `SslStream`) — the data path stays in userspace
/// (ciphertext on the fd). Used **only** to back `wss` (the WebSocket library owns the stream, so
/// kTLS's detached fd doesn't apply); a raw-fd transfer is refused over it. Mirror of the server's
/// `userspace_accept`.
#[cfg(feature = "websocket")]
pub(crate) async fn userspace_connect(
    tls: &ClientTls,
    server_name: &str,
    tcp: tokio::net::TcpStream,
) -> std::io::Result<(
    tokio_openssl::SslStream<tokio::net::TcpStream>,
    Option<Vec<u8>>,
)> {
    let mut config = tls
        .connector
        .configure()
        .map_err(|e| io_other(e.to_string()))?;
    config.set_verify_hostname(tls.verify_hostname);
    let ssl = config
        .into_ssl(server_name)
        .map_err(|e| io_other(e.to_string()))?;
    let mut stream =
        tokio_openssl::SslStream::new(ssl, tcp).map_err(|e| io_other(e.to_string()))?;
    std::pin::Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|e| io_other(e.to_string()))?;
    let binding = channel_binding(stream.ssl());
    Ok((stream, binding))
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
