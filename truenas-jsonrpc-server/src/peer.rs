//! The connected peer's identity — the **Transport** layer (layer 1): the [`Transport`] kind,
//! [`Peer`], and [`TransportPosture`]. Handed to the server's state-from-peer builder so the
//! per-connection session state (the protocol's `S`) can carry the caller's credentials /
//! address.

use std::net::SocketAddr;

#[cfg(feature = "websocket")]
use http::HeaderMap;
use serde::{Deserialize, Serialize};

/// Which transport a connection arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// An AF_UNIX (local) socket — carries [`Ucred`] and supports raw-fd transfer.
    Unix,
    /// A TCP socket — carries the peer [`SocketAddr`].
    Tcp,
}

/// The trust/encryption posture a listener declares for its connections — what the auth stack may
/// rely on. A property of the underlying socket + TLS termination, **independent of framing** (raw
/// JSON-RPC and WebSocket over the same socket share a posture). A connection with no posture
/// (`Peer::posture == None`) — plain TCP or userspace-TLS — is not trusted and may not authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportPosture {
    /// In-app kTLS termination: a direct, encrypted connection with a kernel-plaintext fd.
    KernelTls,
    /// Behind a reverse proxy over AF_UNIX (TLS terminated upstream). `SO_PEERCRED` is the proxy's
    /// uid, **not** the end client's — never trusted; auth via a credential mechanism or the broker.
    ProxiedUnix,
    /// A genuinely local AF_UNIX peer: `SO_PEERCRED` **is** the calling process, trusted for
    /// peer-cred auth.
    TrustedLocalUnix,
}

/// The trust a local AF_UNIX listener declares: a reverse proxy in front, or a genuinely local peer.
/// Maps to [`TransportPosture::ProxiedUnix`] / [`TransportPosture::TrustedLocalUnix`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnixTrust {
    /// Behind a reverse proxy — peer-cred is the proxy's, not the client's.
    Proxied,
    /// A genuinely local peer — peer-cred is the calling process.
    Local,
}

impl From<UnixTrust> for TransportPosture {
    fn from(t: UnixTrust) -> Self {
        match t {
            UnixTrust::Proxied => TransportPosture::ProxiedUnix,
            UnixTrust::Local => TransportPosture::TrustedLocalUnix,
        }
    }
}

/// The real client behind a reverse proxy, recovered from proxy-forwarded request metadata (e.g.
/// nginx's `X-Real-Remote-*` headers on the WebSocket upgrade). Trusted only on a
/// [`Proxied`](UnixTrust::Proxied) listener (where the proxy owns the socket); surfaced as the
/// connection's `origin` in `$/sessions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardedOrigin {
    /// The real client address the proxy reported (typically an IP).
    pub addr: String,
    /// The real client port, if the proxy reported it.
    pub port: Option<u16>,
    /// Whether the client→proxy leg was TLS (the proxy terminated https).
    pub secure: bool,
}

impl ForwardedOrigin {
    /// Render as `addr:port` (or `[addr]:port` for an IPv6 literal); just `addr` when there's no port.
    pub fn render(&self) -> String {
        match self.port {
            Some(p) if self.addr.contains(':') => format!("[{}]:{p}", self.addr),
            Some(p) => format!("{}:{p}", self.addr),
            None => self.addr.clone(),
        }
    }

    /// Parse the real client from the TrueNAS-middleware nginx headers: `X-Real-Remote-Addr`,
    /// `X-Real-Remote-Port`, and `X-Https` (`"on"` ⇒ the client→proxy leg was TLS). `None` if the
    /// address header is absent or empty. A drop-in
    /// [`forwarded_extractor`](crate::JsonRpcServerBuilder::forwarded_extractor) for the standard
    /// nginx setup; pass your own closure to read different headers. Requires the `websocket` feature.
    #[cfg(feature = "websocket")]
    pub fn from_real_remote_headers(headers: &HeaderMap) -> Option<Self> {
        let addr = headers.get("x-real-remote-addr")?.to_str().ok()?.trim();
        if addr.is_empty() {
            return None;
        }
        let port = headers
            .get("x-real-remote-port")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok());
        let secure =
            headers.get("x-https").and_then(|v| v.to_str().ok()).is_some_and(|s| s.trim() == "on");
        Some(ForwardedOrigin { addr: addr.to_string(), port, secure })
    }
}

/// Unix peer credentials from `SO_PEERCRED` (the connecting process's pid/uid/gid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ucred {
    /// Connecting process id.
    pub pid: i32,
    /// Connecting effective user id.
    pub uid: u32,
    /// Connecting effective group id.
    pub gid: u32,
}

/// Identity of the connected peer, passed to the server's state-from-peer builder.
#[derive(Clone, Debug)]
pub struct Peer {
    /// The transport the connection arrived on.
    pub transport: Transport,
    /// Peer credentials — `Some` on AF_UNIX (`SO_PEERCRED`), `None` on TCP.
    pub ucred: Option<Ucred>,
    /// Peer address — `Some` on TCP, `None` on AF_UNIX.
    pub addr: Option<SocketAddr>,
    /// TLS context — `Some` iff the connection is TLS / `wss` (so its presence marks the channel
    /// encrypted). Carries the verified client certificate (mTLS) and the channel-binding value.
    pub tls: Option<TlsPeer>,
    /// The listener's declared [`TransportPosture`] — the trust the auth stack may rely on. `None` =
    /// an insecure / undeclared transport (plain TCP, userspace-TLS) that may not authenticate.
    pub posture: Option<TransportPosture>,
    /// The real client behind a reverse proxy, if a `forwarded_extractor` recovered it on a
    /// `Proxied` listener. `None` otherwise — the origin then comes from the immediate peer.
    pub forwarded: Option<ForwardedOrigin>,
}

/// TLS facts about a connection, surfaced to the auth stack.
#[derive(Clone, Debug, Default)]
pub struct TlsPeer {
    /// The verified client certificate (DER), if the peer presented one (mTLS). `None` if the
    /// client sent no certificate (the acceptor requests but does not require one, so SCRAM/other
    /// mechanisms still apply).
    pub peer_cert: Option<Vec<u8>>,
    /// The server's `tls-server-end-point` channel-binding value (RFC 5929) for this connection —
    /// the hash of the server's leaf certificate — for SCRAM-SHA-512-PLUS. `None` if the server
    /// cert's signature algorithm has no single hash (e.g. Ed25519), where the binding is undefined.
    pub channel_binding: Option<Vec<u8>>,
}

impl Peer {
    /// An AF_UNIX peer with the given `SO_PEERCRED` credentials, defaulting to the
    /// [trusted-local](TransportPosture::TrustedLocalUnix) posture (peer-cred is the caller). A
    /// proxied AF_UNIX listener overrides it via [`with_posture`](Self::with_posture) /
    /// [`UnixTrust::Proxied`].
    pub fn unix(ucred: Option<Ucred>) -> Self {
        Self {
            transport: Transport::Unix,
            ucred,
            addr: None,
            tls: None,
            posture: Some(TransportPosture::TrustedLocalUnix),
            forwarded: None,
        }
    }

    /// A plain (non-TLS) TCP peer at `addr` — **no** posture (an insecure transport that may not
    /// authenticate).
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            transport: Transport::Tcp,
            ucred: None,
            addr: Some(addr),
            tls: None,
            posture: None,
            forwarded: None,
        }
    }

    /// Stamp the listener's declared [`TransportPosture`] (builder form for the serve loops).
    #[must_use]
    pub fn with_posture(mut self, posture: TransportPosture) -> Self {
        self.posture = Some(posture);
        self
    }

    /// Attach the real client [`ForwardedOrigin`] recovered from proxy-forwarded metadata (the serve
    /// loop sets this on a `Proxied` listener via the configured `forwarded_extractor`).
    #[must_use]
    pub fn with_forwarded(mut self, forwarded: ForwardedOrigin) -> Self {
        self.forwarded = Some(forwarded);
        self
    }
}

/// Read `SO_PEERCRED` for an AF_UNIX socket fd (Linux). `None` if the syscall fails or the
/// platform isn't Linux (BSD uses a different mechanism; TrueNAS SCALE is Linux).
#[cfg(target_os = "linux")]
pub(crate) fn peer_cred(fd: std::os::fd::RawFd) -> Option<Ucred> {
    // SAFETY: `getsockopt` writes a `struct ucred` of `len` bytes into `cred` and updates
    // `len`; both out-params are valid for the call and the size matches `SO_PEERCRED`.
    #[allow(unsafe_code)]
    unsafe {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
            &mut len,
        );
        (rc == 0).then_some(Ucred { pid: cred.pid, uid: cred.uid, gid: cred.gid })
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn peer_cred(_fd: std::os::fd::RawFd) -> Option<Ucred> {
    None
}

/// Toggle `O_NONBLOCK` on `fd`. A raw-fd transfer hands the socket to a blocking handler
/// callback, so the fd must be put in blocking mode for the duration and restored to
/// non-blocking afterwards (tokio's reactor owns it again).
pub(crate) fn set_blocking(fd: std::os::fd::RawFd, blocking: bool) -> std::io::Result<()> {
    // SAFETY: `fd` is a live socket owned by the connection; `fcntl` here only reads and
    // rewrites its status flags.
    #[allow(unsafe_code)]
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let next = if blocking { flags & !libc::O_NONBLOCK } else { flags | libc::O_NONBLOCK };
        if libc::fcntl(fd, libc::F_SETFL, next) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "websocket"))]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn forwarded_origin_parses_real_remote_headers() {
        let o = ForwardedOrigin::from_real_remote_headers(&headers(&[
            ("X-Real-Remote-Addr", "203.0.113.7"),
            ("X-Real-Remote-Port", "54321"),
            ("X-Https", "on"),
        ]))
        .unwrap();
        assert_eq!(
            o,
            ForwardedOrigin { addr: "203.0.113.7".into(), port: Some(54321), secure: true }
        );
        assert_eq!(o.render(), "203.0.113.7:54321");
    }

    #[test]
    fn forwarded_origin_handles_ipv6_and_plain_http() {
        let o = ForwardedOrigin::from_real_remote_headers(&headers(&[
            ("X-Real-Remote-Addr", "2001:db8::1"),
            ("X-Real-Remote-Port", "443"),
        ]))
        .unwrap();
        assert!(!o.secure); // no X-Https header
        assert_eq!(o.render(), "[2001:db8::1]:443"); // bracketed IPv6
    }

    #[test]
    fn forwarded_origin_is_none_without_an_address() {
        assert!(ForwardedOrigin::from_real_remote_headers(&headers(&[("X-Https", "on")])).is_none());
        assert!(ForwardedOrigin::from_real_remote_headers(&HeaderMap::new()).is_none());
    }
}
