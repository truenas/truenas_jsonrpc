//! Connection endpoints + client tuning.

use std::path::PathBuf;
use std::time::Duration;

/// Where a client connects.
#[derive(Clone, Debug)]
pub enum Endpoint {
    /// An AF_UNIX socket path.
    Unix(PathBuf),
    /// A TCP `host:port` address.
    Tcp(String),
    /// An encrypted TCP `host:port` over kernel TLS (the `tls` feature). `server_name` is the SNI /
    /// verification hostname. Transfer-capable (the fd is plaintext to us); **fails closed** if kTLS
    /// doesn't engage.
    #[cfg(feature = "tls")]
    Tls {
        /// The TCP `host:port` to connect.
        addr: String,
        /// The SNI / certificate-verification hostname.
        server_name: String,
        /// The TLS material (trust roots, optional mTLS certificate).
        tls: crate::tls::ClientTls,
    },
    /// A WebSocket endpoint (`ws://`) over TCP (the `websocket` feature). One JSON-RPC frame per
    /// message; not transfer-capable (the WebSocket library owns the wire).
    #[cfg(feature = "websocket")]
    Ws {
        /// The TCP `host:port` to connect.
        addr: String,
        /// The WebSocket request path (e.g. `/`).
        path: String,
    },
    /// A WebSocket-over-TLS endpoint (`wss://`) — a userspace TLS handshake, then WebSocket (the
    /// `websocket` + `tls` features). Not transfer-capable.
    #[cfg(all(feature = "tls", feature = "websocket"))]
    Wss {
        /// The TCP `host:port` to connect.
        addr: String,
        /// The SNI / certificate-verification hostname (also the WebSocket `Host`).
        server_name: String,
        /// The WebSocket request path (e.g. `/`).
        path: String,
        /// The TLS material (trust roots, optional mTLS certificate).
        tls: crate::tls::ClientTls,
    },
}

impl Endpoint {
    /// An AF_UNIX endpoint at `path`.
    pub fn unix(path: impl Into<PathBuf>) -> Self {
        Endpoint::Unix(path.into())
    }
    /// A TCP endpoint at `addr` (`host:port`).
    pub fn tcp(addr: impl Into<String>) -> Self {
        Endpoint::Tcp(addr.into())
    }
    /// A kernel-TLS endpoint at `addr` (`host:port`), verified/SNI'd as `server_name`, using `tls`.
    #[cfg(feature = "tls")]
    pub fn tls(
        addr: impl Into<String>,
        server_name: impl Into<String>,
        tls: crate::tls::ClientTls,
    ) -> Self {
        Endpoint::Tls { addr: addr.into(), server_name: server_name.into(), tls }
    }
    /// A `ws://` endpoint at `addr` (`host:port`) with request `path` (e.g. `/`).
    #[cfg(feature = "websocket")]
    pub fn ws(addr: impl Into<String>, path: impl Into<String>) -> Self {
        Endpoint::Ws { addr: addr.into(), path: path.into() }
    }
    /// A `wss://` endpoint at `addr` (`host:port`), verified/SNI'd as `server_name`, request `path`.
    #[cfg(all(feature = "tls", feature = "websocket"))]
    pub fn wss(
        addr: impl Into<String>,
        server_name: impl Into<String>,
        path: impl Into<String>,
        tls: crate::tls::ClientTls,
    ) -> Self {
        Endpoint::Wss { addr: addr.into(), server_name: server_name.into(), path: path.into(), tls }
    }
}

/// Client tuning. [`Default`]: TCP keep-alive after 30s idle and a 4 MiB inbound message limit.
///
/// A call has **no** timeout — per JSON-RPC, a request stays outstanding until it is answered, so a
/// call waits for its reply however long the op takes (a job, a raw-fd transfer). The client never
/// scavenges by duration; a *doomed* call is failed by the **connection** dying — a dead peer
/// (detected by keep-alive on TCP, or EOF on AF_UNIX) drops the pending senders, so every in-flight
/// call resolves as [`Closed`](crate::ClientError::Closed).
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// TCP keep-alive idle time (TCP endpoints only; AF_UNIX detects peer death via EOF). Probes a
    /// silent connection so a crashed/partitioned peer is detected in bounded time **independent of
    /// how long any call runs**. `None` disables it.
    pub tcp_keepalive: Option<Duration>,
    /// Max inbound message (frame) size accepted.
    pub limit: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig { tcp_keepalive: Some(Duration::from_secs(30)), limit: 4 * 1024 * 1024 }
    }
}
