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
