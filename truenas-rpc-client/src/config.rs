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

/// Client tuning. [`Default`] is a 30s call timeout and a 4 MiB inbound message limit.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Max time to await one call's reply before [`ClientError::Timeout`](crate::ClientError::Timeout).
    pub call_timeout: Duration,
    /// Max inbound message (frame) size accepted.
    pub limit: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig { call_timeout: Duration::from_secs(30), limit: 4 * 1024 * 1024 }
    }
}
