//! [`JsonRpcServer`] — binds one or more transports, selects a named protocol per connection
//! with `$/negotiate`, and serves the dispatch loop. Port of `server.py` (the notification
//! routing is push-based via each session's [`Outbound`](truenas_jsonrpc::Outbound), so the
//! per-protocol drain threads Python needs don't exist here).

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, ToSocketAddrs, UnixListener};
use truenas_jsonrpc::JsonRpcProtocol;

use crate::connection;
use crate::framing::DEFAULT_LIMIT;
use crate::peer::{self, Peer, Transport};

/// Listen on an AF_UNIX socket. `mode` is applied to the socket file after bind (`None`
/// leaves the umask default). The path must not already exist (the caller manages stale
/// sockets — binding an existing path errors, mirroring `asyncio.start_unix_server`).
pub struct UnixConfig {
    /// Filesystem path to bind.
    pub path: PathBuf,
    /// Permission bits to `chmod` the socket file to after bind (default `0o660`).
    pub mode: Option<u32>,
}

impl UnixConfig {
    /// An AF_UNIX config for `path`, defaulting the socket mode to `0o660` (owner+group rw).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        UnixConfig { path: path.into(), mode: Some(0o660) }
    }

    /// Override the post-bind socket file mode (`None` leaves the umask default).
    #[must_use]
    pub fn mode(mut self, mode: Option<u32>) -> Self {
        self.mode = mode;
        self
    }
}

/// Maps a connecting [`Peer`] to the per-connection session server state.
type StateFn<S> = Box<dyn Fn(&Peer) -> Option<S> + Send + Sync>;

/// Shared, immutable server state behind an `Arc`, read by every connection task.
pub(crate) struct ServerShared<S> {
    pub(crate) protocols: HashMap<String, Arc<JsonRpcProtocol<S>>>,
    pub(crate) name: Option<String>,
    pub(crate) state_fn: StateFn<S>,
    pub(crate) limit: usize,
}

impl<S> ServerShared<S> {
    /// The offered protocol names, sorted (for a stable `$/negotiate` `available` list).
    pub(crate) fn protocol_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.protocols.keys().cloned().collect();
        names.sort();
        names
    }
}

/// Builds a [`JsonRpcServer`]: register one or more named protocols, optionally map the
/// connecting [`Peer`] to the session's server state, and set the inbound message limit.
pub struct JsonRpcServerBuilder<S> {
    protocols: HashMap<String, Arc<JsonRpcProtocol<S>>>,
    name: Option<String>,
    state_fn: Option<StateFn<S>>,
    limit: usize,
}

impl<S: Send + Sync + 'static> JsonRpcServerBuilder<S> {
    /// Register a named protocol (the `$/negotiate` discriminator). Re-registering a name
    /// replaces it.
    #[must_use]
    pub fn protocol(mut self, name: impl Into<String>, protocol: JsonRpcProtocol<S>) -> Self {
        self.protocols.insert(name.into(), Arc::new(protocol));
        self
    }

    /// Map the connecting [`Peer`] (transport, `SO_PEERCRED`, address) to the per-connection
    /// session server state. Without this, sessions are created with no server state (`None`).
    #[must_use]
    pub fn state_from_peer(
        mut self,
        f: impl Fn(&Peer) -> Option<S> + Send + Sync + 'static,
    ) -> Self {
        self.state_fn = Some(Box::new(f));
        self
    }

    /// Override the maximum inbound message size (default [`DEFAULT_LIMIT`], 4 MiB).
    #[must_use]
    pub fn message_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Finish building the server.
    #[must_use]
    pub fn build(self) -> JsonRpcServer<S> {
        JsonRpcServer {
            shared: Arc::new(ServerShared {
                protocols: self.protocols,
                name: self.name,
                state_fn: self.state_fn.unwrap_or_else(|| Box::new(|_| None)),
                limit: self.limit,
            }),
        }
    }
}

/// A runnable server. Cheap to clone (an `Arc` handle), so a clone can be moved into each
/// transport's accept task.
pub struct JsonRpcServer<S> {
    shared: Arc<ServerShared<S>>,
}

impl<S> Clone for JsonRpcServer<S> {
    fn clone(&self) -> Self {
        JsonRpcServer { shared: self.shared.clone() }
    }
}

impl<S: Send + Sync + 'static> JsonRpcServer<S> {
    /// Begin building a server identified by `name` (reported in `$/negotiate`).
    pub fn builder(name: impl Into<String>) -> JsonRpcServerBuilder<S> {
        JsonRpcServerBuilder {
            protocols: HashMap::new(),
            name: Some(name.into()),
            state_fn: None,
            limit: DEFAULT_LIMIT,
        }
    }

    /// Bind an AF_UNIX socket (and `chmod` it per the config), returning the listener without
    /// accepting yet — so a caller can bind before signalling readiness, then
    /// [`serve_unix_listener`](Self::serve_unix_listener). The path must not already exist.
    pub fn bind_unix(config: &UnixConfig) -> std::io::Result<UnixListener> {
        let listener = UnixListener::bind(&config.path)?;
        if let Some(mode) = config.mode {
            std::fs::set_permissions(&config.path, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(listener)
    }

    /// Accept connections on a bound AF_UNIX `listener` until an accept error occurs. Each
    /// connection carries the peer's `SO_PEERCRED`.
    pub async fn serve_unix_listener(&self, listener: UnixListener) -> std::io::Result<()> {
        loop {
            let (stream, _addr) = listener.accept().await?;
            let peer = Peer {
                transport: Transport::Unix,
                ucred: peer::peer_cred(stream.as_raw_fd()),
                addr: None,
            };
            tokio::spawn(connection::serve(stream, peer, self.shared.clone()));
        }
    }

    /// Bind and serve an AF_UNIX socket (bind + accept loop). Runs forever on the happy path —
    /// spawn it (or `tokio::join!` several transports) to run alongside other work.
    pub async fn serve_unix(&self, config: UnixConfig) -> std::io::Result<()> {
        let listener = Self::bind_unix(&config)?;
        self.serve_unix_listener(listener).await
    }

    /// Accept connections on a TCP `addr` (length-prefixed JSON framing) until an accept error
    /// occurs. Runs forever on the happy path — spawn it to run alongside other work.
    pub async fn serve_tcp(&self, addr: impl ToSocketAddrs) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let _ = stream.set_nodelay(true);
            let peer =
                Peer { transport: Transport::Tcp, ucred: None, addr: Some(peer_addr) };
            tokio::spawn(connection::serve(stream, peer, self.shared.clone()));
        }
    }

    /// The local address a bound TCP listener ended up on — convenience for binding port 0 in
    /// tests, then connecting. Binds, returns the address, and yields the listener for serving.
    pub async fn bind_tcp(addr: impl ToSocketAddrs) -> std::io::Result<(TcpListener, std::net::SocketAddr)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        Ok((listener, local))
    }

    /// Serve a TCP listener already obtained from [`bind_tcp`](Self::bind_tcp).
    pub async fn serve_tcp_listener(&self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let _ = stream.set_nodelay(true);
            let peer =
                Peer { transport: Transport::Tcp, ucred: None, addr: Some(peer_addr) };
            tokio::spawn(connection::serve(stream, peer, self.shared.clone()));
        }
    }
}
