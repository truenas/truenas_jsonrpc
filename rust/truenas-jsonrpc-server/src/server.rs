//! [`JsonRpcServer`] — binds one or more transports, selects a named protocol per connection
//! with `$/negotiate`, and serves the dispatch loop. Port of `server.py` (the notification
//! routing is push-based via each session's [`Outbound`](truenas_jsonrpc::Outbound), so the
//! per-protocol drain threads Python needs don't exist here).

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use http::HeaderMap;
use tokio::net::{TcpListener, ToSocketAddrs, UnixListener};
use truenas_jsonrpc::JsonRpcProtocol;

use crate::connection;
use crate::framing::DEFAULT_LIMIT;
use crate::peer::{self, ForwardedOrigin, Peer, UnixTrust};

/// Listen on an AF_UNIX socket. `mode` is applied to the socket file after bind (`None`
/// leaves the umask default). The path must not already exist (the caller manages stale
/// sockets — binding an existing path errors, mirroring `asyncio.start_unix_server`).
pub struct UnixConfig {
    /// Filesystem path to bind.
    pub path: PathBuf,
    /// Permission bits to `chmod` the socket file to after bind (default `0o660`).
    pub mode: Option<u32>,
    /// The listener's trust posture (default [`UnixTrust::Local`] — peer-cred is the caller). Set
    /// [`UnixTrust::Proxied`] when a reverse proxy forwards remote clients over this socket.
    pub trust: UnixTrust,
}

impl UnixConfig {
    /// An AF_UNIX config for `path`, defaulting the socket mode to `0o660` (owner+group rw) and the
    /// trust to [`UnixTrust::Local`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        UnixConfig { path: path.into(), mode: Some(0o660), trust: UnixTrust::Local }
    }

    /// Override the post-bind socket file mode (`None` leaves the umask default).
    #[must_use]
    pub fn mode(mut self, mode: Option<u32>) -> Self {
        self.mode = mode;
        self
    }

    /// Declare the listener's trust posture (e.g. [`UnixTrust::Proxied`] for a reverse-proxied
    /// socket where `SO_PEERCRED` is the proxy, not the end client).
    #[must_use]
    pub fn trust(mut self, trust: UnixTrust) -> Self {
        self.trust = trust;
        self
    }
}

/// Maps a connecting [`Peer`] to the per-connection session server state.
type StateFn<S> = Box<dyn Fn(&Peer) -> Option<S> + Send + Sync>;

/// A user-supplied parser of a reverse proxy's forwarded request metadata (the WebSocket upgrade
/// headers) into the real client [`ForwardedOrigin`]. Run only on a `Proxied` listener.
type ForwardedFn = Arc<dyn Fn(&Peer, &HeaderMap) -> Option<ForwardedOrigin> + Send + Sync>;

/// Shared, immutable server state behind an `Arc`, read by every connection task.
pub(crate) struct ServerShared<S> {
    pub(crate) protocols: HashMap<String, Arc<JsonRpcProtocol<S>>>,
    pub(crate) name: Option<String>,
    pub(crate) state_fn: StateFn<S>,
    pub(crate) limit: usize,
    pub(crate) allow_unauthenticated: bool,
    /// User-supplied forwarded-origin parser; only read by the WebSocket accept path.
    #[cfg_attr(not(feature = "websocket"), allow(dead_code))]
    pub(crate) forwarded_extractor: Option<ForwardedFn>,
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
    allow_unauthenticated: bool,
    forwarded_extractor: Option<ForwardedFn>,
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

    /// Allow serving protocols that have **no** `$/sessionSetup` over a **network** transport
    /// (TCP / TLS / WebSocket). By default that is refused at serve time, because an
    /// unauthenticated remote client could otherwise reach gated methods — mirroring
    /// `server.py`, which raises when a network transport exposes an unauthenticated protocol.
    /// AF_UNIX is always exempt (local peer-credential / filesystem trust). Opt in only when a
    /// protocol is deliberately unauthenticated or authenticates by another means.
    #[must_use]
    pub fn allow_unauthenticated_network(mut self) -> Self {
        self.allow_unauthenticated = true;
        self
    }

    /// Set a parser that recovers the real client [`ForwardedOrigin`] from a reverse proxy's
    /// forwarded request metadata — the WebSocket upgrade headers — on a `Proxied` listener. The
    /// closure receives the immediate [`Peer`] (e.g. the proxy's `SO_PEERCRED`) and the upgrade
    /// [`HeaderMap`]; it returns the parsed real client, or `None` to leave the origin as the
    /// immediate peer. [`ForwardedOrigin::from_real_remote_headers`] is the drop-in for the standard
    /// nginx setup. **Honored only on a `Proxied` listener** (trust is the listener's posture +
    /// socket permissions) — never on a trusted-local or direct connection, where a client could
    /// forge the headers.
    #[must_use]
    pub fn forwarded_extractor(
        mut self,
        f: impl Fn(&Peer, &HeaderMap) -> Option<ForwardedOrigin> + Send + Sync + 'static,
    ) -> Self {
        self.forwarded_extractor = Some(Arc::new(f));
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
                allow_unauthenticated: self.allow_unauthenticated,
                forwarded_extractor: self.forwarded_extractor,
            }),
        }
    }
}

/// A runnable server. Cheap to clone (an `Arc` handle), so a clone can be moved into each
/// transport's accept task.
pub struct JsonRpcServer<S> {
    pub(crate) shared: Arc<ServerShared<S>>,
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
            allow_unauthenticated: false,
            forwarded_extractor: None,
        }
    }

    /// Guard for the network transports (TCP / TLS / WebSocket): refuse to serve if any
    /// registered protocol has no `$/sessionSetup` (so an unauthenticated remote client can't
    /// reach gated methods), unless the server opted in via
    /// [`allow_unauthenticated_network`](JsonRpcServerBuilder::allow_unauthenticated_network).
    /// AF_UNIX is exempt and never calls this. Mirrors `server.py`'s constructor check, but at
    /// serve time — the transport is chosen per `serve_*` call, not at build.
    pub(crate) fn require_network_auth(&self) -> std::io::Result<()> {
        if self.shared.allow_unauthenticated {
            return Ok(());
        }
        let mut unauth: Vec<&str> = self
            .shared
            .protocols
            .iter()
            .filter(|(_, p)| !p.has_session_setup())
            .map(|(name, _)| name.as_str())
            .collect();
        if unauth.is_empty() {
            return Ok(());
        }
        unauth.sort_unstable();
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to serve protocol(s) with no $/sessionSetup over a network transport: \
                 [{}] — register session setup, serve only over AF_UNIX, or opt in with \
                 .allow_unauthenticated_network()",
                unauth.join(", ")
            ),
        ))
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
    /// connection carries the peer's `SO_PEERCRED` and the listener's declared `trust` posture
    /// ([`UnixTrust::Local`] for a genuinely-local socket; [`UnixTrust::Proxied`] when a reverse
    /// proxy forwards remote clients here, so `SO_PEERCRED` is the proxy's and must not be trusted).
    pub async fn serve_unix_listener(
        &self,
        listener: UnixListener,
        trust: UnixTrust,
    ) -> std::io::Result<()> {
        // A proxied AF_UNIX listener is network-facing (a reverse proxy forwards remote clients in),
        // so — like a TCP/TLS listener — every protocol must authenticate (peer-cred is the proxy's).
        if trust == UnixTrust::Proxied {
            self.require_network_auth()?;
        }
        loop {
            let (stream, _addr) = listener.accept().await?;
            let fd = stream.as_raw_fd();
            let peer = Peer::unix(peer::peer_cred(fd)).with_posture(trust.into());
            tokio::spawn(connection::serve(stream, Some(fd), peer, self.shared.clone()));
        }
    }

    /// Bind and serve an AF_UNIX socket (bind + accept loop), with the config's [`trust`](UnixConfig::trust)
    /// posture. Runs forever on the happy path — spawn it (or `tokio::join!` several transports).
    pub async fn serve_unix(&self, config: UnixConfig) -> std::io::Result<()> {
        let trust = config.trust;
        let listener = Self::bind_unix(&config)?;
        self.serve_unix_listener(listener, trust).await
    }

    /// Bind and serve a TCP `addr` (length-prefixed JSON framing). Refuses (before binding) if a
    /// registered protocol has no `$/sessionSetup` unless opted in (see
    /// [`require_network_auth`](Self::require_network_auth)). Runs forever on the happy path.
    pub async fn serve_tcp(&self, addr: impl ToSocketAddrs) -> std::io::Result<()> {
        self.require_network_auth()?;
        let listener = TcpListener::bind(addr).await?;
        self.serve_tcp_listener(listener).await
    }

    /// The local address a bound TCP listener ended up on — convenience for binding port 0 in
    /// tests, then connecting. Binds, returns the address, and yields the listener for serving.
    pub async fn bind_tcp(addr: impl ToSocketAddrs) -> std::io::Result<(TcpListener, std::net::SocketAddr)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        Ok((listener, local))
    }

    /// Serve a TCP listener already obtained from [`bind_tcp`](Self::bind_tcp). Refuses an
    /// unauthenticated protocol over the network (see [`require_network_auth`](Self::require_network_auth)).
    pub async fn serve_tcp_listener(&self, listener: TcpListener) -> std::io::Result<()> {
        self.require_network_auth()?;
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let _ = stream.set_nodelay(true);
            let fd = stream.as_raw_fd();
            let peer = Peer::tcp(peer_addr);
            tokio::spawn(connection::serve(stream, Some(fd), peer, self.shared.clone()));
        }
    }
}
