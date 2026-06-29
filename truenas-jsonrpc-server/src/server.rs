//! [`JsonRpcServer`] — the **Transport** layer (layer 1) entry point: binds one or more transports,
//! selects a named protocol per connection with `$/negotiate`, and serves the dispatch loop. The
//! notification routing is push-based via each session's [`Outbound`](truenas_jsonrpc::Outbound), so
//! there are no per-protocol drain threads.

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "websocket")]
use http::HeaderMap;
use tokio::net::{TcpListener, ToSocketAddrs, UnixListener};
use truenas_jsonrpc::JsonRpcProtocol;

use crate::engine::{ConnContext, JsonRpcEngine, ProtocolEngine};
use crate::framing::DEFAULT_LIMIT;
use crate::oncrpc::{OncRpcEngine, DEFAULT_PROGRAM, DEFAULT_VERSION};
use crate::peer::{self, Peer, UnixTrust};
#[cfg(feature = "websocket")]
use crate::peer::ForwardedOrigin;

/// Listen on an AF_UNIX socket. `mode` is applied to the socket file after bind (`None`
/// leaves the umask default). The path must not already exist (the caller manages stale
/// sockets — binding an existing path errors).
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

/// How to serve a registered protocol over the ONC RPC wire (see
/// [`serve_oncrpc_unix_listener`](JsonRpcServer::serve_oncrpc_unix_listener)): which protocol's
/// methods to serve, and the ONC RPC program number + version they answer to. [`new`](Self::new)
/// defaults the program/version to the reference engine's (`0x2000_0001` / `1`); override with
/// [`program`](Self::program) / [`version`](Self::version).
pub struct OncRpcConfig {
    /// The registered protocol whose methods are served — each method's XDR proc-id is its procedure.
    pub protocol: String,
    /// The ONC RPC program number this listener answers to.
    pub program: u32,
    /// The ONC RPC program version.
    pub version: u32,
}

impl OncRpcConfig {
    /// Serve the registered protocol `protocol`, defaulting the ONC RPC program/version to the
    /// reference engine's.
    pub fn new(protocol: impl Into<String>) -> Self {
        OncRpcConfig { protocol: protocol.into(), program: DEFAULT_PROGRAM, version: DEFAULT_VERSION }
    }

    /// Set the ONC RPC program number (e.g. in RFC 5531's user range `0x2000_0000..=0x3FFF_FFFF`).
    #[must_use]
    pub fn program(mut self, program: u32) -> Self {
        self.program = program;
        self
    }

    /// Set the ONC RPC program version.
    #[must_use]
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }
}

/// Maps a connecting [`Peer`] to the per-connection session server state.
type StateFn<S> = Box<dyn Fn(&Peer) -> Option<S> + Send + Sync>;

/// A user-supplied parser of a reverse proxy's forwarded request metadata (the WebSocket upgrade
/// headers) into the real client [`ForwardedOrigin`]. Run only on a `Proxied` listener. WebSocket-only
/// (it takes the upgrade `HeaderMap`), so it's gated with the rest of the forwarded-extractor seam.
#[cfg(feature = "websocket")]
type ForwardedFn = Arc<dyn Fn(&Peer, &HeaderMap) -> Option<ForwardedOrigin> + Send + Sync>;

/// Shared, immutable server state behind an `Arc`, read by every connection task.
pub(crate) struct ServerShared<S> {
    pub(crate) protocols: HashMap<String, Arc<JsonRpcProtocol<S>>>,
    pub(crate) name: Option<String>,
    pub(crate) state_fn: StateFn<S>,
    pub(crate) limit: usize,
    pub(crate) allow_unauthenticated: bool,
    /// User-supplied forwarded-origin parser; only meaningful on the WebSocket accept path, so it
    /// exists only with the `websocket` feature.
    #[cfg(feature = "websocket")]
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
    #[cfg(feature = "websocket")]
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
    /// unauthenticated remote client could otherwise reach gated methods. AF_UNIX is always
    /// exempt (local peer-credential / filesystem trust). Opt in only when a
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
    /// forge the headers. Requires the `websocket` feature (it parses the upgrade headers).
    #[cfg(feature = "websocket")]
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
                #[cfg(feature = "websocket")]
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
            #[cfg(feature = "websocket")]
            forwarded_extractor: None,
        }
    }

    /// Guard for the network transports (TCP / TLS / WebSocket): refuse to serve if any
    /// registered protocol has no `$/sessionSetup` (so an unauthenticated remote client can't
    /// reach gated methods), unless the server opted in via
    /// [`allow_unauthenticated_network`](JsonRpcServerBuilder::allow_unauthenticated_network).
    /// AF_UNIX is exempt and never calls this. This runs at serve time — the transport is chosen
    /// per `serve_*` call, not at build.
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
        let engine: Arc<dyn ProtocolEngine> = Arc::new(JsonRpcEngine::new(self.shared.clone()));
        self.accept_unix(listener, trust, engine).await
    }

    /// Like [`serve_unix_listener`](Self::serve_unix_listener), but serves a caller-supplied
    /// [`ProtocolEngine`] in place of JSON-RPC — the per-listener extension point. The engine owns
    /// its own authentication, so the JSON-RPC network-auth guard is not applied here; scope the
    /// listener's exposure to match the engine's auth model.
    pub async fn serve_unix_listener_with(
        &self,
        listener: UnixListener,
        trust: UnixTrust,
        engine: Arc<dyn ProtocolEngine>,
    ) -> std::io::Result<()> {
        self.accept_unix(listener, trust, engine).await
    }

    /// The shared AF_UNIX accept loop: each accepted connection becomes a [`ConnContext`] handed to
    /// `engine`, which owns it for the rest of its life.
    async fn accept_unix(
        &self,
        listener: UnixListener,
        trust: UnixTrust,
        engine: Arc<dyn ProtocolEngine>,
    ) -> std::io::Result<()> {
        loop {
            let (stream, _addr) = listener.accept().await?;
            let fd = stream.as_raw_fd();
            let peer = Peer::unix(peer::peer_cred(fd)).with_posture(trust.into());
            let ctx = ConnContext {
                stream: Box::new(stream),
                transfer_fd: Some(fd),
                peer,
                limit: self.shared.limit,
            };
            let engine = engine.clone();
            tokio::spawn(async move {
                engine.serve(ctx).await;
            });
        }
    }

    /// Bind and serve an AF_UNIX socket (bind + accept loop), with the config's [`trust`](UnixConfig::trust)
    /// posture. Runs forever on the happy path — spawn it (or `tokio::join!` several transports).
    pub async fn serve_unix(&self, config: UnixConfig) -> std::io::Result<()> {
        let trust = config.trust;
        let listener = Self::bind_unix(&config)?;
        self.serve_unix_listener(listener, trust).await
    }

    /// Accept ONC RPC connections (RFC 5531, record-marking framed) on a bound AF_UNIX `listener`,
    /// serving the methods of `config`'s registered protocol over the binary wire under its ONC RPC
    /// program/version — each method's XDR proc-id is its procedure number. So a method registered
    /// once is reachable over *both* the JSON-RPC transports and this one (one service, two wires),
    /// chosen per listener. The demo authenticates with `AUTH_NONE`/`AUTH_SYS`, so it is offered only
    /// over AF_UNIX (local peer-credential trust), never a network transport. Errors before serving if
    /// the named protocol is not registered. Runs forever on the happy path.
    pub async fn serve_oncrpc_unix_listener(
        &self,
        listener: UnixListener,
        config: OncRpcConfig,
    ) -> std::io::Result<()> {
        let proto = self.shared.protocols.get(&config.protocol).cloned().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "serve_oncrpc_unix_listener: no protocol named '{}' is registered",
                    config.protocol
                ),
            )
        })?;
        let engine = OncRpcEngine::new(proto.service().clone(), config.program, config.version);
        self.serve_unix_listener_with(listener, UnixTrust::Local, Arc::new(engine)).await
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
        let engine: Arc<dyn ProtocolEngine> = Arc::new(JsonRpcEngine::new(self.shared.clone()));
        self.accept_tcp(listener, engine).await
    }

    /// Like [`serve_tcp_listener`](Self::serve_tcp_listener), but serves a caller-supplied
    /// [`ProtocolEngine`] in place of JSON-RPC — the per-listener extension point. The engine owns
    /// its own authentication (the JSON-RPC network-auth guard is not applied).
    pub async fn serve_tcp_listener_with(
        &self,
        listener: TcpListener,
        engine: Arc<dyn ProtocolEngine>,
    ) -> std::io::Result<()> {
        self.accept_tcp(listener, engine).await
    }

    /// The shared TCP accept loop: each accepted connection becomes a [`ConnContext`] handed to
    /// `engine`, which owns it for the rest of its life.
    async fn accept_tcp(
        &self,
        listener: TcpListener,
        engine: Arc<dyn ProtocolEngine>,
    ) -> std::io::Result<()> {
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let _ = stream.set_nodelay(true);
            let fd = stream.as_raw_fd();
            let peer = Peer::tcp(peer_addr);
            let ctx = ConnContext {
                stream: Box::new(stream),
                transfer_fd: Some(fd),
                peer,
                limit: self.shared.limit,
            };
            let engine = engine.clone();
            tokio::spawn(async move {
                engine.serve(ctx).await;
            });
        }
    }
}
