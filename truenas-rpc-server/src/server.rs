//! [`TruenasRpcServer`] — the **Transport** layer (layer 1) entry point: binds one or more transports,
//! selects a named protocol per connection with `$/negotiate`, and serves the dispatch loop. The
//! notification routing is push-based via each session's [`Outbound`](truenas_rpc::Outbound), so
//! there are no per-protocol drain threads.

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "websocket")]
use http::HeaderMap;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::net::{TcpListener, ToSocketAddrs, UnixListener};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, SessionId};

use crate::engine::{ConnContext, ProtocolEngine};
use crate::framing::DEFAULT_LIMIT;
#[cfg(feature = "websocket")]
use crate::peer::ForwardedOrigin;
use crate::peer::{self, Peer, UnixTrust};
use crate::wire::{NetworkWire, Wire, WireHost};

/// Listen on an AF_UNIX socket. `mode` is applied to the socket file after bind (`None`
/// leaves the umask default). The path must not already exist (the caller manages stale
/// sockets — binding an existing path errors). The trust posture is the `serve_*` method's concern:
/// [`serve_unix_listener`](TruenasRpcServer::serve_unix_listener) is trusted-local,
/// [`serve_proxied_unix_listener`](TruenasRpcServer::serve_proxied_unix_listener) is reverse-proxied.
pub struct UnixConfig {
    /// Filesystem path to bind.
    pub path: PathBuf,
    /// Permission bits to `chmod` the socket file to after bind (default `0o660`).
    pub mode: Option<u32>,
}

impl UnixConfig {
    /// An AF_UNIX config for `path`, defaulting the socket mode to `0o660` (owner+group rw).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        UnixConfig {
            path: path.into(),
            mode: Some(0o660),
        }
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

    /// The network-auth guard, the one source of truth: refuse to serve if any registered protocol
    /// has no `$/sessionSetup` (so an unauthenticated remote client can't reach gated methods),
    /// unless the server opted in via
    /// [`allow_unauthenticated_network`](TruenasRpcServerBuilder::allow_unauthenticated_network).
    /// AF_UNIX (trusted-local) is exempt. Run at serve time by every network-facing transport —
    /// the byte-stream wires via [`NetworkWire::admit_network`](crate::NetworkWire::admit_network),
    /// the WebSocket transport directly.
    pub(crate) fn require_session_auth(&self) -> std::io::Result<()>
    where
        S: Send + Sync + 'static,
    {
        if self.allow_unauthenticated {
            return Ok(());
        }
        let mut unauth: Vec<&str> = self
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
}

/// Builds a [`TruenasRpcServer`]: register one or more named protocols, optionally map the
/// connecting [`Peer`] to the session's server state, and set the inbound message limit.
pub struct TruenasRpcServerBuilder<S> {
    protocols: HashMap<String, Arc<JsonRpcProtocol<S>>>,
    name: Option<String>,
    state_fn: Option<StateFn<S>>,
    limit: usize,
    allow_unauthenticated: bool,
    #[cfg(feature = "websocket")]
    forwarded_extractor: Option<ForwardedFn>,
}

impl<S: Send + Sync + 'static> TruenasRpcServerBuilder<S> {
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
    pub fn build(self) -> TruenasRpcServer<S> {
        TruenasRpcServer {
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
pub struct TruenasRpcServer<S> {
    pub(crate) shared: Arc<ServerShared<S>>,
}

impl<S> Clone for TruenasRpcServer<S> {
    fn clone(&self) -> Self {
        TruenasRpcServer {
            shared: self.shared.clone(),
        }
    }
}

impl<S: Send + Sync + 'static> TruenasRpcServer<S> {
    /// Begin building a server identified by `name` (reported in `$/negotiate`).
    pub fn builder(name: impl Into<String>) -> TruenasRpcServerBuilder<S> {
        TruenasRpcServerBuilder {
            protocols: HashMap::new(),
            name: Some(name.into()),
            state_fn: None,
            limit: DEFAULT_LIMIT,
            allow_unauthenticated: false,
            #[cfg(feature = "websocket")]
            forwarded_extractor: None,
        }
    }

    /// The [`WireHost`] view handed to a [`Wire`] when resolving it to its engine — wraps the
    /// crate-private substrate so it never crosses the public seam.
    pub(crate) fn host(&self) -> WireHost<'_, S> {
        WireHost::new(&self.shared)
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

    /// Serve a `wire` (e.g. [`JsonRpc`](crate::JsonRpc) or [`OncRpc`](crate::OncRpc)) on a bound,
    /// **trusted-local** AF_UNIX `listener`: each connection carries the peer's `SO_PEERCRED`
    /// ([`UnixTrust::Local`]). Trusted-local AF_UNIX is exempt from the network-auth guard. For a
    /// reverse-proxied socket use [`serve_proxied_unix_listener`](Self::serve_proxied_unix_listener).
    pub async fn serve_unix_listener<W: Wire<S>>(
        &self,
        listener: UnixListener,
        wire: W,
    ) -> std::io::Result<()> {
        let engine = wire.into_engine(self.host())?;
        self.accept_unix(listener, UnixTrust::Local, engine).await
    }

    /// Serve a network-facing `wire` on a **reverse-proxied** AF_UNIX `listener` — `SO_PEERCRED` is
    /// the proxy's and is not trusted ([`UnixTrust::Proxied`]), so the wire's
    /// [`admit_network`](crate::NetworkWire::admit_network) guard runs (JSON-RPC refuses a protocol
    /// with no `$/sessionSetup`). ONC RPC is not a [`NetworkWire`](crate::NetworkWire), so it cannot
    /// be served here — a compile error, by design.
    pub async fn serve_proxied_unix_listener<W: NetworkWire<S>>(
        &self,
        listener: UnixListener,
        wire: W,
    ) -> std::io::Result<()> {
        wire.admit_network(self.host())?;
        let engine = wire.into_engine(self.host())?;
        self.accept_unix(listener, UnixTrust::Proxied, engine).await
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

    /// Bind and serve a `wire` on a **trusted-local** AF_UNIX socket (bind + accept loop). Runs
    /// forever on the happy path — spawn it (or `tokio::join!` several transports).
    pub async fn serve_unix<W: Wire<S>>(&self, config: UnixConfig, wire: W) -> std::io::Result<()> {
        let listener = Self::bind_unix(&config)?;
        self.serve_unix_listener(listener, wire).await
    }

    /// Bind and serve a network-facing `wire` on a TCP `addr`. The wire's
    /// [`admit_network`](crate::NetworkWire::admit_network) guard runs (JSON-RPC refuses, before
    /// binding, a protocol with no `$/sessionSetup` unless opted in). Runs forever on the happy path.
    pub async fn serve_tcp<W: NetworkWire<S>>(
        &self,
        addr: impl ToSocketAddrs,
        wire: W,
    ) -> std::io::Result<()> {
        wire.admit_network(self.host())?;
        let listener = TcpListener::bind(addr).await?;
        self.serve_tcp_listener(listener, wire).await
    }

    /// The local address a bound TCP listener ended up on — convenience for binding port 0 in
    /// tests, then connecting. Binds, returns the address, and yields the listener for serving.
    pub async fn bind_tcp(
        addr: impl ToSocketAddrs,
    ) -> std::io::Result<(TcpListener, std::net::SocketAddr)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        Ok((listener, local))
    }

    /// Serve a network-facing `wire` on a TCP listener obtained from [`bind_tcp`](Self::bind_tcp).
    /// The wire's [`admit_network`](crate::NetworkWire::admit_network) guard runs (JSON-RPC refuses a
    /// protocol with no `$/sessionSetup`). A pre-built engine can be served via
    /// [`CustomWire`](crate::CustomWire).
    pub async fn serve_tcp_listener<W: NetworkWire<S>>(
        &self,
        listener: TcpListener,
        wire: W,
    ) -> std::io::Result<()> {
        wire.admit_network(self.host())?;
        let engine = wire.into_engine(self.host())?;
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

    /// Publish a notification to every subscriber of `topic` on the named `protocol` — the
    /// embedder's handle for server→client pub/sub. The protocol was moved in at
    /// [`build`](TruenasRpcServerBuilder::build); this reaches the registered instance, so
    /// subscribers on live connections receive the notification over their back-channel. Non-blocking
    /// (drops on a slow subscriber's backpressure, like any notification). Errors if the `protocol`
    /// or `topic` is unknown, or the payload doesn't match the topic's declared notification type.
    pub fn send_notification<T: Serialize>(
        &self,
        protocol: &str,
        topic: &str,
        payload: &T,
    ) -> Result<(), JsonRpcError> {
        match self.shared.protocols.get(protocol) {
            Some(p) => p.send_notification(topic, payload),
            None => Err(JsonRpcError::internal(format!(
                "no protocol named {protocol:?}"
            ))),
        }
    }

    /// Snapshot the live **session → operation tree** as JSON: every negotiated protocol's active
    /// sessions (id, lifecycle, origin, credential, age) and each session's in-flight long-lived
    /// operations — raw-fd transfers, passthrough take-overs, and cancellable requests. Normal
    /// method calls are **not** listed: they complete in microseconds and the dispatch fast path
    /// tracks nothing, so this shows only the handful of genuinely long-running things in flight.
    ///
    /// Reads only shared registries, so it never perturbs the data path. A consumer wires it to
    /// whatever trigger it likes — a signal handler, an admin RPC, an HTTP `/debug` route; see
    /// [`write_operations_dump`](Self::write_operations_dump) for the write-to-a-file form.
    pub fn dump_operations_json(&self) -> Value {
        // The protocol map is unordered — sort by name for a stable dump (sessions within a protocol
        // are already oldest-first). `SessionId::nil()` as the "caller" marks no entry `current`.
        let mut names: Vec<&String> = self.shared.protocols.keys().collect();
        names.sort();
        let sessions: Vec<Value> = names
            .into_iter()
            .filter_map(|n| self.shared.protocols.get(n))
            .flat_map(|p| p.render_sessions(SessionId::nil()))
            .collect();
        json!({
            "server": self.shared.name,
            "dumped_at": unix_now(),
            "session_count": sessions.len(),
            "sessions": sessions,
        })
    }

    /// Write [`dump_operations_json`](Self::dump_operations_json) to `path` as pretty JSON, replacing
    /// it atomically (write-temp-then-rename, so a reader never sees a half-written file). Reads only
    /// shared registries, so it never perturbs the data path.
    ///
    /// **Signal policy is the application's, not the library's.** This crate deliberately does *not*
    /// install a signal handler: a library seizing the process-global `SIGUSR2` disposition (and
    /// spawning a thread for it) would fight the embedding binary. Wire it to whatever trigger you
    /// want — e.g. `SIGUSR2`, entirely in your own code:
    ///
    /// ```ignore
    /// let mut sigusr2 =
    ///     tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
    /// tokio::spawn(async move {
    ///     while sigusr2.recv().await.is_some() {
    ///         let _ = server.write_operations_dump("/run/truenas-rpc/operations.json");
    ///     }
    /// });
    /// ```
    pub fn write_operations_dump(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        let body = serde_json::to_vec_pretty(&self.dump_operations_json())
            .expect("a serde_json::Value always serializes");
        // Write a sibling temp file then rename over the target: rename is atomic on one filesystem,
        // so a concurrent reader (an admin, a tool) never observes a half-written dump.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &body)?;
        std::fs::rename(&tmp, path)
    }
}

/// Seconds since the Unix epoch, for the dump's `dumped_at` (a wall-clock stamp on an otherwise
/// monotonic snapshot).
fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
