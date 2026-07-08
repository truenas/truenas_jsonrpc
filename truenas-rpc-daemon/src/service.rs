//! [`Service`] — a [`TruenasRpcServer`] plus the transports it is served on, with the server's
//! session type `S` and wire type `W` **erased** so a `Vec<Service>` can hold heterogeneous servers
//! and [`Daemon`](crate::Daemon) stays generic only over the config type.
//!
//! Build one with [`Service::new`] (the default [`JsonRpc`] wire) or [`Service::with_wire`], add
//! transports, then [`ServiceBuilder::build`]. Erasure happens at `.build()`-time boxing: each
//! transport becomes an async *bind* step (run before readiness) that yields a *serve* step (run
//! until shutdown). The transport methods keep the server crate's compile-time guarantee —
//! [`listen_tcp`](ServiceBuilder::listen_tcp) and
//! [`listen_unix_proxied`](ServiceBuilder::listen_unix_proxied) require `W: NetworkWire<S>`, so a
//! non-network wire (e.g. ONC RPC) over a network transport does not compile.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::watch;
use truenas_rpc_server::{JsonRpc, NetworkWire, TruenasRpcServer, UnixConfig, Wire};

use crate::error::DaemonError;

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Serve a bound transport until the `shutdown` receiver flips to `true`. Erased (S/W gone).
pub(crate) type ServeFn =
    Box<dyn FnOnce(watch::Receiver<bool>) -> BoxFut<Result<(), DaemonError>> + Send>;

/// Bind one transport now (before readiness); on success yields its [`ServeFn`]. Erased (S/W gone).
type BindFn = Box<dyn FnOnce() -> BoxFut<Result<ServeFn, DaemonError>> + Send>;

/// Produces a fresh wire value per transport (the server's `serve_*` methods consume the wire, and
/// `JsonRpc` is not `Clone`, so a factory rather than a stored value).
type WireFactory<W> = Arc<dyn Fn() -> W + Send + Sync>;

/// One transport of one service: a human label plus its erased bind step.
pub(crate) struct Transport {
    pub(crate) label: String,
    pub(crate) bind: BindFn,
}

/// A server and its transports, with session/wire types erased. Produced by
/// [`ServiceBuilder::build`] and registered via [`DaemonBuilder::services`](crate::DaemonBuilder).
pub struct Service {
    transports: Vec<Transport>,
}

impl Service {
    /// Begin a service serving `server` over the default [`JsonRpc`] wire. Add transports, then
    /// [`build`](ServiceBuilder::build).
    pub fn builder<S>(server: TruenasRpcServer<S>) -> ServiceBuilder<S, JsonRpc>
    where
        S: Send + Sync + 'static,
    {
        ServiceBuilder {
            server,
            wire: Arc::new(|| JsonRpc),
            transports: Vec::new(),
        }
    }

    /// Begin a service serving `server` over a custom `wire` (e.g. ONC RPC). The wire must be
    /// `Clone` so a fresh value can be produced for each transport.
    pub fn with_wire<S, W>(server: TruenasRpcServer<S>, wire: W) -> ServiceBuilder<S, W>
    where
        S: Send + Sync + 'static,
        W: Wire<S> + Clone + Send + Sync + 'static,
    {
        ServiceBuilder {
            server,
            wire: Arc::new(move || wire.clone()),
            transports: Vec::new(),
        }
    }

    /// The erased transports, for the daemon to bind then serve.
    pub(crate) fn into_transports(self) -> Vec<Transport> {
        self.transports
    }
}

/// Builder for a [`Service`]: accumulate transports for one `server`/`wire`, then
/// [`build`](Self::build). Each transport is erased into the builder at the call site (where the
/// wire's `Wire`/`NetworkWire` bound is known), so `build` needs no bounds and the network-safety
/// check is enforced by the type system.
pub struct ServiceBuilder<S, W = JsonRpc> {
    server: TruenasRpcServer<S>,
    wire: WireFactory<W>,
    transports: Vec<Transport>,
}

/// Race the server's (forever) serve future against the shutdown signal.
async fn until_true(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    let _ = rx.wait_for(|v| *v).await;
}

impl<S, W> ServiceBuilder<S, W>
where
    S: Send + Sync + 'static,
    W: Wire<S> + Send + Sync + 'static,
{
    /// Serve on a **trusted-local** AF_UNIX socket at `path` (mode `0o660`). Each connection carries
    /// the peer's `SO_PEERCRED`; trusted-local AF_UNIX is exempt from the network-auth guard.
    #[must_use]
    pub fn listen_unix(self, path: impl Into<PathBuf>) -> Self {
        self.listen_unix_config(UnixConfig::new(path))
    }

    /// Serve on a **trusted-local** AF_UNIX socket described by `cfg` (custom socket mode).
    #[must_use]
    pub fn listen_unix_config(mut self, cfg: UnixConfig) -> Self {
        let label = format!("unix:{}", cfg.path.display());
        let server = self.server.clone();
        let wire = self.wire.clone();
        let lbl = label.clone();
        let bind: BindFn = Box::new(move || {
            Box::pin(async move {
                let listener = TruenasRpcServer::<S>::bind_unix(&cfg)
                    .map_err(|e| DaemonError::Bind(lbl.clone(), e))?;
                let serve: ServeFn = Box::new(move |mut shutdown| {
                    Box::pin(async move {
                        let w = (wire)();
                        tokio::select! {
                            r = server.serve_unix_listener(listener, w) => r.map_err(DaemonError::from),
                            _ = until_true(&mut shutdown) => Ok(()),
                        }
                    })
                });
                Ok(serve)
            })
        });
        self.transports.push(Transport { label, bind });
        self
    }

    /// Finish building the [`Service`], erasing the session and wire types.
    #[must_use]
    pub fn build(self) -> Service {
        Service {
            transports: self.transports,
        }
    }
}

impl<S, W> ServiceBuilder<S, W>
where
    S: Send + Sync + 'static,
    W: NetworkWire<S> + Send + Sync + 'static,
{
    /// Serve on a **reverse-proxied** AF_UNIX socket at `path` (mode `0o660`): `SO_PEERCRED` is the
    /// proxy's and is not trusted, so the wire's network-auth guard runs. Requires `W: NetworkWire`.
    #[must_use]
    pub fn listen_unix_proxied(self, path: impl Into<PathBuf>) -> Self {
        self.listen_unix_proxied_config(UnixConfig::new(path))
    }

    /// Serve on a **reverse-proxied** AF_UNIX socket described by `cfg`. Requires `W: NetworkWire`.
    #[must_use]
    pub fn listen_unix_proxied_config(mut self, cfg: UnixConfig) -> Self {
        let label = format!("unix-proxied:{}", cfg.path.display());
        let server = self.server.clone();
        let wire = self.wire.clone();
        let lbl = label.clone();
        let bind: BindFn = Box::new(move || {
            Box::pin(async move {
                let listener = TruenasRpcServer::<S>::bind_unix(&cfg)
                    .map_err(|e| DaemonError::Bind(lbl.clone(), e))?;
                let serve: ServeFn = Box::new(move |mut shutdown| {
                    Box::pin(async move {
                        let w = (wire)();
                        tokio::select! {
                            r = server.serve_proxied_unix_listener(listener, w) => r.map_err(DaemonError::from),
                            _ = until_true(&mut shutdown) => Ok(()),
                        }
                    })
                });
                Ok(serve)
            })
        });
        self.transports.push(Transport { label, bind });
        self
    }

    /// Serve on a TCP socket at `addr`. The wire's network-auth guard runs at serve start. Requires
    /// `W: NetworkWire` — a non-network wire over TCP is a compile error, by design.
    #[must_use]
    pub fn listen_tcp(mut self, addr: impl Into<SocketAddr>) -> Self {
        let addr = addr.into();
        let label = format!("tcp:{addr}");
        let server = self.server.clone();
        let wire = self.wire.clone();
        let lbl = label.clone();
        let bind: BindFn = Box::new(move || {
            Box::pin(async move {
                let (listener, _local) = TruenasRpcServer::<S>::bind_tcp(addr)
                    .await
                    .map_err(|e| DaemonError::Bind(lbl.clone(), e))?;
                let serve: ServeFn = Box::new(move |mut shutdown| {
                    Box::pin(async move {
                        let w = (wire)();
                        tokio::select! {
                            r = server.serve_tcp_listener(listener, w) => r.map_err(DaemonError::from),
                            _ = until_true(&mut shutdown) => Ok(()),
                        }
                    })
                });
                Ok(serve)
            })
        });
        self.transports.push(Transport { label, bind });
        self
    }
}
