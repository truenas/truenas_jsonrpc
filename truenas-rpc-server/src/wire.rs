//! The **`Wire`** seam — the per-listener selector for *which* wire protocol a
//! [`TruenasRpcServer`](crate::TruenasRpcServer) serves on a listener, passed by value to its
//! `serve_*` methods (`serve_unix_listener(l, JsonRpc)`, `serve_unix_listener(l, OncRpc::protocol("x"))`).
//!
//! A wire is resolved to its per-connection [`ProtocolEngine`] **once per listener** (at serve time)
//! via [`Wire::into_engine`]; the engine then owns every connection. The per-connection `dyn` hop is
//! off the request hot path (see `engine.rs`), so the `Wire` generic costs nothing at runtime — it is
//! a typed, monomorphized way to choose the wire, not a per-request indirection.
//!
//! [`WireHost`] is the construction-time analogue of [`ConnContext`](crate::ConnContext): the curated,
//! opaque view a wire gets of the server — never the `ServerShared` substrate (op-tables, negotiate
//! state), which stays crate-private. Built-in wires: [`JsonRpc`] (the default JSON-RPC + TXDR engine)
//! and [`OncRpc`](crate::OncRpc) (RFC 5531). [`CustomWire`] adapts any pre-built engine.
//!
//! A **network-facing** transport (TCP, TLS, reverse-proxied AF_UNIX) requires [`NetworkWire`]; ONC
//! RPC (AUTH_NONE/AUTH_SYS) is AF_UNIX-only, so it is `Wire` but *not* `NetworkWire` — serving it over
//! a network transport is a **compile** error, not a runtime check.

use std::sync::Arc;

use truenas_rpc::Service;

use crate::engine::{JsonRpcEngine, ProtocolEngine};
use crate::server::ServerShared;

/// A wire protocol selected per listener. Resolves the server's registered substrate to the
/// per-connection [`ProtocolEngine`] for one listener. Implemented by [`JsonRpc`],
/// [`OncRpc`](crate::OncRpc), and [`CustomWire`]; implement it for a wire of your own.
pub trait Wire<S> {
    /// Resolve this wire to its per-connection engine over `host`'s registered services. `Err`
    /// ([`InvalidInput`](std::io::ErrorKind::InvalidInput)) if the wire can't be satisfied (e.g. ONC
    /// RPC names an unregistered protocol). Consumes the wire value.
    fn into_engine(self, host: WireHost<'_, S>) -> std::io::Result<Arc<dyn ProtocolEngine>>;
}

/// A [`Wire`] servable over a **network-facing** transport (TCP, TLS, reverse-proxied AF_UNIX). ONC
/// RPC is deliberately *not* a `NetworkWire`, so `serve_tcp_listener(l, OncRpc::..)` is a type error —
/// ONC-over-network is unrepresentable, not a runtime `Err`.
pub trait NetworkWire<S>: Wire<S> {
    /// Admission check run before serving over a network-facing transport. Default: admit. [`JsonRpc`]
    /// overrides this to refuse protocols lacking `$/sessionSetup` (so an unauthenticated remote can't
    /// reach gated methods); a wire whose engine owns its own authentication keeps the default.
    fn admit_network(&self, host: WireHost<'_, S>) -> std::io::Result<()> {
        let _ = host;
        Ok(())
    }
}

/// The curated, opaque view of the server a [`Wire`] gets at construction — the factory-time analogue
/// of [`ConnContext`](crate::ConnContext). Wraps the crate-private `ServerShared` so the substrate
/// (op-tables, negotiate state, the session registry) never crosses the public seam.
#[derive(Clone, Copy)]
pub struct WireHost<'a, S> {
    shared: &'a Arc<ServerShared<S>>,
}

impl<'a, S: Send + Sync + 'static> WireHost<'a, S> {
    /// Wrap the server's shared substrate (crate-internal — see `TruenasRpcServer::host`).
    pub(crate) fn new(shared: &'a Arc<ServerShared<S>>) -> Self {
        WireHost { shared }
    }

    /// The default JSON-RPC engine over this server's registered protocols (the `$/negotiate` view).
    pub fn json_rpc_engine(self) -> Arc<dyn ProtocolEngine> {
        Arc::new(JsonRpcEngine::new(self.shared.clone()))
    }

    /// A registered protocol's wire-neutral op-table, for a binary wire-view to serve over its own
    /// framing. `None` if no protocol of that name is registered.
    pub fn service(self, protocol: &str) -> Option<Arc<Service<S>>> {
        self.shared
            .protocols
            .get(protocol)
            .map(|p| p.service().clone())
    }

    /// The sole registered protocol's op-table, if *exactly one* is registered (for a wire that does
    /// not name a protocol). `None` if zero or more than one are registered.
    pub fn sole_service(self) -> Option<Arc<Service<S>>> {
        let mut it = self.shared.protocols.values();
        match (it.next(), it.next()) {
            (Some(p), None) => Some(p.service().clone()),
            _ => None,
        }
    }

    /// The configured inbound message-size limit.
    pub fn limit(self) -> usize {
        self.shared.limit
    }

    /// The network-auth guard: `Err` if any registered protocol has no `$/sessionSetup` (unless the
    /// server opted in). The one source of truth, shared by [`NetworkWire::admit_network`] and the
    /// WebSocket transport.
    pub fn require_session_auth(self) -> std::io::Result<()> {
        self.shared.require_session_auth()
    }
}

/// The JSON-RPC (+ TXDR) wire — the default engine (`$/negotiate` across all registered protocols).
/// Carries no trust posture: trust is a *transport* property (an AF_UNIX socket is local or proxied;
/// TCP/TLS carry their own), so the `serve_*` method fixes the posture, not this value.
pub struct JsonRpc;

impl<S: Send + Sync + 'static> Wire<S> for JsonRpc {
    fn into_engine(self, host: WireHost<'_, S>) -> std::io::Result<Arc<dyn ProtocolEngine>> {
        Ok(host.json_rpc_engine())
    }
}

impl<S: Send + Sync + 'static> NetworkWire<S> for JsonRpc {
    fn admit_network(&self, host: WireHost<'_, S>) -> std::io::Result<()> {
        host.require_session_auth()
    }
}

/// A pre-built [`ProtocolEngine`] as a wire value — the raw extension point for a custom wire. Owns
/// its own authentication (the default [`NetworkWire::admit_network`] admits), so scope a network
/// listener's exposure to match the engine's auth model.
pub struct CustomWire(pub Arc<dyn ProtocolEngine>);

impl<S> Wire<S> for CustomWire {
    fn into_engine(self, _host: WireHost<'_, S>) -> std::io::Result<Arc<dyn ProtocolEngine>> {
        Ok(self.0)
    }
}

impl<S> NetworkWire<S> for CustomWire {}
