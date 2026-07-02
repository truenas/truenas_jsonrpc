//! The **`ProtocolEngine`** seam — the per-listener owner of a connection's wire protocol.
//!
//! A listener is bound to exactly one engine (chosen at serve time, never switched per request). The
//! server hands each accepted connection — as a protocol-neutral [`ConnContext`] — to its engine,
//! which **owns the whole per-connection loop** (framing, envelope, control, outcome handling) and
//! drives it to completion. JSON-RPC is the default engine ([`JsonRpcEngine`], whose loop is
//! [`connection::serve`]); the `oncrpc` module is the reference second implementation; and a
//! downstream crate can implement [`ProtocolEngine`] for a protocol of its own.
//!
//! **The boundary is deliberately narrow.** An engine receives only [`ConnContext`] — the byte
//! stream, the peer, the raw-fd transfer channel, and the inbound size limit — never the
//! JSON-RPC-specific server substrate (`ServerShared`: the op-tables, the negotiate state, the
//! session registry). The default engine keeps that substrate to itself, captured at construction.
//! Building the second engine showed how little a peer protocol actually needs from the server, and
//! this context is exactly that intersection — so making the seam public commits to a small, neutral
//! surface, not the JSON-RPC internals.
//!
//! **Performance:** the boundary is `dyn`-dispatched **once per connection**, never per request, so
//! the per-request hot path inside an engine stays fully monomorphized (see `PERF.md`). The only
//! cost the seam adds is erasing the connection's byte stream to `Box<dyn AsyncStream>` so an engine
//! is object-safe without monomorphizing over every transport type — a vtable indirection per
//! `poll_read`/`poll_write`, i.e. per *syscall*, negligible against the read/write it guards.

use std::future::Future;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::connection;
use crate::peer::Peer;
use crate::server::ServerShared;

/// A bidirectional byte stream a connection runs over (AF_UNIX / TCP / TLS). The supertrait bundle
/// lets a single `Box<dyn AsyncStream>` be both read and written, so an engine is object-safe (one
/// `dyn` call per connection) without a type parameter for every transport. The blanket impl covers
/// every concrete async stream, so it is never implemented by hand.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// The protocol-neutral view of one accepted connection, handed to a [`ProtocolEngine`]. It is the
/// *intersection* of what wire protocols need from the transport — nothing JSON-RPC-specific. Taken
/// by value (the engine owns the connection); `#[non_exhaustive]` so fields can be added later
/// without a breaking change.
#[non_exhaustive]
pub struct ConnContext {
    /// The connection's byte stream; an engine splits / reads / writes it directly.
    pub stream: Box<dyn AsyncStream>,
    /// The connection's plaintext fd for raw-fd operations (`sendfile` / `SCM_RIGHTS`), or `None`
    /// when the fd does not carry plaintext (e.g. userspace TLS) and such operations must be
    /// refused. An engine with no raw-fd path ignores it.
    pub transfer_fd: Option<RawFd>,
    /// The connected peer (transport, credentials, TLS facts, proxied origin).
    pub peer: Peer,
    /// The maximum inbound message size the server is configured to accept.
    pub limit: usize,
}

/// A wire protocol bound to a listener. The server resolves one engine per listener and hands it
/// each accepted connection as a [`ConnContext`]; the engine owns the per-connection loop and drives
/// it to completion. Implement this to serve a custom protocol over the server's transports,
/// alongside (or instead of) the built-in JSON-RPC engine.
pub trait ProtocolEngine: Send + Sync {
    /// Serve one accepted connection to completion.
    ///
    /// The future is boxed by hand rather than via `async-trait`, so the seam adds **no new
    /// dependency**; the box is allocated once per connection — off the hot path.
    fn serve<'a>(&'a self, ctx: ConnContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// The default engine: JSON-RPC (text) + the TXDR binary wire, length-prefix framed. It owns its
/// JSON-RPC server substrate ([`ServerShared`]) — captured here, so the substrate never crosses the
/// public seam — and runs the per-connection loop in [`connection::serve`].
pub(crate) struct JsonRpcEngine<S> {
    shared: Arc<ServerShared<S>>,
}

impl<S> JsonRpcEngine<S> {
    /// Bind the engine to a server's shared substrate (one engine per listener; cheap to make).
    pub(crate) fn new(shared: Arc<ServerShared<S>>) -> Self {
        JsonRpcEngine { shared }
    }
}

impl<S: Send + Sync + 'static> ProtocolEngine for JsonRpcEngine<S> {
    fn serve<'a>(&'a self, ctx: ConnContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        // The JSON-RPC loop reads its size limit from the captured substrate, so `ctx.limit` is
        // unused on this path; every other engine draws the limit from the context instead.
        let ConnContext {
            stream,
            transfer_fd,
            peer,
            limit: _,
        } = ctx;
        Box::pin(connection::serve(
            stream,
            transfer_fd,
            peer,
            self.shared.clone(),
        ))
    }
}
