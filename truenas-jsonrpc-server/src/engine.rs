//! The **`ProtocolEngine`** seam — the per-listener owner of a connection's wire protocol.
//!
//! A listener is bound to exactly one engine (chosen at server-configuration time, never switched
//! per request). The server hands each accepted connection to its engine, which **owns the whole
//! per-connection loop** — framing, envelope, control verbs, and outcome handling — and drives it to
//! completion. JSON-RPC is the default engine ([`JsonRpcEngine`], whose loop is
//! [`connection::serve`]); a future binary engine would implement this trait instead.
//!
//! **Performance:** the boundary is `dyn`-dispatched **once per connection**, never per request, so
//! the per-request hot path inside an engine stays fully monomorphized (see `PERF.md`). The only
//! cost the seam adds is erasing the connection's byte stream to `Box<dyn AsyncStream>` so the engine
//! can be object-safe without monomorphizing over every transport type — a vtable indirection per
//! `poll_read`/`poll_write`, i.e. per *syscall*, which is negligible against the read/write it does.

use std::future::Future;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::connection;
use crate::peer::Peer;
use crate::server::ServerShared;

/// A bidirectional byte stream a connection runs over (AF_UNIX / TCP / TLS). The supertrait bundle
/// lets a single `Box<dyn AsyncStream>` be both read and written, so [`ProtocolEngine::serve`] can be
/// object-safe (one `dyn` call per connection) without a type parameter for every transport.
pub(crate) trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// A wire protocol bound to a listener. The server resolves one engine per listener and hands it
/// each accepted connection; the engine owns the per-connection loop and drives it to completion.
pub(crate) trait ProtocolEngine<S: Send + Sync + 'static>: Send + Sync {
    /// Serve one accepted connection to completion. `transfer_fd` is the raw fd for raw-fd
    /// (`sendfile` / `SCM_RIGHTS`) operations (`None` when the fd is not plaintext, e.g. userspace
    /// TLS); `peer` is the connected identity; `shared` is the server substrate (protocol op-tables,
    /// the inbound size limit, …).
    ///
    /// The future is boxed by hand rather than via `async-trait`, so the seam adds **no new
    /// dependency** to this crate; the box is allocated once per connection — off the hot path.
    fn serve<'a>(
        &'a self,
        stream: Box<dyn AsyncStream>,
        transfer_fd: Option<RawFd>,
        peer: Peer,
        shared: Arc<ServerShared<S>>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// The default engine: JSON-RPC (text) + the TXDR binary wire, length-prefix framed. Its
/// per-connection loop is [`connection::serve`] — unchanged by the seam.
pub(crate) struct JsonRpcEngine;

impl<S: Send + Sync + 'static> ProtocolEngine<S> for JsonRpcEngine {
    fn serve<'a>(
        &'a self,
        stream: Box<dyn AsyncStream>,
        transfer_fd: Option<RawFd>,
        peer: Peer,
        shared: Arc<ServerShared<S>>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(connection::serve(stream, transfer_fd, peer, shared))
    }
}
