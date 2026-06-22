//! `truenas-jsonrpc` — the transport-agnostic JSON-RPC 2.0 **dispatch core** for
//! TrueNAS, a Rust port of Python's `truenas_pyjsonrpc` (`JSONRPCProtocol` /
//! `JSONRPCMethod`).
//!
//! It is a refinement of JSON-RPC 2.0 designed for long-lived, authenticated,
//! multiplexed connections; the language-agnostic wire contract lives in the
//! repo-root `ARCHITECTURE.md`. This crate owns envelope parsing/validation, the
//! session state machine + gate, the per-request dispatch pipeline, the `$/`
//! control messages, and message construction. It is **transport-free**: a server
//! drives [`JsonRpcProtocol::dispatch`] with framed bytes and a per-connection
//! [`Session`], and routes the bytes it returns.
//!
//! ## Execution model (blocking vs. awaitable)
//!
//! [`JsonRpcProtocol::dispatch`] is `async` and **branches on the method kind**: a
//! sync [`JsonRpcMethod`] (the default — covers blocking work like ZFS ioctls,
//! file I/O, and auth-stack crypto) runs its pipeline on a `spawn_blocking` worker
//! (the analogue of Python's `ThreadPoolExecutor`); an [`AsyncJsonRpcMethod`] (for
//! genuinely awaitable work) is awaited on the runtime.

mod envelope;
mod error;
mod meta;
mod method;
mod protocol;
mod pydispatch;
mod request;
mod session;
mod transfer;
mod types;

pub use error::{BuildResult, Error, ErrorCode, JsonRpcError};
pub use meta::Secret;
pub use method::{
    AsyncJsonRpcMethod, FilterableJsonRpcMethod, JsonRpcFdPassMethod, JsonRpcFdTransferMethod,
    JsonRpcMethod, MethodDef, SubscriptionDef,
};
pub use protocol::{
    AuditSink, Authorizer, CancelTarget, Canceller, Dispatched, JsonRpcProtocol,
    JsonRpcProtocolBuilder, ServerInfoHandler,
};
pub use transfer::{FileTransfer, Transfer, TransferDirection};
pub use pydispatch::{PyDispatcher, PyOutcome, PyResult};
pub use request::RequestCtx;
pub use session::{Clock, IdGen, NullOutbound, Outbound, Session, SessionId, SystemClock, UuidGen};
pub use types::{
    AuthorizationResponse, JsonRpcRequest, MessageDirection, ServerInfo, SessionLifecycle,
};
// Re-exported from `truenas-filter` so consumers can write filterable (query) handlers
// without a direct dependency on the engine crate.
pub use truenas_filter::{
    compile_filters, compile_options, tnfilter, tnmatch, CompiledFilters, CompiledOptions,
    FilterError, Filtered, QueryFilters, QueryOptions,
};

/// The JSON-RPC protocol version string this implementation speaks.
pub const JSONRPC_VERSION: &str = "2.0";
