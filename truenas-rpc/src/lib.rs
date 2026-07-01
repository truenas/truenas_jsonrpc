//! `truenas-rpc` — the transport-agnostic JSON-RPC 2.0 **dispatch core** for
//! TrueNAS.
//!
//! It is a refinement of JSON-RPC 2.0 designed for long-lived, authenticated,
//! multiplexed connections; the language-agnostic wire contract lives in the
//! repo-root `ARCHITECTURE.md`. This crate owns envelope parsing/validation, the
//! session state machine + gate, the per-request dispatch pipeline, the `$/`
//! control messages, and message construction — the **dispatch core** of the `ARCHITECTURE.md`
//! layer stack (the **Codec**, **Envelope**, and **Dispatch** layers plus the **Authorization**
//! gate and **Control-plane**). It is **transport-free**: a server
//! drives [`JsonRpcProtocol::dispatch`] with framed bytes and a per-connection
//! [`Session`], and routes the bytes it returns.
//!
//! ## Execution model (blocking vs. awaitable)
//!
//! [`JsonRpcProtocol::dispatch`] is `async` and **branches on the method kind**: a
//! sync [`RpcMethod`] (the default — covers blocking work like ZFS ioctls,
//! file I/O, and auth-stack crypto) runs its pipeline on a `spawn_blocking` worker;
//! an [`AsyncRpcMethod`] (for genuinely awaitable work) is awaited on the runtime.

mod envelope;
mod error;
mod meta;
mod method;
mod protocol;
mod pydispatch;
mod request;
mod role;
mod session;
mod setup;
mod transfer;
mod types;

pub use error::{BuildResult, Error, ErrorCode, JsonRpcError};
pub use meta::Secret;
pub use method::{
    AsyncRpcMethod, FilterableRpcMethod, RpcFdPassMethod, RpcFdTransferMethod,
    RpcMethod, MethodDef, SubscriptionDef,
};
pub use protocol::{
    AuditOutcome, AuditSink, CancelTarget, Canceller, Dispatched, JsonRpcProtocol,
    JsonRpcProtocolBuilder, ServerInfoHandler, Service, SessionInfo,
};
pub use setup::{SetupHandoff, SetupOutcome, SetupTakeover};
pub use transfer::{FileTransfer, Transfer, TransferDirection};
pub use pydispatch::{PyDispatcher, PyOutcome, PyResult};
pub use request::RequestCtx;
pub use role::{RoleMask, Roles};
pub use session::{
    Clock, Credential, IdGen, NullOutbound, OperationGuard, OperationInfo, OperationKind, Outbound,
    Session, SessionId, SessionOrigin, SystemClock, UuidGen,
};
pub use types::{RequestInfo, MessageDirection, ServerInfo, SessionLifecycle};
// Re-exported from `truenas-filter` so consumers can write filterable (query) handlers
// without a direct dependency on the engine crate.
pub use truenas_filter::{
    compile_filters, compile_options, tnfilter, tnmatch, CompiledFilters, CompiledOptions,
    FilterError, Filtered, QueryFilters, QueryOptions,
};

/// The JSON-RPC protocol version string this implementation speaks.
pub const JSONRPC_VERSION: &str = "2.0";
