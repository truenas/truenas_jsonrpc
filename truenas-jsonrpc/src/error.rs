//! Error model: wire error codes ([`ErrorCode`]), the handler-facing [`JsonRpcError`],
//! and the construction-time crate [`Error`]. Mirrors Python `truenas_pyjsonrpc.errors`
//! + `types.JSONRPCError`.

/// Wire error codes — the JSON-RPC 2.0 standard set plus the library/LSP-derived
/// extensions. Serializes as its `i32`. Mirrors Python's `JSONRPCError(IntEnum)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ErrorCode {
    /// Malformed JSON ("Parse error").
    InvalidJson = -32700,
    /// Bad envelope (non-object, non-UUID id, or an empty JSON-RPC 2.0 batch array).
    InvalidRequest = -32600,
    /// Unknown method.
    MethodNotFound = -32601,
    /// Params failed decode/validation (by-name only).
    InvalidParams = -32602,
    /// Unexpected handler/return fault (a bug).
    InternalError = -32603,
    /// An authorizer denied the call (library code, server-error range).
    NotAuthorized = -32000,
    /// A non-`pre_auth` method before the session was ESTABLISHED, or on CLOSED (LSP).
    SessionNotEstablished = -32002,
    /// A request cancelled via `$/cancelRequest` (LSP).
    RequestCancelled = -32800,
    /// A valid+authorized request that failed for an *expected* reason (vs a bug) (LSP).
    RequestFailed = -32803,
}

impl ErrorCode {
    /// The numeric wire code.
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// The error a handler returns to choose a wire error code (mirrors Python's
/// `JsonRpcError` exception). `code` is an `i32` (not the enum) so a handler may return
/// a custom code in the implementation-defined server range (-32000..-32099), exactly
/// like Python's `int(code)`.
#[derive(Clone, Debug, thiserror::Error)]
#[error("[{code}] {message}")]
pub struct JsonRpcError {
    /// The wire error code (a known [`ErrorCode`] or a custom server-range `i32`).
    pub code: i32,
    /// The human-readable error message.
    pub message: String,
    /// Optional structured error data.
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    /// Build from a known [`ErrorCode`].
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code: code.code(), message: message.into(), data: None }
    }

    /// Build with an arbitrary integer code (custom server-error range).
    pub fn custom(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), data: None }
    }

    /// Attach structured `data` to the error.
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// An `INVALID_PARAMS` error (the params failed validation).
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams, msg)
    }
    /// A `METHOD_NOT_FOUND` error.
    pub fn method_not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::MethodNotFound, msg)
    }
    /// A `NOT_AUTHORIZED` error (an authorizer denied the call).
    pub fn not_authorized(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotAuthorized, msg)
    }
    /// A `REQUEST_FAILED` error (a valid call that failed for an expected reason).
    pub fn request_failed(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::RequestFailed, msg)
    }
    /// An `INTERNAL_ERROR` (an unexpected handler/server fault — a bug).
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, msg)
    }
    /// A `SESSION_NOT_ESTABLISHED` error.
    pub fn session_not_established(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::SessionNotEstablished, msg)
    }
    /// A `REQUEST_CANCELLED` error (for a `$/cancelRequest`-aborted handler).
    pub fn cancelled() -> Self {
        Self::new(ErrorCode::RequestCancelled, "Request cancelled")
    }
}

/// Construction-time errors from building a [`crate::JsonRpcProtocol`] (the builder).
/// Distinct from [`JsonRpcError`] (the wire error) — **never** produced by `dispatch`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A method name in the reserved `rpc.` / `$/` namespace was registered.
    #[error("method names beginning with 'rpc.' or '$/' are reserved: {0:?}")]
    ReservedName(String),
    /// The same method name was registered twice.
    #[error("duplicate method: {0:?}")]
    DuplicateMethod(String),
    /// A miscellaneous builder configuration error.
    #[error("{0}")]
    Config(String),
}

/// Result alias for construction-time / builder operations (error type [`Error`]).
/// Deliberately **not** named `Result`: handlers and the wire-encoding path use the std
/// `Result<T, JsonRpcError>`, and a crate-level `Result` alias would shadow it
/// (forcing fully-qualified `std::result::Result` at every handler signature).
pub type BuildResult<T> = std::result::Result<T, Error>;
