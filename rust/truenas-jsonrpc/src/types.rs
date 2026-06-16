//! Shared protocol vocabulary: enums and the data types handed to the authz/audit
//! hooks. Mirrors Python `truenas_pyjsonrpc.types`.

use serde::{Deserialize, Serialize};

/// The authentication state of a connection's [`crate::Session`].
///
/// The `#[repr(u8)]` discriminants are the in-memory encoding used by the session's
/// atomic lifecycle cell (`session::AtomicLifecycle`); they are not sent on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum SessionLifecycle {
    /// Fresh, unauthenticated connection.
    None = 0,
    /// Multi-step auth in progress (expecting `$/sessionSetupContinue`).
    Init = 1,
    /// Authenticated; normal methods are allowed.
    Established = 2,
    /// Ended; no further dispatch is accepted.
    Closed = 3,
}

/// Which way a method's primary payload travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    /// A normal request method (the default).
    ClientServer,
    /// A subscribable notification topic: the client subscribes, the server publishes.
    ServerClient,
}

/// The request context passed to the authorization and audit hooks. `params` is the
/// decoded params as a `serde_json::Value` snapshot (so authz/audit see the same payload
/// the handler does, decoupled from the concrete `Accepts` type). `id` is `None` for a
/// notification. `roles` are the dispatched method's declared roles (metadata only — the
/// protocol does not enforce them).
#[derive(Clone, Debug)]
pub struct JsonRpcRequest {
    /// The method name.
    pub method: String,
    /// The request id (`None` for a notification).
    pub id: Option<String>,
    /// Decoded params as a `serde_json::Value` snapshot (what authz/audit observe).
    pub params: serde_json::Value,
    /// The dispatched method's declared roles (metadata only; not enforced here).
    pub roles: Vec<String>,
}

/// The result an authorizer must return. `authorized == false` skips the handler and
/// yields a `NOT_AUTHORIZED` error built from `message`/`data`.
#[derive(Clone, Debug)]
pub struct AuthorizationResponse {
    /// Whether the call is allowed (`false` skips the handler → `NOT_AUTHORIZED`).
    pub authorized: bool,
    /// Denial message (used to build the `NOT_AUTHORIZED` error).
    pub message: String,
    /// Optional structured data attached to a denial.
    pub data: Option<serde_json::Value>,
}

impl AuthorizationResponse {
    /// Allow the call.
    pub fn allow() -> Self {
        Self { authorized: true, message: String::new(), data: None }
    }
    /// Deny the call with a message (default Python message is "Not authorized").
    pub fn deny(message: impl Into<String>) -> Self {
        Self { authorized: false, message: message.into(), data: None }
    }
}

/// Server identity for the `$/serverInfo` probe (LSP `serverInfo`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    /// The server/product name.
    pub name: String,
    /// The server/product version, if reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}
