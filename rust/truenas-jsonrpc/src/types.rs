//! Shared protocol vocabulary: enums and the data types handed to the authz/audit
//! hooks. Mirrors Python `truenas_pyjsonrpc.types`.

use serde::{Deserialize, Serialize};

/// The authentication state of a connection's [`crate::Session`].
///
/// `None` — fresh, unauthenticated. `Init` — multi-step auth in progress (expecting
/// `$/sessionSetupContinue`). `Established` — authenticated; normal methods allowed.
/// `Closed` — ended; no further dispatch accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionLifecycle {
    None,
    Init,
    Established,
    Closed,
}

/// Which way a method's primary payload travels.
///
/// `ClientServer` (default) is a normal request method. `ServerClient` is a
/// subscribable notification topic (the client subscribes, the server later publishes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    ClientServer,
    ServerClient,
}

/// The request context passed to the authorization and audit hooks. `params` is the
/// decoded params as a `serde_json::Value` snapshot (so authz/audit see the same payload
/// the handler does, decoupled from the concrete `Accepts` type). `id` is `None` for a
/// notification. `roles` are the dispatched method's declared roles (metadata only — the
/// protocol does not enforce them).
#[derive(Clone, Debug)]
pub struct JsonRpcRequest {
    pub method: String,
    pub id: Option<String>,
    pub params: serde_json::Value,
    pub roles: Vec<String>,
}

/// The result an authorizer must return. `authorized == false` skips the handler and
/// yields a `NOT_AUTHORIZED` error built from `message`/`data`.
#[derive(Clone, Debug)]
pub struct AuthorizationResponse {
    pub authorized: bool,
    pub message: String,
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
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}
