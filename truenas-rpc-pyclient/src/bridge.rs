//! The async→sync bridge: a shared multi-thread runtime + a blocking connect/call. Pure Rust (no
//! Python) — the `pyo3-ffi` layer releases the GIL around these, so the wire I/O never stalls other
//! Python threads.

use std::sync::OnceLock;

use tokio::runtime::Runtime;
use truenas_rpc_client::{
    ClientConfig, ClientError, Endpoint, JsonRpcClient, JsonRpcMethod, Negotiated,
};

/// The process-wide multi-thread tokio runtime hosting every client's connection tasks. Multi-thread
/// is **required**: `connect_negotiate` spawns background recv/writer tasks that must keep running on
/// worker threads between blocking calls (a current-thread runtime would stall them).
pub(crate) fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build the truenas-rpc-pyclient tokio runtime")
    })
}

/// Connect + `$/negotiate` `protocol` over an AF_UNIX socket at `path`, blocking on the shared
/// runtime. Returns the connected engine + the negotiated info (protocol/server/available), or a
/// message on failure. Notifications are dropped (the shim has no notification path).
pub(crate) fn connect_unix(
    path: &str,
    protocol: &str,
) -> Result<(JsonRpcClient, Negotiated), String> {
    let endpoint = Endpoint::unix(path);
    runtime()
        .block_on(JsonRpcClient::connect_negotiate(
            &endpoint,
            protocol,
            ClientConfig::default(),
        ))
        .map(|(client, negotiated, _notifications)| (client, negotiated))
        .map_err(|e| e.to_string())
}

/// Make one by-name call, blocking on the shared runtime: `params`/result are the raw wire bytes
/// (the Python side owns the msgspec types). A server error surfaces as its `(code, message)`.
pub(crate) fn call_blocking(
    client: &JsonRpcClient,
    method: &str,
    params: &[u8],
) -> Result<Vec<u8>, CallError> {
    runtime()
        .block_on(client.call(&JsonRpcMethod::Name(method.to_string()), params))
        .map_err(CallError::from)
}

/// A flattened call failure: a JSON-RPC `code` + `message` (a transport/decode fault flattens to
/// `INTERNAL_ERROR` via [`ClientError::into_jsonrpc`]).
pub(crate) struct CallError {
    pub code: i32,
    pub message: String,
}

impl From<ClientError> for CallError {
    fn from(e: ClientError) -> Self {
        let e = e.into_jsonrpc();
        CallError {
            code: e.code,
            message: e.message,
        }
    }
}
