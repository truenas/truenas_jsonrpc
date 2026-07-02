//! The blocking bridge: drive the async `JsonRpcClient` from synchronous Python.

use std::sync::{Mutex, OnceLock};

use pyo3::prelude::*;
use tokio::runtime::Runtime;
use truenas_rpc_client::{CallEngine, ClientConfig, Endpoint, JsonRpcClient, MethodKey};

use crate::error::rpc_error;

/// The process-wide multi-thread tokio runtime hosting every client's connection tasks. Multi-thread
/// is **required**: `connect_negotiate` spawns background recv/writer tasks that must keep running on
/// worker threads between blocking calls (a current-thread runtime would stall them).
fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build the truenas-rpc-client-pyo3 tokio runtime")
    })
}

/// A synchronous handle to a connected [`JsonRpcClient`]. Each method runs its async op on the shared
/// runtime with the GIL released; the generated `<Name>Client` pyclass holds one.
///
/// The client lives behind a `Mutex<Option<_>>`: `Option` so [`close`](Self::close) can consume it
/// (graceful close takes `self`), `Mutex` so the pyclass is `Sync` and concurrent Python calls
/// serialize on the one connection.
pub struct BlockingClient {
    inner: Mutex<Option<JsonRpcClient>>,
}

impl BlockingClient {
    /// Connect and `$/negotiate` `protocol`, blocking until the session is established.
    pub fn connect(
        py: Python<'_>,
        endpoint: &Endpoint,
        protocol: &str,
        config: Option<&ClientConfig>,
    ) -> PyResult<Self> {
        let endpoint = endpoint.clone();
        let protocol = protocol.to_string();
        let config = config.cloned().unwrap_or_default();
        // No `PyErr` may cross `allow_threads` (it is not `Ungil`): return a plain-Rust result and map
        // it to the Python exception once the GIL is re-held.
        let connected = py.allow_threads(move || {
            rt().block_on(JsonRpcClient::connect_negotiate(&endpoint, &protocol, config))
                .map_err(|e| e.to_string())
        });
        let (client, _negotiated, _notifications) = connected.map_err(rpc_error)?;
        Ok(BlockingClient { inner: Mutex::new(Some(client)) })
    }

    /// Serialize `request` to JSON, call `method`, and deserialize the reply. Used by the generated
    /// JSON-RPC methods.
    pub fn call_json<Req, Res>(&self, py: Python<'_>, method: &str, request: &Req) -> PyResult<Res>
    where
        Req: serde::Serialize,
        Res: serde::de::DeserializeOwned,
    {
        let params =
            serde_json::to_vec(request).map_err(|e| rpc_error(format!("encode {method}: {e}")))?;
        let reply = self.call_raw(py, MethodKey::Name(method), &params)?;
        serde_json::from_slice(&reply).map_err(|e| rpc_error(format!("decode {method}: {e}")))
    }

    /// XDR-encode `request`, call proc `proc_id` over the binary wire, and XDR-decode the reply. Used
    /// by the generated `xdr:true` methods.
    pub fn call_xdr<Req, Res>(&self, py: Python<'_>, proc_id: u32, request: &Req) -> PyResult<Res>
    where
        Req: serde::Serialize,
        Res: serde::de::DeserializeOwned,
    {
        let params = truenas_rpc_client::to_xdr(request)
            .map_err(|e| rpc_error(format!("xdr encode proc {proc_id}: {e}")))?;
        let reply = self.call_raw(py, MethodKey::Proc(proc_id), &params)?;
        truenas_rpc_client::from_xdr(&reply)
            .map_err(|e| rpc_error(format!("xdr decode proc {proc_id}: {e}")))
    }

    /// Gracefully close the session (`$/sessionClose`). Idempotent — a second call is a no-op.
    pub fn close(&self, py: Python<'_>) -> PyResult<()> {
        let client = self.inner.lock().expect("client mutex").take();
        if let Some(client) = client {
            py.allow_threads(|| rt().block_on(client.close()).map_err(|e| e.to_string()))
                .map_err(rpc_error)?;
        }
        Ok(())
    }

    /// Run one already-encoded call on the shared runtime with the GIL released.
    fn call_raw(&self, py: Python<'_>, method: MethodKey<'_>, params: &[u8]) -> PyResult<Vec<u8>> {
        let reply: Result<Vec<u8>, String> = py.allow_threads(|| {
            let guard = self.inner.lock().expect("client mutex");
            let client = guard.as_ref().ok_or_else(|| "client is closed".to_string())?;
            // Disambiguate the object-safe `CallEngine::call` from the inherent `Client::call`.
            rt().block_on(CallEngine::call(client, method, params)).map_err(|e| e.to_string())
        });
        reply.map_err(rpc_error)
    }
}
