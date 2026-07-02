//! The synchronous bridge: a shared runtime + a blocking connect. The generated Python client wraps
//! the **generated Rust typed client** (`<Name>Client<JsonRpcClient>`) and drives its async methods
//! on this runtime with the GIL released — so the wire (de)serialization stays in the Rust client,
//! and this crate only bridges async→sync.

use std::sync::OnceLock;

use pyo3::prelude::*;
use tokio::runtime::Runtime;
use truenas_rpc_client::{ClientConfig, Endpoint, JsonRpcClient};

use crate::error::rpc_error;

/// The process-wide multi-thread tokio runtime hosting every client's connection tasks. Multi-thread
/// is **required**: `connect_negotiate` spawns background recv/writer tasks that must keep running on
/// worker threads between blocking calls (a current-thread runtime would stall them).
///
/// The generated client methods call `runtime().block_on(rust_client.<method>(args))` inside
/// `Python::allow_threads`, so the GIL is released for the duration of each call.
pub fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build the truenas-rpc-pyclient tokio runtime")
    })
}

/// Connect and `$/negotiate` `protocol`, returning the raw engine for the generated client to wrap
/// (`<Name>Client::new(engine)`). Blocks with the GIL released.
pub fn connect_blocking(
    py: Python<'_>,
    endpoint: &Endpoint,
    protocol: &str,
    config: Option<&ClientConfig>,
) -> PyResult<JsonRpcClient> {
    let endpoint = endpoint.clone();
    let protocol = protocol.to_string();
    let config = config.cloned().unwrap_or_default();
    // No `PyErr` may cross `allow_threads` (it is not `Ungil`): return a plain-Rust result and map it
    // to the Python exception once the GIL is re-held.
    let connected = py.allow_threads(move || {
        runtime()
            .block_on(JsonRpcClient::connect_negotiate(
                &endpoint, &protocol, config,
            ))
            .map_err(|e| e.to_string())
    });
    let (client, _negotiated, _notifications) = connected.map_err(rpc_error)?;
    Ok(client)
}
