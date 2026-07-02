//! Runtime for the **generated Python client** (`truenas-rpc-codegen`'s `emit_pyclient`).
//!
//! The design is a **thin wrapper over the generated Rust typed client**: `emit_client` already
//! produces `<Name>Client::<E>::<method>(Args) -> Result<Result, JsonRpcError>`, which does the wire
//! (de)serialization into typed structs. The generated `pyclient_gen.rs` wraps that client and drives
//! its async methods synchronously on this crate's runtime, so the only new work is Python↔Rust struct
//! conversion. This crate supplies:
//!
//! - [`connect_blocking`] — connect + `$/negotiate`, returning the engine the generated client wraps
//!   (`<Name>Client::new(engine)`); and [`runtime`] — the shared runtime the generated methods
//!   `block_on` (with the GIL released via `Python::allow_threads`).
//! - [`to_py`] / [`from_py`] — the serde struct↔Python boundary (used by the generated per-field
//!   getters and keyword constructors).
//! - [`PyEndpoint`] / [`PyClientConfig`] — the `Endpoint` / `ClientConfig` classes, [`RpcError`] — the
//!   exception every call raises, [`map_call_err`] — `JsonRpcError` → `RpcError`, and
//!   [`register_common`] — add the shared classes to a generated module.
//!
//! Like `truenas-rpc-pyo3`, it links libpython (via the high-level `pyo3` framework), so it is **not**
//! a workspace `default-member`.

mod bridge;
mod config;
mod convert;
mod error;

use pyo3::prelude::*;
use pyo3::types::PyModule;

pub use bridge::{connect_blocking, runtime};
pub use config::{PyClientConfig, PyEndpoint};
pub use convert::{from_py, to_py};
pub use error::{map_call_err, RpcError};

/// Register the shared `Endpoint` / `ClientConfig` classes and the `RpcError` exception into a
/// generated extension module. The generated `#[pymodule]` calls this before adding the per-service
/// classes, so `from <module> import Endpoint, ClientConfig, RpcError` works.
pub fn register_common(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEndpoint>()?;
    m.add_class::<PyClientConfig>()?;
    m.add("RpcError", m.py().get_type::<RpcError>())?;
    Ok(())
}
