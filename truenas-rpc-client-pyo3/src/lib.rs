//! PyO3 support runtime for the **generated Python client** (`truenas-rpc-codegen`'s `emit_pyo3`).
//!
//! The generated `pyo3_gen.rs` defines a `#[pyclass]` wrapper per request/response type and a
//! `#[pyclass] <Name>Client`; both build on this crate. It supplies:
//!
//! - [`BlockingClient`] — the async→sync bridge over the client engine's `CallEngine`. It owns a
//!   process-wide multi-thread tokio runtime and runs each call with the GIL released, so the
//!   generated client's methods are ordinary synchronous Python methods.
//! - [`PyEndpoint`] / [`PyClientConfig`] — the `Endpoint` / `ClientConfig` classes Python code uses
//!   to connect, and [`RpcError`] — the exception every call raises on failure.
//! - [`register_common`] — adds those three to a generated extension module.
//!
//! It is the Python analogue of `truenas-rpc-client`, and — like `truenas-rpc-pyo3` — links
//! libpython (via the high-level `pyo3` framework), so it is **not** a workspace `default-member`;
//! a consumer opts in by depending on it and generating a `#[pymodule]`.

mod bridge;
mod config;
mod error;

use pyo3::prelude::*;
use pyo3::types::PyModule;

pub use bridge::BlockingClient;
pub use config::{PyClientConfig, PyEndpoint};
pub use error::RpcError;

/// Register the shared `Endpoint` / `ClientConfig` classes and the `RpcError` exception into a
/// generated extension module. The generated `#[pymodule]` calls this before adding the
/// per-service classes, so `from <module> import Endpoint, ClientConfig, RpcError` works.
pub fn register_common(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEndpoint>()?;
    m.add_class::<PyClientConfig>()?;
    m.add("RpcError", m.py().get_type::<RpcError>())?;
    Ok(())
}
