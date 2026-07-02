//! Python-visible connection endpoint + client tuning.

use std::time::Duration;

use pyo3::prelude::*;
use truenas_rpc_client::{ClientConfig, Endpoint};

/// Where the Python client connects — `Endpoint.unix(path)` or `Endpoint.tcp("host:port")`.
#[pyclass(name = "Endpoint")]
#[derive(Clone)]
pub struct PyEndpoint {
    inner: Endpoint,
}

#[pymethods]
impl PyEndpoint {
    /// An AF_UNIX endpoint at `path`.
    #[staticmethod]
    pub fn unix(path: String) -> Self {
        PyEndpoint { inner: Endpoint::unix(path) }
    }

    /// A TCP endpoint at `addr` (`host:port`).
    #[staticmethod]
    pub fn tcp(addr: String) -> Self {
        PyEndpoint { inner: Endpoint::tcp(addr) }
    }

    fn __repr__(&self) -> String {
        format!("Endpoint({:?})", self.inner)
    }
}

impl PyEndpoint {
    /// The wrapped client [`Endpoint`] — used by the generated `connect`.
    pub fn inner(&self) -> &Endpoint {
        &self.inner
    }
}

/// Client tuning — `ClientConfig(tcp_keepalive_secs=30.0, limit=4194304)`. Omitted / `None` fields
/// keep the defaults (30 s TCP keep-alive, 4 MiB inbound message limit).
#[pyclass(name = "ClientConfig")]
#[derive(Clone)]
pub struct PyClientConfig {
    inner: ClientConfig,
}

#[pymethods]
impl PyClientConfig {
    /// Build a config; a non-positive `tcp_keepalive_secs` disables the keep-alive.
    #[new]
    #[pyo3(signature = (tcp_keepalive_secs = None, limit = None))]
    fn new(tcp_keepalive_secs: Option<f64>, limit: Option<usize>) -> Self {
        let mut inner = ClientConfig::default();
        if let Some(secs) = tcp_keepalive_secs {
            inner.tcp_keepalive = (secs > 0.0).then(|| Duration::from_secs_f64(secs));
        }
        if let Some(limit) = limit {
            inner.limit = limit;
        }
        PyClientConfig { inner }
    }

    fn __repr__(&self) -> String {
        format!("ClientConfig(tcp_keepalive={:?}, limit={})", self.inner.tcp_keepalive, self.inner.limit)
    }
}

impl PyClientConfig {
    /// The wrapped [`ClientConfig`] — used by the generated `connect`.
    pub fn inner(&self) -> &ClientConfig {
        &self.inner
    }
}
