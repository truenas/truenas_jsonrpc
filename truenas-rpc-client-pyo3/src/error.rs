//! The Python-visible error type + conversion helper.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::PyErr;

create_exception!(
    truenas_rpc_client_pyo3,
    RpcError,
    PyException,
    "An error from a truenas-rpc PyO3 client — a server-returned RPC error, or a local \
     transport / encode / decode failure."
);

/// Build an [`RpcError`] from a message. Bridge code returns plain-Rust `Result<_, String>` across
/// the GIL-released boundary (a `PyErr` is not `Ungil`), then maps the message here with the GIL held.
pub(crate) fn rpc_error(msg: impl Into<String>) -> PyErr {
    RpcError::new_err(msg.into())
}
