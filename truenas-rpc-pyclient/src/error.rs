//! The Python-visible error type + conversion helper.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::PyErr;

create_exception!(
    truenas_rpc_pyclient,
    RpcError,
    PyException,
    "An error from the truenas-rpc Python client — a server-returned RPC error, or a local \
     transport / encode / decode failure."
);

/// Build an [`RpcError`] from a message. Bridge code returns plain-Rust `Result<_, String>` across
/// the GIL-released boundary (a `PyErr` is not `Ungil`), then maps the message here with the GIL held.
pub(crate) fn rpc_error(msg: impl Into<String>) -> PyErr {
    RpcError::new_err(msg.into())
}

/// Map a call's [`JsonRpcError`](truenas_rpc::JsonRpcError) (from the generated Rust client) to the
/// Python [`RpcError`]. The generated client methods use this: `.map_err(map_call_err)`.
pub fn map_call_err(error: truenas_rpc::JsonRpcError) -> PyErr {
    rpc_error(error.to_string())
}
