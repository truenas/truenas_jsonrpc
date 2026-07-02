//! The Python <-> Rust struct boundary (the serde layer). `pythonize` serializes straight to/from
//! Python objects — there is **no intermediate JSON string** — and one uniform conversion handles
//! every generated field shape (nested `$ref`, string-enum, `Secret`, `Vec`, `Option`) because they
//! are all `Serialize` / `Deserialize`. Used by the generated per-field getters (`to_py`) and the
//! keyword constructors (`from_py`).

use pyo3::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::rpc_error;

/// Convert a Rust value into a Python object (a generated per-field getter).
pub fn to_py<T: Serialize>(py: Python<'_>, value: &T) -> PyResult<PyObject> {
    pythonize::pythonize(py, value)
        .map(|obj| obj.unbind())
        .map_err(|e| rpc_error(format!("to python: {e}")))
}

/// Convert a Python object into a Rust value (a generated keyword constructor). A wrong type or a
/// missing required field surfaces as an `RpcError`.
pub fn from_py<T: DeserializeOwned>(obj: &Bound<'_, PyAny>) -> PyResult<T> {
    pythonize::depythonize(obj).map_err(|e| rpc_error(format!("from python: {e}")))
}
