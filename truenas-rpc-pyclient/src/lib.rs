//! Runtime for the **generated Python client** (`truenas-rpc-codegen`'s `emit_py_client`).
//!
//! A thin `pyo3-ffi` shim that exposes the Rust `truenas-rpc-client` engine to Python as a
//! `RawClient` with a **byte boundary** — `RawClient.call(method, params_bytes) -> result_bytes`.
//! The generated `<Proto>Client` (msgspec) owns the types: it `msgspec.json.encode`s the request,
//! hands the bytes to `RawClient.call`, and `msgspec.json.decode`s the reply. This crate only
//! shuttles bytes and bridges async→sync (a shared multi-thread runtime + GIL-releasing `block_on`).
//! No per-type translation, no high-level pyo3 — the same raw `pyo3-ffi` the embedded **server**
//! bridge (`truenas-rpc-pyo3`) uses. It links libpython, so it is **not** a workspace
//! `default-member`.
//!
//! Two entry points: the extension-module init [`PyInit_truenas_rpc_pyclient`] (`connect(path,
//! protocol) -> RawClient` when Python imports the `.so`), and [`make_raw_client`] (when a Rust host
//! embeds Python, connects the engine itself, and hands the object to Python). Use
//! [`append_to_inittab`] to register the module in an embedded interpreter before `Py_Initialize`.

use std::os::raw::c_char;

use pyo3_ffi as ffi;

mod bridge;
mod rawclient;

pub use rawclient::{make_raw_client, make_raw_client_negotiated, PyInit_truenas_rpc_pyclient};

/// Register the module as a built-in so an **embedded** interpreter can `import truenas_rpc_pyclient`
/// (and call `connect(...)`). Must be called **before** `Py_Initialize`. Returns `true` on success.
#[allow(unsafe_code)]
pub fn append_to_inittab() -> bool {
    // SAFETY: `PyImport_AppendInittab` is valid before interpreter init; the name is NUL-terminated
    // and `PyInit_truenas_rpc_pyclient` is the matching init hook.
    unsafe {
        ffi::PyImport_AppendInittab(
            c"truenas_rpc_pyclient".as_ptr().cast::<c_char>(),
            Some(PyInit_truenas_rpc_pyclient),
        ) == 0
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::path::PathBuf;
    use std::sync::Once;

    use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
    use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

    use super::*;
    use crate::bridge::runtime;

    /// Bring the embedded interpreter up once, with our module registered as a built-in first (so
    /// `import truenas_rpc_pyclient` works). Releases the init thread's GIL for later `Gil::acquire`.
    #[allow(unsafe_code)]
    fn init_python() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            assert!(
                append_to_inittab(),
                "append_to_inittab before Py_Initialize"
            );
            // SAFETY: guarded by `Once`; `PyEval_SaveThread` releases the init thread's GIL for the
            // per-thread `PyGILState_Ensure` in `Gil`.
            unsafe {
                ffi::Py_InitializeEx(0);
                let _ = ffi::PyEval_SaveThread();
            }
        });
    }

    /// RAII GIL guard.
    struct Gil(ffi::PyGILState_STATE);
    impl Gil {
        #[allow(unsafe_code)]
        fn acquire() -> Self {
            init_python();
            // SAFETY: the interpreter is initialized; pairs with `PyGILState_Release` in `Drop`.
            Gil(unsafe { ffi::PyGILState_Ensure() })
        }
    }
    impl Drop for Gil {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: `self.0` is the state from the matching `PyGILState_Ensure`.
            unsafe { ffi::PyGILState_Release(self.0) }
        }
    }

    /// A no-auth `demo` protocol with `math.add` (reachable from NONE).
    fn proto() -> JsonRpcProtocol<()> {
        JsonRpcProtocol::<()>::builder("demo", "1")
            .method(RpcMethod::new(
                MethodDef::new("math.add"),
                |a: (i64, i64), _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(a.0 + a.1),
            ))
            .unwrap()
            .build()
    }

    /// Bind + spawn a live `demo` server over AF_UNIX on the shared runtime; return its socket path.
    fn serve() -> PathBuf {
        let path = std::env::temp_dir().join(format!("tnrpc-pyclient-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let p = path.clone();
        runtime().block_on(async move {
            let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&p)).unwrap();
            let srv = TruenasRpcServer::<()>::builder("demo-server")
                .protocol("demo", proto())
                .build();
            tokio::spawn(async move { srv.serve_unix_listener(listener, JsonRpc).await });
        });
        path
    }

    /// Run `code` in the interpreter's `__main__`; returns whether it completed without raising (a
    /// raised exception is printed to stderr and yields `false`). Must hold the GIL.
    #[allow(unsafe_code)]
    fn run(code: &str) -> bool {
        let c = CString::new(code).unwrap();
        // SAFETY: GIL held (caller holds a `Gil`); `c` is a valid NUL-terminated program.
        unsafe { ffi::PyRun_SimpleString(c.as_ptr()) == 0 }
    }

    #[test]
    fn raw_client_extension_round_trips_against_a_live_server() {
        let path = serve();
        let _gil = Gil::acquire();

        // `math.add` here takes a 2-tuple `[a, b]` and returns their sum — the msgspec side owns the
        // shapes, so `call` just shuttles the JSON bytes.
        let script = format!(
            r#"
import json
import truenas_rpc_pyclient as m

# RawClient() is not directly constructible.
try:
    m.RawClient()
    raise AssertionError("RawClient() should not be constructible")
except RuntimeError:
    pass

# A failed connect raises RpcError.
try:
    m.connect("/nonexistent/tnrpc-missing.sock", "demo")
    raise AssertionError("connect to a missing socket must raise")
except m.RpcError:
    pass

# Happy path: connect + a by-name byte call against the live server.
c = m.connect({path:?}, "demo")

# The $/negotiate result is surfaced as a dict.
neg = c.negotiated()
assert neg["protocol"] == "demo", neg
assert neg["available"] == ["demo"], neg
assert "server" in neg, neg

out = c.call("math.add", b"[20, 22]")
assert isinstance(out, (bytes, bytearray)), type(out)
assert json.loads(out) == 42, out

# A server-side error (unknown method) surfaces as RpcError.
try:
    c.call("does.not.exist", b"[]")
    raise AssertionError("unknown method must raise")
except m.RpcError:
    pass
"#,
            path = path.to_string_lossy(),
        );
        let ok = run(&script);
        let _ = std::fs::remove_file(&path);
        assert!(ok, "the embedded round-trip script raised (see stderr)");
    }
}
