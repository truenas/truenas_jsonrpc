//! Behavioral tests for the sync bridge + the Python↔Rust conversion boundary. `connect_blocking`
//! against a live `TruenasRpcServer` over AF_UNIX (then a raw seam call to prove the connection), and
//! the `to_py`/`from_py` serde round-trip. The full *typed* round-trip — through the generated client
//! this crate wraps — is proven in `examples/demo-py`.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_client::{CallEngine, MethodKey};
use truenas_rpc_pyclient::{connect_blocking, from_py, runtime, to_py, PyEndpoint, RpcError};
use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Debug, Serialize, Deserialize)]
struct AddResult {
    sum: i64,
}

fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build()
}

/// Bind + serve `proto` on a dedicated background runtime; the channel signals once bound + listening.
fn serve(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("tnrpc-cpyo3-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let serve_path = path.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener =
                TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&serve_path)).unwrap();
            let srv = TruenasRpcServer::<()>::builder("demo-server")
                .protocol("demo", proto())
                .build();
            ready_tx.send(()).unwrap();
            let _ = srv.serve_unix_listener(listener, JsonRpc).await;
        });
    });
    ready_rx.recv().unwrap();
    path
}

#[test]
fn connect_blocking_then_raw_call() {
    pyo3::prepare_freethreaded_python();
    let path = serve("connect");

    Python::with_gil(|py| {
        let endpoint = PyEndpoint::unix(path.to_string_lossy().into_owned());
        let client = connect_blocking(py, endpoint.inner(), "demo", None).unwrap();
        // The generated typed client rides the `CallEngine` seam; here (no generated client in this
        // crate) we drive that seam directly to prove connect + the shared runtime work end to end.
        let params = serde_json::to_vec(&AddArgs { a: 20, b: 22 }).unwrap();
        let reply = py
            .allow_threads(|| {
                runtime().block_on(CallEngine::call(
                    &client,
                    MethodKey::Name("math.add"),
                    &params,
                ))
            })
            .unwrap();
        assert_eq!(serde_json::from_slice::<AddResult>(&reply).unwrap().sum, 42);
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn python_rust_conversion_round_trips() {
    pyo3::prepare_freethreaded_python();
    Python::with_gil(|py| {
        let value = AddArgs { a: 3, b: 4 };
        let obj = to_py(py, &value).unwrap();
        let back: AddArgs = from_py(obj.bind(py)).unwrap();
        assert_eq!(back, value);
    });
}

#[test]
fn connect_failure_raises_rpc_error() {
    pyo3::prepare_freethreaded_python();
    Python::with_gil(|py| {
        let endpoint = PyEndpoint::unix("/nonexistent/truenas-rpc-cpyo3.sock".to_string());
        let err = connect_blocking(py, endpoint.inner(), "demo", None)
            .err()
            .unwrap();
        assert!(err.is_instance_of::<RpcError>(py));
    });
}
