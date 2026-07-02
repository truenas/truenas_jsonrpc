//! Behavioral round-trip: the blocking bridge against a live `TruenasRpcServer` over AF_UNIX. Proves
//! the async→sync bridge (connect / call / close through a real socket, GIL released) that the
//! generated Python client rides.

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_client_pyo3::{BlockingClient, PyEndpoint, RpcError};
use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

#[derive(Serialize, Deserialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Debug, Serialize, Deserialize)]
struct AddResult {
    sum: i64,
}

/// A no-auth protocol with a single `math.add` method (reachable without `$/sessionSetup`).
fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build()
}

/// Bind + serve `proto` on a dedicated background runtime (the client uses its own internal one).
/// Binding creates a tokio `UnixListener`, so it must happen inside the runtime; the channel signals
/// once the socket is bound + listening, so the caller can connect without racing the accept loop.
fn serve(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("tnrpc-cpyo3-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let serve_path = path.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&serve_path)).unwrap();
            let srv = TruenasRpcServer::<()>::builder("demo-server").protocol("demo", proto()).build();
            ready_tx.send(()).unwrap();
            let _ = srv.serve_unix_listener(listener, JsonRpc).await;
        });
    });
    ready_rx.recv().unwrap();
    path
}

#[test]
fn blocking_call_round_trip() {
    pyo3::prepare_freethreaded_python();
    let path = serve("call");

    Python::with_gil(|py| {
        let endpoint = PyEndpoint::unix(path.to_string_lossy().into_owned());
        let client = BlockingClient::connect(py, endpoint.inner(), "demo", None).unwrap();
        let out: AddResult = client.call_json(py, "math.add", &AddArgs { a: 20, b: 22 }).unwrap();
        assert_eq!(out.sum, 42);
        // A second call on the same connection, then a graceful close (idempotent).
        let out: AddResult = client.call_json(py, "math.add", &AddArgs { a: 1, b: 1 }).unwrap();
        assert_eq!(out.sum, 2);
        client.close(py).unwrap();
        client.close(py).unwrap();
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn unknown_method_raises_rpc_error() {
    pyo3::prepare_freethreaded_python();
    let path = serve("nope");

    Python::with_gil(|py| {
        let endpoint = PyEndpoint::unix(path.to_string_lossy().into_owned());
        let client = BlockingClient::connect(py, endpoint.inner(), "demo", None).unwrap();
        let err = client.call_json::<_, AddResult>(py, "math.nope", &AddArgs { a: 1, b: 2 }).unwrap_err();
        assert!(err.is_instance_of::<RpcError>(py));
    });

    let _ = std::fs::remove_file(&path);
}

#[test]
fn connect_failure_raises_rpc_error() {
    pyo3::prepare_freethreaded_python();
    Python::with_gil(|py| {
        let endpoint = PyEndpoint::unix("/nonexistent/truenas-rpc-cpyo3.sock".to_string());
        // `BlockingClient` isn't `Debug`, so unwrap the error off the `Option`, not the `Result`.
        let err = BlockingClient::connect(py, endpoint.inner(), "demo", None).err().unwrap();
        assert!(err.is_instance_of::<RpcError>(py));
    });
}
