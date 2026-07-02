//! Compile + import proof for the generated Python client (`truenas-rpc-codegen`'s `emit_pyclient`).
//!
//! This cdylib `include!`s the generated shared types, the Rust typed client, and the PyO3 module
//! from `examples/demo`'s spec — so `cargo build` proves the generated PyO3 code compiles into a real
//! extension. The test populates the module in-process (exactly what `PyInit_demo` does for a real
//! `.so`) and drives the generated Python client — construct a typed request, connect to a live
//! `TruenasRpcServer`, call `greet`, read the typed result — proving the whole Python surface works.

// Types first, then the Rust typed client the Python client wraps, then the PyO3 module. The basic
// Python client wraps only request→result methods, so the Rust client's query/transfer methods are
// unused here — `dead_code` is expected for generated code a given consumer doesn't fully use.
#[allow(clippy::all, clippy::pedantic, missing_docs, dead_code)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/types_gen.rs"));
    include!(concat!(env!("OUT_DIR"), "/client_gen.rs"));
    include!(concat!(env!("OUT_DIR"), "/pyclient_gen.rs"));
}

#[cfg(test)]
mod tests {
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyModule};
    use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
    use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

    // The generated shared types: the server handler produces the same structs the client sends/reads.
    use crate::generated::{GreetArgs, GreetResult};

    /// Serve a `greet` method on a dedicated background runtime; the channel signals once listening.
    fn serve() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("demo-py-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let serve_path = path.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let proto = JsonRpcProtocol::<()>::builder("demo", "1.0.0")
                    .method(RpcMethod::new(
                        MethodDef::new("greet"),
                        |a: GreetArgs, _cx: &RequestCtx<()>| {
                            Ok::<_, JsonRpcError>(GreetResult { message: format!("hi {}", a.name) })
                        },
                    ))
                    .unwrap()
                    .build();
                let listener =
                    TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&serve_path)).unwrap();
                let srv =
                    TruenasRpcServer::<()>::builder("demo-server").protocol("demo", proto).build();
                ready_tx.send(()).unwrap();
                let _ = srv.serve_unix_listener(listener, JsonRpc).await;
            });
        });
        ready_rx.recv().unwrap();
        path
    }

    #[test]
    fn generated_python_client_round_trip() {
        let path = serve();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Populate a module with the generated classes — what `PyInit_demo` does for a real `.so`.
            let module = PyModule::new(py, "demo").unwrap();
            crate::generated::demo(&module).unwrap();

            // Drive the generated Python client through Python's object protocol.
            let endpoint = module
                .getattr("Endpoint")
                .unwrap()
                .call_method1("unix", (path.to_str().unwrap(),))
                .unwrap();
            let client =
                module.getattr("DemoClient").unwrap().call_method1("connect", (endpoint,)).unwrap();

            let kwargs = PyDict::new(py);
            kwargs.set_item("name", "world").unwrap();
            let args = module.getattr("GreetArgs").unwrap().call((), Some(&kwargs)).unwrap();

            let result = client.call_method1("greet", (args,)).unwrap();
            let message: String = result.getattr("message").unwrap().extract().unwrap();
            assert_eq!(message, "hi world");

            client.call_method0("close").unwrap();
        });
        let _ = std::fs::remove_file(&path);
    }
}
