//! Client round-trip: the generated msgspec `DemoClient` (over a `truenas-rpc-pyclient` `RawClient`)
//! against a live `TruenasRpcServer`. Embeds CPython with the `truenas_rpc_pyclient` module
//! registered, adds `$OUT_DIR` (the generated `demo_*.py`) to `sys.path`, and drives the client.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Once;

use pyo3_ffi as ffi;
use serde::{Deserialize, Serialize};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

#[derive(Serialize, Deserialize)]
struct GreetArgs {
    name: String,
}
#[derive(Serialize, Deserialize)]
struct GreetResult {
    message: String,
}
#[derive(Serialize, Deserialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Serialize, Deserialize)]
struct AddResult {
    sum: i64,
}

/// Serve `demo` (`greet` + `add`) over AF_UNIX on a dedicated runtime; signal once listening.
fn serve() -> PathBuf {
    let path = std::env::temp_dir().join(format!("demo-py-client-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let serve_path = path.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let proto = JsonRpcProtocol::<()>::builder("demo", "1.0.0")
                .method(RpcMethod::new(
                    MethodDef::new("greet"),
                    |a: GreetArgs, _cx: &RequestCtx<()>| {
                        Ok::<_, JsonRpcError>(GreetResult {
                            message: format!("hi {}", a.name),
                        })
                    },
                ))
                .unwrap()
                .method(RpcMethod::new(
                    MethodDef::new("add"),
                    |a: AddArgs, _cx: &RequestCtx<()>| {
                        Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b })
                    },
                ))
                .unwrap()
                .build();
            let listener =
                TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&serve_path)).unwrap();
            let srv = TruenasRpcServer::<()>::builder("demo-server")
                .protocol("demo", proto)
                .build();
            ready_tx.send(()).unwrap();
            let _ = srv.serve_unix_listener(listener, JsonRpc).await;
        });
    });
    ready_rx.recv().unwrap();
    path
}

/// Bring the embedded interpreter up once, with `truenas_rpc_pyclient` registered as a built-in.
fn init_python() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        assert!(truenas_rpc_pyclient::append_to_inittab());
        unsafe {
            ffi::Py_InitializeEx(0);
            let _ = ffi::PyEval_SaveThread();
        }
    });
}

struct Gil(ffi::PyGILState_STATE);
impl Gil {
    fn acquire() -> Self {
        init_python();
        Gil(unsafe { ffi::PyGILState_Ensure() })
    }
}
impl Drop for Gil {
    fn drop(&mut self) {
        unsafe { ffi::PyGILState_Release(self.0) }
    }
}

/// Run `code` in `__main__`; `false` if it raised (the traceback prints to stderr). GIL must be held.
fn run(code: &str) -> bool {
    let c = CString::new(code).unwrap();
    unsafe { ffi::PyRun_SimpleString(c.as_ptr()) == 0 }
}

#[test]
fn generated_msgspec_client_round_trips() {
    let path = serve();
    let _gil = Gil::acquire();
    let script = format!(
        r#"
import sys
sys.path.insert(0, {out_dir:?})
import demo_types
from demo_client import DemoClient

# The typed client IS the connection object: it pins + $/negotiates its own protocol.
client = DemoClient.connect({path:?})
assert client.PROTOCOL == "demo" and client.VERSION == "1.0.0"
assert client.negotiated["protocol"] == "demo", client.negotiated
assert client.available == ["demo"], client.available

# A typed request in, a typed msgspec result out — the Rust engine only saw bytes.
r = client.greet(demo_types.GreetArgs(name="world"))
assert r.message == "hi world", r
assert isinstance(r, demo_types.GreetResult), type(r)

s = client.add(demo_types.AddArgs(a=20, b=22))
assert s.sum == 42, s
"#,
        out_dir = env!("OUT_DIR"),
        path = path.to_string_lossy(),
    );
    let ok = run(&script);
    let _ = std::fs::remove_file(&path);
    assert!(
        ok,
        "the generated client round-trip script raised (see stderr)"
    );
}
