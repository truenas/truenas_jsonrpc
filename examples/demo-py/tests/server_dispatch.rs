//! Server dispatch: a `python:true` body (`py.hello`) run by the embedded `truenas-rpc-pyo3` bridge
//! through the generated `dispatch(name, params, session, call)`. The body msgspec-decodes its params,
//! forwards to the core `greet` via `call` (a typed byte round-trip), and returns a msgspec result —
//! all through real CPython, driven by the core spine.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use truenas_rpc::{
    Dispatched, JsonRpcError, JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx, RpcMethod,
};
use truenas_rpc_pyo3::PyBridge;

#[derive(Serialize, Deserialize)]
struct GreetArgs {
    name: String,
}
#[derive(Serialize, Deserialize)]
struct GreetResult {
    message: String,
}

#[tokio::test]
async fn python_body_dispatches_through_generated_server_and_call() {
    // The generated `demo_*.py` and this handlers module live in `$OUT_DIR`; put it on `sys.path`
    // (via `PYTHONPATH`, before the interpreter initializes) so `PyBridge::import` can load them —
    // the production path, no arbitrary-source exec. `demo_handlers` re-exports the generated
    // `dispatch` and registers `py.hello` (which forwards to the core `greet` via `call`).
    let out_dir = env!("OUT_DIR");
    std::env::set_var("PYTHONPATH", out_dir);
    std::fs::write(
        format!("{out_dir}/demo_handlers.py"),
        r#"import msgspec
import demo_types
from demo_server import method, dispatch


@method("py.hello")
def py_hello(req, ctx):
    reply = ctx.call("greet", msgspec.json.encode(req))
    return msgspec.json.decode(reply, type=demo_types.GreetResult)
"#,
    )
    .expect("write the demo handlers module");
    let bridge = PyBridge::import("demo_handlers").expect("import the demo handlers module");

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
        .python_method(MethodDef::new("py.hello"))
        .unwrap()
        .python_dispatcher(bridge)
        .build();

    let session = proto.new_session(Some(()), Arc::new(NullOutbound));
    let wire = r#"{"jsonrpc":"2.0","method":"py.hello","id":"f81d4fae-7dec-11d0-a765-00a0c91e6bf6","params":{"name":"world"}}"#;
    let reply: serde_json::Value = match proto.dispatch(wire.as_bytes(), &session).await {
        Dispatched::Reply(b) => serde_json::from_slice(&b).unwrap(),
        _ => panic!("expected a reply"),
    };
    // The python body decoded GreetArgs, called the core `greet` through `call`, and returned a typed
    // GreetResult — the core encoded it back onto the wire.
    assert_eq!(reply["result"]["message"], "hi world");
}
