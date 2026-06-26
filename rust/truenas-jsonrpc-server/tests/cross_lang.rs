//! Cross-language conformance: the canonical **Python** client (`truenas_pyjsonrpc_client`)
//! driving the **Rust** server over AF_UNIX — `$/negotiate` + a method call — proving the two
//! interoperate on the wire. Skipped (not failed) when the Python client / msgspec aren't
//! importable here, so it never blocks a Rust-only build; run it where Python is available with
//! `cargo test -p truenas-jsonrpc-server`.

use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use truenas_jsonrpc::{JsonRpcError, JsonRpcMethod, JsonRpcProtocol, MethodDef, RequestCtx};
use truenas_jsonrpc_server::{JsonRpcServer, UnixConfig, UnixTrust};

#[derive(Deserialize, Serialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Serialize)]
struct AddResult {
    sum: i64,
}

fn server() -> JsonRpcServer<()> {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build();
    JsonRpcServer::<()>::builder("xlang-server").protocol("main", proto).build()
}

fn python_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../python")
}

/// Whether the Python client + msgspec import under our `python/` dir.
fn python_client_available() -> bool {
    Command::new("python3")
        .env("PYTHONPATH", python_dir())
        .args(["-c", "import truenas_pyjsonrpc_client, msgspec"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn python_client_drives_rust_server() {
    if !python_client_available() {
        eprintln!("skipping cross-language test: python3 + truenas_pyjsonrpc_client not available");
        return;
    }

    let path = std::env::temp_dir().join(format!("tnrpc-xlang-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = server();
    let listener = JsonRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_unix_listener(listener, UnixTrust::Local).await })
    };

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/python_client.py");
    let sock = path.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new("python3")
            .env("PYTHONPATH", python_dir())
            .arg(&script)
            .arg(&sock)
            .output()
            .expect("spawn python client")
    })
    .await
    .unwrap();

    assert!(
        out.status.success(),
        "python client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("python stdout not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["negotiate"]["protocol"], "main");
    assert_eq!(v["negotiate"]["server"], "xlang-server");
    assert_eq!(v["add"]["sum"], 42); // the method's typed result, round-tripped through Python

    task.abort();
    let _ = std::fs::remove_file(&path);
}
