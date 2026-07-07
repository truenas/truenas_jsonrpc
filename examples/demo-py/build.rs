//! Generate the demo's msgspec Python modules — `demo_types.py` / `demo_client.py` /
//! `demo_server.py` — from `examples/demo`'s spec into `$OUT_DIR`. The integration tests add
//! `$OUT_DIR` to `sys.path` and import them.

fn main() {
    let json_idl = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../demo/json-idl");
    let build = || truenas_rpc_codegen::Build::new().json_idl(json_idl.clone());
    build()
        .emit_py_structs()
        .expect("json-idl -> py structs codegen failed");
    build()
        .emit_py_client()
        .expect("json-idl -> py client codegen failed");
    build()
        .emit_py_server()
        .expect("json-idl -> py server codegen failed");
}
