//! Generate shared types + Rust typed client + the PyO3 Python client from `examples/demo`'s spec
//! into `$OUT_DIR/{types,client,pyclient}_gen.rs`.

fn main() {
    let json_idl = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../demo/json-idl");
    let build = || truenas_rpc_codegen::Build::new().json_idl(json_idl.clone());
    build()
        .emit_types()
        .expect("json-idl -> types codegen failed");
    build()
        .emit_client()
        .expect("json-idl -> client codegen failed");
    build()
        .emit_pyclient()
        .expect("json-idl -> pyclient codegen failed");
}
