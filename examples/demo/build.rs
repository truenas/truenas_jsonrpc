//! Generate server bindings from this crate's `json-idl/` into `$OUT_DIR/server_gen.rs`.

fn main() {
    let json_idl = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("json-idl");
    truenas_rpc_codegen::Build::new()
        .json_idl(json_idl)
        .emit_server()
        .expect("json-idl -> server codegen failed");
}
