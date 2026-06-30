//! Generate server + client bindings from this crate's `json-idl/` into `$OUT_DIR/{server,client}_gen.rs`.

fn main() {
    let json_idl = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("json-idl");
    truenas_rpc_codegen::Build::new()
        .json_idl(json_idl.clone())
        .emit_server()
        .expect("json-idl -> server codegen failed");
    truenas_rpc_codegen::Build::new()
        .json_idl(json_idl)
        .emit_client()
        .expect("json-idl -> client codegen failed");
}
