//! Generate the shared types + server bindings from this crate's `json-idl/` into
//! `$OUT_DIR/{types,server}_gen.rs`. (The client is the generated *TypeScript* client, emitted
//! separately via the `codegen` CLI for the Node E2E — no Rust client here.)

fn main() {
    let json_idl = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("json-idl");
    truenas_rpc_codegen::Build::new()
        .json_idl(json_idl.clone())
        .emit_types()
        .expect("json-idl -> types codegen failed");
    truenas_rpc_codegen::Build::new()
        .json_idl(json_idl)
        .emit_server()
        .expect("json-idl -> server codegen failed");
}
