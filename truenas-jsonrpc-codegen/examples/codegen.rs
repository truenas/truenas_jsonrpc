//! Standalone codegen CLI: `cargo run --example codegen -- <server|client|openrpc> <json-idl-dir> [--out FILE]`.
//! A thin wrapper over `truenas_jsonrpc_codegen::run_cli` (the testable, covered entry point).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = truenas_jsonrpc_codegen::run_cli(&args, &mut stdout) {
        eprintln!("truenas-jsonrpc-codegen: error: {e}");
        std::process::exit(1);
    }
}
