//! `truenas-jsonrpc-codegen` — generate Rust server bindings, a typed client, and an
//! OpenRPC document from a json-idl directory.
//!
//! Used as a **build-dependency** from a consumer's `server-gen` / `client-gen` crate via
//! [`Build`] (the prost/tonic-build pattern), or as a standalone CLI (`run_cli`, shipped as
//! the `codegen` example). It emits source TEXT (it is not a proc-macro), so its only
//! dependencies are `serde` + `serde_json`. See the crate README for the consumer layout.

mod emit_client;
mod emit_openrpc;
mod emit_server;
mod error;
mod model;
mod naming;
mod typemap;
mod validate;

use std::io::Write;
use std::path::{Path, PathBuf};

pub use error::{CodegenError, Result};

/// A parsed + validated json-idl spec (one logical service).
#[derive(Debug)]
pub struct Spec {
    raw: model::Spec,
    sources: Vec<PathBuf>,
    origin: String,
}

impl Spec {
    /// Parse + validate a single in-memory spec. `origin` labels it in error messages.
    pub fn parse(json: &str, origin: &str) -> Result<Spec> {
        let raw: model::Spec = serde_json::from_str(json)
            .map_err(|e| CodegenError::at(origin, format!("invalid json-idl: {e}")))?;
        validate::validate(&raw, origin)?;
        Ok(Spec { raw, sources: Vec::new(), origin: origin.to_string() })
    }

    /// Load + validate every `*.json` in `dir` (lexicographic order), merging their `$defs`
    /// and `methods` into one service (`name`/`version` come from the first file). Errors on
    /// a duplicate `$def`/method across files.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Spec> {
        let dir = dir.as_ref();
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(CodegenError::new(format!("no *.json json-idl specs in {}", dir.display())));
        }
        let mut merged: Option<model::Spec> = None;
        for f in &files {
            let text = std::fs::read_to_string(f)?;
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("<spec>").to_string();
            let parsed: model::Spec = serde_json::from_str(&text)
                .map_err(|e| CodegenError::at(name.clone(), format!("invalid json-idl: {e}")))?;
            match &mut merged {
                None => merged = Some(parsed),
                Some(acc) => merge(acc, parsed, &name)?,
            }
        }
        let raw = merged.expect("files is non-empty");
        let origin = dir.display().to_string();
        validate::validate(&raw, &origin)?;
        Ok(Spec { raw, sources: files, origin })
    }

    /// The source files (for `build.rs` `cargo:rerun-if-changed`).
    pub fn source_files(&self) -> &[PathBuf] {
        &self.sources
    }
}

fn merge(acc: &mut model::Spec, other: model::Spec, origin: &str) -> Result<()> {
    for (k, v) in other.defs.0 {
        if acc.defs.contains_key(&k) {
            return Err(CodegenError::at(origin, format!("duplicate $def {k:?} across spec files")));
        }
        acc.defs.0.push((k, v));
    }
    for (k, v) in other.methods.0 {
        if acc.methods.contains_key(&k) {
            return Err(CodegenError::at(origin, format!("duplicate method {k:?} across spec files")));
        }
        acc.methods.0.push((k, v));
    }
    Ok(())
}

/// Emit the server module (typed structs + `Handlers` trait + `register()`).
pub fn generate_server(spec: &Spec) -> Result<String> {
    emit_server::generate(&spec.raw, &spec.origin)
}

/// Emit the typed async client module (a `Transport` trait + one method per RPC).
pub fn generate_client(spec: &Spec) -> Result<String> {
    emit_client::generate(&spec.raw, &spec.origin)
}

/// Emit the OpenRPC 1.3.2 service description (the `$/describe` payload + client contract).
pub fn generate_openrpc(spec: &Spec) -> Result<String> {
    emit_openrpc::generate(&spec.raw, &spec.origin)
}

// --- build.rs helper ---------------------------------------------------------

/// A `build.rs` helper (prost/tonic-build style): point it at a `json-idl/` dir and emit one
/// of the artifacts into `OUT_DIR`.
///
/// ```no_run
/// // build.rs
/// truenas_jsonrpc_codegen::Build::new()
///     .json_idl("../json-idl")
///     .emit_server()
///     .expect("json-idl -> server codegen failed");
/// ```
#[derive(Default)]
pub struct Build {
    json_idl: Option<PathBuf>,
    out_dir: Option<PathBuf>,
}

impl Build {
    /// A fresh builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// The json-idl directory. A relative path is resolved against `CARGO_MANIFEST_DIR`
    /// (a build script's working directory is not reliable).
    pub fn json_idl(mut self, dir: impl Into<PathBuf>) -> Self {
        self.json_idl = Some(dir.into());
        self
    }

    /// Override the output directory (default: `OUT_DIR`).
    pub fn out_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.out_dir = Some(dir.into());
        self
    }

    /// Emit `server_gen.rs`; returns its path (for `include!`).
    pub fn emit_server(self) -> Result<PathBuf> {
        self.emit("server_gen.rs", generate_server)
    }

    /// Emit `client_gen.rs`; returns its path.
    pub fn emit_client(self) -> Result<PathBuf> {
        self.emit("client_gen.rs", generate_client)
    }

    /// Emit `openrpc.json`; returns its path.
    pub fn emit_openrpc(self) -> Result<PathBuf> {
        self.emit("openrpc.json", generate_openrpc)
    }

    fn resolved_json_idl(&self) -> Result<PathBuf> {
        let p =
            self.json_idl.clone().ok_or_else(|| CodegenError::new("Build::json_idl(..) was not set"))?;
        if p.is_absolute() {
            Ok(p)
        } else if let Some(manifest) = std::env::var_os("CARGO_MANIFEST_DIR") {
            Ok(PathBuf::from(manifest).join(p))
        } else {
            Ok(p)
        }
    }

    fn resolved_out(&self) -> Result<PathBuf> {
        if let Some(o) = &self.out_dir {
            return Ok(o.clone());
        }
        std::env::var_os("OUT_DIR")
            .map(PathBuf::from)
            .ok_or_else(|| CodegenError::new("OUT_DIR is not set (call from build.rs, or set out_dir)"))
    }

    fn emit(&self, file: &str, generate: impl Fn(&Spec) -> Result<String>) -> Result<PathBuf> {
        let dir = self.resolved_json_idl()?;
        let spec = Spec::load_dir(&dir)?;
        let code = generate(&spec)?;
        let path = self.resolved_out()?.join(file);
        std::fs::write(&path, code)?;
        // Regenerate when the dir (files added/removed) or any source file changes.
        println!("cargo:rerun-if-changed={}", dir.display());
        for f in spec.source_files() {
            println!("cargo:rerun-if-changed={}", f.display());
        }
        Ok(path)
    }
}

// --- CLI (used by the `codegen` example) -------------------------------------

/// Run the codegen CLI: `<server|client|openrpc> <json-idl-dir> [--out FILE]`. Output goes
/// to `FILE` (if `--out` given) or is written to `stdout`.
pub fn run_cli(args: &[String], stdout: &mut dyn Write) -> Result<()> {
    let sub = args.first().map(String::as_str);
    let dir = args.get(1).ok_or_else(|| {
        CodegenError::new("usage: <server|client|openrpc> <json-idl-dir> [--out FILE]")
    })?;
    let out_file = match args.get(2).map(String::as_str) {
        Some("--out") => Some(
            args.get(3)
                .ok_or_else(|| CodegenError::new("--out requires a FILE argument"))?
                .clone(),
        ),
        Some(other) => return Err(CodegenError::new(format!("unexpected argument {other:?}"))),
        None => None,
    };
    let spec = Spec::load_dir(dir)?;
    let text = match sub {
        Some("server") => generate_server(&spec)?,
        Some("client") => generate_client(&spec)?,
        Some("openrpc") => generate_openrpc(&spec)?,
        other => {
            return Err(CodegenError::new(format!(
                "unknown subcommand {other:?} (expected server|client|openrpc)"
            )))
        }
    };
    match out_file {
        Some(f) => std::fs::write(f, text)?,
        None => stdout.write_all(text.as_bytes())?,
    }
    Ok(())
}
