# truenas-jsonrpc-codegen

Generate Rust **server bindings**, a typed **client**, and an **OpenRPC** document from a
`json-idl/` directory — the spec-first codegen for the TrueNAS JSON-RPC stack. It is the
Rust analogue of the cross-language `api-specs/gen.py`: the json-idl is the source of truth,
and this crate emits the boilerplate. It emits source **text** (it is not a proc-macro), so
its only dependencies are `serde` + `serde_json`.

## The json-idl dialect

A spec is a single JSON file (JSON-Schema draft 2020-12 + a few extensions):

```jsonc
{
  "name": "myservice", "version": "1.0.0",
  "$defs": {                                  // named request/result/entry types
    "LoginArgs": { "type": "object",
      "properties": { "user": {"type":"string"},
                      "password": {"type":"string", "secret": true} },
      "required": ["user","password"], "additionalProperties": false }
  },
  "methods": {                                // wire-name -> method
    "login": { "handler": "login", "params": {"$ref":"#/$defs/LoginArgs"},
               "result": {"$ref":"#/$defs/LoginResult"},
               "audit": true, "auditMessage": "user login" }
  }
}
```

Per-method keys: `handler` (the Rust handler symbol — required), `params` (required `$ref`),
`result` / `entry` / `notifies` (`$ref`s), `summary`, `audit` / `auditMessage`, `preAuth`,
`cancellable`, `roles`, `direction` (`client_server` | `server_client`), `filterable`, `xdr`
+ `xdr_id` (> 1000), `python`. Per-field: `secret`, `enum` (string), `default`. Validation
mirrors `gen.py`: `filterable ⇒ entry` (and no `result`); `xdr ⇒ xdr_id` (unique, > 1000);
`python ⇒ result` (and not combinable with filterable/xdr/server_client); every `$ref` must
be `#/$defs/<Name>` and resolve. Type mapping: object→struct, `$ref`→named, string→`String`,
integer→`i64`, number→`f64`, boolean→`bool`, array→`Vec<T>`, string-enum→a generated `enum`,
`secret`→`truenas_jsonrpc::Secret<T>`; `required`→`T`, `default`→`T` (+ `#[serde(default)]`),
otherwise→`Option<T>`.

## Consumer layout

```
my-truenas-service/
├── json-idl/              # the spec(s) — the single source of truth
│   └── myservice.json
├── server-gen/            # generated server code (build.rs → emit_server)
│   ├── build.rs
│   └── src/lib.rs         #   include!(concat!(env!("OUT_DIR"), "/server_gen.rs"));
├── client-gen/            # generated client code (build.rs → emit_client + emit_openrpc)
│   ├── build.rs
│   └── src/lib.rs         #   include!(concat!(env!("OUT_DIR"), "/client_gen.rs"));
└── server/                # YOUR crate: impl Handlers + wire up JsonRpcProtocol
    └── src/main.rs
```

`server-gen/Cargo.toml`:

```toml
[dependencies]
truenas-jsonrpc = "..."        # the dispatch core (and serde, for the derives)
serde = { version = "1", features = ["derive"] }

[build-dependencies]
truenas-jsonrpc-codegen = "..."
```

`server-gen/build.rs`:

```rust
fn main() {
    let json_idl = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../json-idl");
    truenas_jsonrpc_codegen::Build::new()
        .json_idl(json_idl)
        .emit_server()                 // writes $OUT_DIR/server_gen.rs
        .expect("json-idl -> server codegen failed");
    // emit_server() also prints cargo:rerun-if-changed for the dir + each *.json.
}
```

`server-gen/src/lib.rs`:

```rust
include!(concat!(env!("OUT_DIR"), "/server_gen.rs"));
```

`server/src/main.rs` — the generated `Handlers<S>` trait is your binding point (a
missing/mistyped handler is a **compile error**, the Rust analogue of Zig's `H.<handler>`):

```rust
use std::sync::Arc;
use truenas_jsonrpc::{JsonRpcProtocol, RequestCtx, JsonRpcError};
use server_gen::{register, Handlers, LoginArgs, LoginResult};

struct MyHandlers;
impl Handlers<MyState> for MyHandlers {
    fn login(&self, req: LoginArgs, _cx: &RequestCtx<MyState>) -> Result<LoginResult, JsonRpcError> {
        Ok(LoginResult { /* ... */ })
    }
    // ... one method per non-subscription, non-python RPC ...
}

fn build() -> JsonRpcProtocol<MyState> {
    register(JsonRpcProtocol::<MyState>::builder("myservice", "1.0.0"), Arc::new(MyHandlers))
        .expect("register")
        .authorizer(/* ... */)
        .build()
}
```

`client-gen` is symmetric (`.emit_client()`, plus `.emit_openrpc()` to also drop an
`openrpc.json` for `$/describe`). The generated client is transport-agnostic: implement the
emitted `Transport` trait over your connection (WebSocket / Unix / TCP) and call the typed
`async fn` per method.

## The `Build` API

- `Build::new().json_idl(dir).emit_server()` → `$OUT_DIR/server_gen.rs`
- `…​.emit_client()` → `$OUT_DIR/client_gen.rs`
- `…​.emit_openrpc()` → `$OUT_DIR/openrpc.json`

A relative `json_idl` is resolved against `CARGO_MANIFEST_DIR` (a build script's CWD is not
reliable). Each `emit_*` prints `cargo:rerun-if-changed` for the directory **and** every
discovered `*.json`, so edits trigger regeneration. `.out_dir(dir)` overrides `$OUT_DIR`.

A standalone CLI is shipped as an example:
`cargo run --example codegen -- <server|client|openrpc> <json-idl-dir> [--out FILE]`.

### Packaging caveat

`server-gen` / `client-gen` read a **sibling** `../json-idl` from their build script, which
works for workspace / path-dependency builds (the common case) but **not** for
`cargo package` (which copies only the crate's own directory). Treat these as internal,
unpublished crates. If you must package one, either move `json-idl/` inside the gen crate and
add `include = ["json-idl/**"]` to its `Cargo.toml`, or commit the generated `.rs` and skip
the build script for the packaged build.

## Known parity gaps (v1)

- **xdr methods** bind on both the JSON and XDR wires (`MethodDef::xdr(id)`); the binary-wire
  path's v1 limitations are documented in `truenas-jsonrpc`.
- **python methods** are registered (`.python_method`) and listed in a generated
  `PYTHON_METHODS` table, but their bodies run via the `truenas-jsonrpc-pyo3` bridge — they
  are **not** in the `Handlers` trait.
- **filterable** queries drop `query-options.select` and the `~` regex operator (a permanent,
  documented divergence in `truenas-filter`).
