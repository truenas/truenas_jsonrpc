# demo-consumer

A worked example of the documented consumer layout: a crate that generates server bindings
from a `json-idl/` spec at build time and dispatches through the live `truenas-jsonrpc` core.
It is the end-to-end reference for `truenas-jsonrpc-codegen`, not a library to depend on.

## Layout

- `json-idl/demo.json` — the interface definition (the spec).
- `build.rs` — runs `truenas_jsonrpc_codegen::Build::new().json_idl("json-idl").emit_server()`,
  emitting `$OUT_DIR/server_gen.rs` (structs + a `Handlers` trait + `register()`). The
  `json-idl` dir is resolved against `CARGO_MANIFEST_DIR`.
- `src/lib.rs` — `include!`s the generated code, implements the generated `Handlers` trait
  (a missing or mistyped handler is a compile error), registers it on a `JsonRpcProtocol`, and
  has tests that `dispatch` requests through it.

## Run

```sh
cargo test -p demo-consumer
```

## Dependencies

`truenas-jsonrpc` (runtime) + `truenas-jsonrpc-codegen` (build-dependency), plus `serde` /
`serde_json`. No generated code is committed — it is produced into `OUT_DIR` on each build.
