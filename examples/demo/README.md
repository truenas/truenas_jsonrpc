# demo-consumer

A worked example of the documented consumer layout: a crate that generates shared **types** +
**server** + **client** bindings from a `json-idl/` spec at build time, dispatches through the live
`truenas-rpc` core, and drives the generated client against a live server. It is the end-to-end
reference for `truenas-rpc-codegen`, not a library to depend on.

## Layout

- `json-idl/demo.json` — the interface definition (the spec).
- `build.rs` — runs three codegen steps: `.emit_types()` (the shared `$defs` structs →
  `types_gen.rs`), `.emit_server()` (a `Handlers` trait + `register` → `server_gen.rs`), and
  `.emit_client()` (the typed `DemoClient` → `client_gen.rs`). The `json-idl` dir is resolved
  against `CARGO_MANIFEST_DIR`.
- `src/lib.rs` — `include!`s all three generated modules (types first, then server + client),
  implements the generated `Handlers` trait (a missing/mistyped handler is a compile error), and has
  tests that dispatch through the core **and** drive the generated `DemoClient` against a live server
  over a real socket (plain calls, a filterable query, a raw-fd transfer). A `standalone_client`
  module shows a client compiling from just `types_gen.rs` + `client_gen.rs` — no server bindings.

## Run

```sh
cargo test -p demo-consumer
```

## Dependencies

`truenas-rpc` (runtime) and `truenas-audit` (the audit backend — `demo.json` has no `audit` block,
so auditing is **on by default** and the generated `register` wires a kernel-audit sink), plus
`truenas-rpc-codegen` (build-dependency) and `serde` / `serde_json`. The end-to-end test additionally
dev-depends on `truenas-rpc-server` + `truenas-rpc-client` (a live server + the generated client). No
generated code is committed — it is produced into `OUT_DIR` on each build.
