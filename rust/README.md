# truenas_jsonrpc — Rust implementation

A Rust port of the TrueNAS JSON-RPC 2.0 stack (the Python reference lives in
[`../python/`](../python/)). This is a Cargo workspace; the language-agnostic wire contract is
in [`../ARCHITECTURE.md`](../ARCHITECTURE.md) and the project overview in
[`../README.md`](../README.md).

## Crates

This is a workspace of focused crates, but **a consumer depends on only one of them at
runtime.** The split is internal layering (and, for two of them, a hard requirement — see
below), not a per-crate dependency you take on. What actually goes in your `Cargo.toml`:

- **`truenas-jsonrpc`** — *your only runtime dependency.* The transport-agnostic **dispatch
  core** (Python's `JSONRPCProtocol`): envelope parse/validation, the session lifecycle +
  gate, the authorize → handler → audit pipeline, the `$/` control messages, pub/sub
  (`SERVER_CLIENT` subscriptions), and filterable (query) methods. Sync handlers run on
  `spawn_blocking`; async handlers are awaited (a Rust-only addition — Python has no async
  methods). It **re-exports the filter API** (`tnfilter`, `Filtered`, `CompiledFilters`, …),
  so you `use truenas_jsonrpc::…` for filtering too.
- **`truenas-jsonrpc-codegen`** — a **build-dependency** (never a runtime one): the `json-idl/`
  → Rust generator, run from `build.rs` (see [Code generation](#code-generation-truenas-jsonrpc-codegen)).
- **`truenas-jsonrpc-pyo3`** — **optional**, only if you run `python:true` handler bodies in an
  embedded CPython interpreter. It is excluded from the workspace's default members, so a
  default `cargo build` links **zero** libpython.

The remaining crates are **internal** — pulled in transitively by `truenas-jsonrpc`, so you
don't name them. Each is self-contained with a smaller dependency set, so it's *also* usable
standalone if you want just that piece:

- **`truenas-filter`** — the `query-filters` / `query-options` **engine**, a port of the
  `truenas_pyfilter` C extension (deps: `serde` + `serde_json`). Re-exported through
  `truenas-jsonrpc`.
- **`truenas-xdr`** — a serde **XDR (RFC 4506) codec** + the TXDR binary frame (deps: `serde` +
  `thiserror`), driving the binary wire inside the core's dispatch. Its `derive` feature adds
  `#[derive(XdrEnum/XdrUnion)]`.
- **`truenas-xdr-derive`** — the proc-macro crate behind that `derive` feature. A proc-macro
  *must* be its own crate (a language rule), so you never depend on it directly — you enable
  `truenas-xdr`'s `derive` feature and the macros are re-exported for you.

## Dependency graph

Arrows are Cargo dependencies (`A --> B` means A depends on B). `[opt]` marks an optional
add-on, pulled only for that capability. A typical consumer names only `truenas-jsonrpc`
(runtime) and `truenas-jsonrpc-codegen` (build-dependency); the rest are transitive or opt-in.

```text
                          consumer service crate
                    (generated Handlers, json-idl/ spec)
                       |                          |
              build-dep|                          | runtime
                       v                          |
       +------------------------------+           |
       | truenas-jsonrpc-codegen      |           |
       | json-idl -> Rust (build time;|           |
       | output uses truenas-jsonrpc) |           |
       +------------------------------+           |
                                                  v
    +------------------------+ [opt]   +-----------------------+
    | truenas-jsonrpc-server |-------->|    truenas-jsonrpc    |
    | (AF_UNIX / TCP)        |         |    (dispatch core)    |
    +------------------------+         |                       |
    +------------------------+ [opt]   |                       |
    | truenas-jsonrpc-pyo3   |-------->|                       |
    | (embedded CPython)     |         +-----+-----------+-----+
    +------------------------+               |           |
                                            v           v
                                  +----------------+  +--------------------+
                                  | truenas-filter |  |     truenas-xdr    |
                                  | (query engine) |  |  (XDR codec+frame) |
                                  +----------------+  +---------+----------+
                                                                |
                                                       "derive" | feature
                                                                v
                                                      +---------------------+
                                                      | truenas-xdr-derive  |
                                                      | (proc-macro)        |
                                                      +---------------------+
```

`truenas-jsonrpc-codegen` runs at build time only; it is never linked into the runtime — its
*generated code* uses `truenas-jsonrpc`. `truenas-jsonrpc` re-exports the `truenas-filter` API,
so a filterable handler needs only the core crate.

## Parity & proof

A/B **differential conformance** against the Python reference is the gating proof: Python
generators (`conformance/generate.py` and `truenas-filter/conformance/generate.py`) run a
fixed corpus through the reference implementation / C oracle and emit golden JSON; the Rust
tests replay it and assert **byte-identical** results. Line coverage is gated at 100%
(`./coverage.sh`).

## Filter-engine deviations

`truenas-filter` matches the C engine (`truenas_pyfilter`) byte-for-byte for `query-filters`
and `query-options` — **with two deliberate exceptions:**

- **`query-options.select` is not supported.** `select` is the only option that *reshapes* a
  row (project / rename / sub-select fields). Omitting it keeps every returned row's shape
  stable — equal to the method's declared `entry` type — and lets the engine stay
  **read-only**: it filters, orders, and slices, then passes rows through **unchanged**.
  Concretely, `tnfilter` takes `IntoIterator<Item = Value>` and *moves* a matched row into the
  result; it never re-serializes a row per item or builds a projected object, which a
  `select`-capable dynamic engine would force. Clients that need column projection do it
  client-side.

- **The `~` regex operator is not supported.** It is the only operator whose semantics can't
  be guaranteed byte-identical — Rust's `regex` crate is not Python's `re` (no
  backreferences/lookaround, a different dialect) — and the only one that would pull in a
  regex dependency. Use `^` / `!^` / `$` / `!$` (starts/ends-with) or `in` / `rin`
  (containment) instead, or filter client-side.

Both are parity gaps vs. the Python/middleware `filter_list`. Everything else is identical to
the oracle: the remaining filter operators (`=` `!=` `>` `>=` `<` `<=` `in` `nin` `rin` `rnin`
`^` `!^` `$` `!$`, incl. the `C` case-insensitive prefix), `OR`/`AND` nesting, dotted /
indexed / `*`-wildcard / escaped-dot path traversal, `order_by` (`-` / `nulls_first:` /
`nulls_last:`, multi-key, stable), `get`, `count`, `offset`, `limit`, and the Python
comparison semantics (numeric tower; `==`/`!=` total; `<`/`>`/… raise on incomparable operands).

## Build & test

```sh
cargo test --all-features --locked          # spine + pub/sub + filterable + both A/B goldens
cargo clippy --all-targets --all-features -- -D warnings
./coverage.sh 100                            # native source-based coverage, gated at 100%
```

Regenerating the golden corpora (requires the Python reference + the installed
`truenas_pyfilter`):

```sh
python3 conformance/generate.py                  # protocol A/B golden
python3 truenas-filter/conformance/generate.py   # filter-engine A/B golden
```

## Code generation (`truenas-jsonrpc-codegen`)

A consumer defines a `json-idl/` directory of JSON-Schema specs and generates typed server
bindings (structs + a `Handlers` trait + `register()`), a typed client, and an OpenRPC
document — via a `build.rs` build-dependency (prost/tonic-build style):

```rust
// server-gen/build.rs
truenas_jsonrpc_codegen::Build::new().json_idl("../json-idl").emit_server().unwrap();
```

See `truenas-jsonrpc-codegen/README.md` for the dialect, the consumer crate layout
(`json-idl/` + `server-gen` + `client-gen` + your own crate), and the packaging caveat. The
generated OpenRPC is byte-for-byte equivalent (A/B-tested) to `api-specs/gen.py`'s output.
