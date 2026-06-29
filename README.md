# truenas_rpc

A JSON-RPC 2.0 **server/client protocol stack** for TrueNAS — a transport-agnostic dispatch
core, a few transports, and a matching client — implemented in Rust as a Cargo workspace. The
language-agnostic wire contract is in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## What it implements

A refinement of JSON-RPC 2.0 designed for long-lived, authenticated, multiplexed connections: a
transport-agnostic **dispatch core** (`bytes` in → `bytes`/`None` out) with pluggable transports
and a back channel for server→client messages.

### The protocol

Every message is a single JSON-RPC 2.0 object; the transport frames each one (a 4-byte length
prefix on AF_UNIX/TCP, or one WebSocket message — see [Transports](#transports)). There are four
envelope shapes:

```jsonc
// request — `id` is a UUID string; `params` is a by-name object
{"jsonrpc": "2.0", "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "method": "pool.create", "params": {"name": "tank"}}

// success response — correlated by the same `id`
{"jsonrpc": "2.0", "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "result": {"id": 7, "name": "tank"}}

// error response — same `id`
{"jsonrpc": "2.0", "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "error": {"code": -32000, "message": "Not authorized", "data": null}}

// notification — no `id`, no reply (the server→client back channel)
{"jsonrpc": "2.0", "method": "pool.events", "params": {"name": "tank", "state": "ONLINE"}}
```

Deliberate refinements of JSON-RPC 2.0: **UUID-only ids** (a present `id` must be a canonical UUID
string), **by-name params only** (`params` must be an object — no positional arrays), and the
**reserved `$/` and `rpc.` prefixes** (only the control messages below may use `$/`). JSON-RPC 2.0
**batch** (a top-level array) is supported on the JSON wire — an *empty* array is `INVALID_REQUEST`
per spec.

**Control messages** (`$/` namespace, handled by the server/runtime — not application methods):

| message | dir | params → result |
|---|---|---|
| `$/negotiate` | C→S | `{protocol}` → `{protocol, server, available[]}` — bind one of the server's named protocols (unauthenticated) |
| `$/sessionSetup`, `$/sessionSetupContinue` | C→S | `{credentials…}` → the auth result; advances the session lifecycle (the *Continue* step is multi-step / 2FA) |
| `$/sessionClose` | C→S | — → end the session (`CLOSED`) |
| `$/serverInfo` | C→S | — → server identity (unauthenticated, opt-in) |
| `$/progress` | S→C | `{id, percent?, description?, extra?}` — progress for the in-flight request `id` (a notification) |
| `$/cancelRequest` | C→S | `{target_id}` → `true` — cancel an in-flight request **or** drop a subscription, by id |
| `$/transferReady` → `$/transferGo` | S→C, C→S | `{id, direction, result}` / `{id}` — handshake for the raw socket operations below |

**Session lifecycle.** A connection sends `$/negotiate` to pick a protocol, then `$/sessionSetup`
(+ `$/sessionSetupContinue` for multi-step / 2FA) to authenticate, then issues calls. The session
advances `NONE → INIT → ESTABLISHED → CLOSED`; once session setup is configured, a normal method
before `ESTABLISHED` is rejected `SESSION_NOT_ESTABLISHED`. Each call also runs an
**authorization** check and an opt-in **audit** record (fields marked secret are redacted in the
audit view).

**Pub/sub** reuses the request/notification shapes: a *topic* is a server→client method;
**subscribing** is a normal request to it (the `result` is a subscription UUID), and each
**publish** is a notification `{"method": "<topic>", "params": <payload>}` delivered to that
connection. `$/cancelRequest` with the subscription id unsubscribes.

**Query methods.** A method may declare its result a filterable list. Such a method takes two
optional by-name params — `query-filters` (a condition list, e.g.
`[["name", "=", "tank"], ["OR", [...]]]`) and `query-options` (`select`, `order_by`, `offset`,
`limit`, plus `count` → an integer and `get` → a single record) — that narrow the result *at the
source*. Omitting them returns the full list, so it is additive. The filter/option grammar is the
TrueNAS middleware `query` syntax; the full operator and option tables are in
**[ARCHITECTURE.md → Query methods](ARCHITECTURE.md#7-query-methods-filtering)**.

> **Note:** this stack intentionally omits `query-options.select` (column projection) and the `~`
> regex operator; all other filter/option behavior matches the middleware byte-for-byte. See
> [Filter-engine deviations](#filter-engine-deviations).

**Raw socket operations.** Two operations step *outside* JSON-RPC framing to do raw I/O directly on
the established socket, coordinated by the `$/transferReady`/`$/transferGo` handshake (the reader
pauses, the operation runs, then normal JSON-RPC resumes). They are distinct:

- **Byte-stream transfer** — a method's handler is handed the **connection's own socket fd** to
  read or write a self-delimiting byte stream directly on the wire (e.g. a `zfs send`/`recv`
  stream, via `sendfile`/`recvfile`). Requires a plaintext fd → a **plain or kernel-TLS**
  connection (AF_UNIX **or** TCP); rejected over userspace TLS or WebSocket.
- **File-descriptor passing** — a handler passes **other open file descriptors** to the peer as
  `SCM_RIGHTS` ancillary data; the peer receives new fds for the same open files (the
  privilege-broker pattern). **AF_UNIX only** (`SCM_RIGHTS` does not exist elsewhere).

**Error object** — `{"code", "message", "data"?}`. Codes (JSON-RPC standard + LSP-derived):

| code | meaning |
|------|---------|
| `-32700` | parse error — malformed JSON |
| `-32600` | invalid request — bad envelope (non-object, non-UUID id, empty array) |
| `-32601` | method not found |
| `-32602` | invalid params — failed by-name decode/validation |
| `-32603` | internal error — unexpected fault |
| `-32000` | not authorized — the authorizer denied the call |
| `-32002` | session not established — a normal method before `ESTABLISHED`, or on `CLOSED` |
| `-32800` | request cancelled — via `$/cancelRequest` |
| `-32803` | request failed — a valid, authorized request failed for an expected reason |

The per-message dispatch order and full semantics are in
**[ARCHITECTURE.md](ARCHITECTURE.md)**.

### Transports

| Transport | Framing | Notes |
|-----------|---------|-------|
| AF_UNIX   | 4-byte big-endian length + JSON | peer credentials (uid/gid/pid) |
| TCP       | 4-byte big-endian length + JSON | optional TLS; **kernel-TLS** keeps the fd plaintext for zero-copy transfers |
| WebSocket | one JSON-RPC message per frame  | `ws://` / `wss://`; optional dependency; no raw-fd transfers |

## Architecture

The stack splits into a transport-agnostic **dispatch core** and a **transport layer** around it.
The core is a single seam — a request message in, a response message out (or nothing, for a
notification) — plus an outbound queue for server→client messages. It owns no sockets, event loop,
or threads; everything around it is the transport's job. The full layer model is in
[ARCHITECTURE.md → Layers](ARCHITECTURE.md#layers).

| Dispatch core (`truenas-rpc`) | Transport layer (`truenas-rpc-server`) |
|---|---|
| envelope parse + validation; the dispatch state machine | connection accept; framing; the event / read loop |
| method routing; the authorize → handler → audit pipeline | the `session → connection` registry and message routing |
| session lifecycle + gate; response/notification construction | draining the outbound queue to the wire; backpressure |

## Crates

This is a workspace of focused crates, but **a consumer depends on only one of them at runtime.**
The split mirrors the [layer stack](ARCHITECTURE.md#layers) (and, for two of them, is a hard
requirement — see below), not a per-crate dependency you take on. What actually goes in your
`Cargo.toml`:

- **`truenas-rpc`** — *your only runtime dependency.* The transport-agnostic **dispatch core**:
  envelope parse/validation, the session lifecycle + gate, the authorize → handler → audit
  pipeline, the `$/` control messages, pub/sub (`SERVER_CLIENT` subscriptions), and filterable
  (query) methods. Sync handlers run on `spawn_blocking`; async handlers are awaited. It
  **re-exports the filter API** (`tnfilter`, `Filtered`, `CompiledFilters`, …), so you
  `use truenas_rpc::…` for filtering too.
- **`truenas-rpc-codegen`** — a **build-dependency** (never a runtime one): the `json-idl/`
  → Rust generator, run from `build.rs` (see [Code generation](#code-generation-truenas-rpc-codegen)).
- **`truenas-rpc-pyo3`** — **optional**, only if you run `python:true` handler bodies in an
  embedded CPython interpreter. It is excluded from the workspace's default members, so a default
  `cargo build` links **zero** libpython.

The remaining crates are **internal** — pulled in transitively by `truenas-rpc`, so you don't
name them. Each is self-contained with a smaller dependency set, so it's *also* usable standalone
if you want just that piece:

- **`truenas-filter`** — the `query-filters` / `query-options` **engine** (deps: `serde` +
  `serde_json`), matching the TrueNAS middleware's `truenas_pyfilter` C filter engine. Re-exported
  through `truenas-rpc`.
- **`truenas-xdr`** — a serde **XDR (RFC 4506) codec** + the TXDR binary frame (deps: `serde` +
  `thiserror`), driving the binary wire inside the core's dispatch. Its `derive` feature adds
  `#[derive(XdrEnum/XdrUnion)]`.
- **`truenas-xdr-derive`** — the proc-macro crate behind that `derive` feature. A proc-macro
  *must* be its own crate (a language rule), so you never depend on it directly — you enable
  `truenas-xdr`'s `derive` feature and the macros are re-exported for you.

## Dependency graph

Arrows are Cargo dependencies (`A --> B` means A depends on B). `[opt]` marks an optional add-on,
pulled only for that capability. A typical consumer names only `truenas-rpc` (runtime) and
`truenas-rpc-codegen` (build-dependency); the rest are transitive or opt-in.

```text
                          consumer service crate
                    (generated Handlers, json-idl/ spec)
                       |                          |
              build-dep|                          | runtime
                       v                          |
       +------------------------------+           |
       | truenas-rpc-codegen      |           |
       | json-idl -> Rust (build time;|           |
       | output uses truenas-rpc) |           |
       +------------------------------+           |
                                                  v
    +------------------------+ [opt]   +-----------------------+
    | truenas-rpc-server |-------->|    truenas-rpc    |
    | (AF_UNIX / TCP)        |         |    (dispatch core)    |
    +------------------------+         |                       |
    +------------------------+ [opt]   |                       |
    | truenas-rpc-pyo3   |-------->|                       |
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

`truenas-rpc-codegen` runs at build time only; it is never linked into the runtime — its
*generated code* uses `truenas-rpc`. `truenas-rpc` re-exports the `truenas-filter` API, so
a filterable handler needs only the core crate.

## Parity & proof

**Differential conformance** is the gating proof: the conformance tests replay a committed, frozen
golden corpus (`truenas-rpc/tests/conformance/golden.json` and
`truenas-filter/tests/conformance/golden.json`) and assert **byte-identical** results across the
dispatch core and the filter engine. Line coverage is gated at 100% (`./coverage.sh`).

## Filter-engine deviations

`truenas-filter` matches the TrueNAS middleware's `truenas_pyfilter` C engine byte-for-byte for
`query-filters` and `query-options` — **with two deliberate exceptions:**

- **`query-options.select` is not supported.** `select` is the only option that *reshapes* a row
  (project / rename / sub-select fields). Omitting it keeps every returned row's shape stable —
  equal to the method's declared `entry` type — and lets the engine stay **read-only**: it filters,
  orders, and slices, then passes rows through **unchanged**. Concretely, `tnfilter` takes
  `IntoIterator<Item = Value>` and *moves* a matched row into the result; it never re-serializes a
  row per item or builds a projected object, which a `select`-capable dynamic engine would force.
  Clients that need column projection do it client-side.

- **The `~` regex operator is not supported.** It is the only operator whose semantics can't be
  guaranteed byte-identical — Rust's `regex` crate is a different dialect (no
  backreferences/lookaround) — and the only one that would pull in a regex dependency. Use `^` /
  `!^` / `$` / `!$` (starts/ends-with) or `in` / `rin` (containment) instead, or filter
  client-side.

Both are parity gaps vs. the TrueNAS middleware `filter_list`. Everything else is identical to the
oracle: the remaining filter operators (`=` `!=` `>` `>=` `<` `<=` `in` `nin` `rin` `rnin` `^` `!^`
`$` `!$`, incl. the `C` case-insensitive prefix), `OR`/`AND` nesting, dotted / indexed /
`*`-wildcard / escaped-dot path traversal, `order_by` (`-` / `nulls_first:` / `nulls_last:`,
multi-key, stable), `get`, `count`, `offset`, `limit`, and the middleware comparison semantics
(numeric tower; `==`/`!=` total; `<`/`>`/… raise on incomparable operands).

## Build & test

```sh
cargo test --all-features --locked          # spine + pub/sub + filterable + both A/B goldens
cargo clippy --all-targets --all-features -- -D warnings
./coverage.sh 100                            # native source-based coverage, gated at 100%
```

The golden corpora are committed, frozen fixtures — the conformance tests replay them with no
external dependency.

## Code generation (`truenas-rpc-codegen`)

A consumer defines a `json-idl/` directory of JSON-Schema specs and generates typed server
bindings (structs + a `Handlers` trait + `register()`), a typed client, and an OpenRPC document —
via a `build.rs` build-dependency (prost/tonic-build style):

```rust
// server-gen/build.rs
truenas_rpc_codegen::Build::new().json_idl("../json-idl").emit_server().unwrap();
```

The generated server **audits on by default** — every `audit: true` method (and the `$/` control
ops) emits to the Linux kernel audit subsystem via `truenas-audit`; a top-level `audit` block in
the spec configures the service / queue bound or turns it off (`audit.enabled = false`).

See `truenas-rpc-codegen/README.md` for the dialect, the consumer crate layout (`json-idl/` +
`server-gen` + `client-gen` + your own crate), and the packaging caveat.

## References

- [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification) — the base protocol this
  stack refines.
- [Language Server Protocol 3.18 specification](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/)
  — inspiration for the `$/` control-message namespace, progress, cancellation, and the extended
  error-code ranges.
- This stack's protocol architecture — component boundary, dispatch flow, control messages, the
  transfer handshake, error codes: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## License

MIT — see [LICENSE](LICENSE).
