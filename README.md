# truenas_rpc

A JSON-RPC 2.0 **server/client protocol stack** for TrueNAS — a transport-agnostic dispatch
core, a few transports, and a matching client — implemented in Rust as a Cargo workspace. The
language-agnostic wire contract is in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Quickstart: build an RPC service

A service is **spec-first**: you describe an interface in `json-idl`, code generation turns it into a
typed `Handlers` trait plus a matching typed client, and you implement the trait. The generated trait
*is* the contract — a missing or mistyped handler is a compile error, not a runtime surprise.

```text
my-greeter/
├── Cargo.toml
├── build.rs            # runs codegen
├── json-idl/
│   └── greeter.json    # the interface — the source of truth
└── src/
    └── lib.rs          # impl the generated Handlers
```

**1. Describe the interface** (`json-idl/greeter.json`) — one method, its argument and result types:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "name": "greeter",
  "version": "1.0.0",
  "$defs": {
    "GreetArgs":   { "type": "object", "properties": { "name":    { "type": "string" } }, "required": ["name"],    "additionalProperties": false },
    "GreetResult": { "type": "object", "properties": { "message": { "type": "string" } }, "required": ["message"], "additionalProperties": false }
  },
  "methods": {
    "greet": {
      "summary": "Greet by name.",
      "handler": "greet",
      "params": { "$ref": "#/$defs/GreetArgs" },
      "result": { "$ref": "#/$defs/GreetResult" }
    }
  }
}
```

**2. Wire up codegen** (`build.rs`) — emits three modules into `OUT_DIR` at build time; nothing
generated is committed:

```rust
// build.rs
fn main() {
    let json_idl = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("json-idl");
    let build = || truenas_rpc_codegen::Build::new().json_idl(json_idl.clone());
    build().emit_types().expect("types codegen");    // shared $defs structs  -> types_gen.rs
    build().emit_server().expect("server codegen");  // Handlers + register   -> server_gen.rs
    build().emit_client().expect("client codegen");  // the typed client      -> client_gen.rs
}
```

`Cargo.toml` (these crates aren't published — depend on them by `path` or `git`):

```toml
[dependencies]
truenas-rpc        = { path = "…" }   # dispatch core: JsonRpcProtocol, RequestCtx, JsonRpcError
truenas-rpc-server = { path = "…" }   # serve the protocol over a socket
truenas-rpc-client = { path = "…" }   # the generated client (drop if callers live in another crate)
truenas-audit      = { path = "…" }   # audit sink — auditing is on by default
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
tokio      = { version = "1", features = ["full"] }

[build-dependencies]
truenas-rpc-codegen = { path = "…" }
```

**3. Implement the handlers** (`src/lib.rs`) — `include!` the generated modules (**types first**),
then fill in the trait:

```rust
#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/types_gen.rs"));   // the $defs structs
    include!(concat!(env!("OUT_DIR"), "/server_gen.rs"));  // Handlers trait + register()
    include!(concat!(env!("OUT_DIR"), "/client_gen.rs"));  // the typed GreeterClient
}
pub use generated::*;

use std::sync::Arc;
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, RequestCtx};

struct GreetHandlers;

impl Handlers<()> for GreetHandlers {
    fn greet(&self, req: GreetArgs, _cx: &RequestCtx<()>) -> Result<GreetResult, JsonRpcError> {
        Ok(GreetResult { message: format!("hi {}", req.name) })
    }
}

/// The dispatchable protocol — `register` binds every method the IDL declares to a handler.
pub fn proto() -> JsonRpcProtocol<()> {
    register(JsonRpcProtocol::<()>::builder("greeter", "1.0.0"), Arc::new(GreetHandlers))
        .expect("register")
        .build()
}
```

**4. Serve it** — over a trusted-local AF_UNIX socket (runs forever; spawn it, or `tokio::join!`
several transports):

```rust
use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

let server = TruenasRpcServer::<()>::builder("greeter").protocol("greeter", proto()).build();
server.serve_unix(UnixConfig::new("/run/greeter.sock"), JsonRpc).await?;
```

**5. Call it** — from a caller (its own crate, or this crate's tests) via the generated client (the
spec `name` → `GreeterClient`):

```rust
use truenas_rpc_client::{ClientConfig, Endpoint, JsonRpcClient};

let (engine, _negotiated, _notifications) =
    JsonRpcClient::connect_negotiate(&Endpoint::unix("/run/greeter.sock"), "greeter", ClientConfig::default())
        .await?;
let client = GreeterClient::new(engine);

let reply = client.greet(GreetArgs { name: "world".into() }).await?;
assert_eq!(reply.message, "hi world");
```

That's the whole loop. [`examples/demo`](examples/demo) is this exact flow — runnable with `cargo
test -p demo-consumer` — extended with a redacted-secret method, a dual-wire (JSON + XDR) method, a
filterable query, and raw-fd transfers. The full IDL dialect (every method flag, the type mapping,
the CLI) is documented in the [`truenas-rpc-codegen` README](truenas-rpc-codegen/README.md).

### Best practices

- **Spec-first, trait-as-contract.** The generated `Handlers` trait is the contract; evolve the IDL,
  not the generated code. A missing or mistyped handler won't compile.
- **Emit one set of types.** Always run `emit_types()` — server and client share the `$defs` structs.
  A standalone client (no server crate) is just `types_gen.rs` + `client_gen.rs`.
- **Generate at build time; don't commit the output.** `build.rs` regenerates into `OUT_DIR` every
  build, so the spec and the bindings can't drift — review the *spec* diff (the contract), not
  machine output, and never hand-edit `*_gen.rs`. If you must check bindings in (to show them in PR
  diffs, or to drop the codegen build-dependency for downstream consumers), emit to a tracked dir —
  `Build::new().json_idl(dir).out_dir("src/generated").emit_*()`, or the CLI `codegen server
  ./json-idl --out src/generated/server_gen.rs` — **and add a CI step that fails if regeneration
  produces a `git diff`**.
- **Fail with `JsonRpcError`, don't panic.** Return `Err(JsonRpcError::request_failed(…))` (or a
  sibling constructor) from a handler; a panic tears down the connection.
- **Mark secrets in the IDL.** A `"secret": true` field becomes a `Secret<String>` — redacted in
  audit logs and `Debug`, read via deref.
- **Auditing is on by default.** It's declared per method in the IDL (`"audit": true`,
  `"auditMessage": …`); generated servers wire the sink automatically. Opt out only deliberately.
- **Authenticate anything network-facing.** A trusted-local AF_UNIX socket needs none; for TCP/TLS,
  install an auth stack — `AuthStack::builder().scram(source).build()` + `install(builder, stack)` +
  `.state_from_peer(AuthSession::from_peer)` — for channel-bound SCRAM-SHA-512-PLUS. See
  [`truenas-rpc-auth`](truenas-rpc-auth).
- **Transports are opt-in and fail closed.** Client `tls` / `websocket` / `scram` / `fd-passing`
  features are off by default (AF_UNIX + TCP only); a capability a transport can't host (a raw-fd
  transfer over WebSocket) is *refused*, never silently dropped.
- **Test at two levels.** Fast, in-process: build `proto()` and call
  `JsonRpcProtocol::dispatch(bytes, &session)`. Full path: stand up a `TruenasRpcServer` and drive
  the generated client over a real socket. `examples/demo` does both.

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

> The **complete inventory** — every crate's internal/external dependencies, feature flags, and
> coverage status, plus an external-dependency audit — is in **[CRATES.md](CRATES.md)**. This section
> is the consumer's quick view: what you actually name.

This is a workspace of focused crates; a consumer names only what it needs — the dispatch core,
plus a **server** or **client** crate, and a build-dependency on the codegen. The split mirrors the
[layer stack](ARCHITECTURE.md#layers). What actually goes in your `Cargo.toml`:

- **`truenas-rpc`** — the transport-agnostic **dispatch core** (every server *and* client depends on
  it): envelope parse/validation, the session lifecycle + gate, the authorize → handler → audit
  pipeline, the `$/` control messages, pub/sub (`SERVER_CLIENT` subscriptions), and filterable
  (query) methods. Sync handlers run on `spawn_blocking`; async handlers are awaited. It
  **re-exports the filter API** (`tnfilter`, `Filtered`, `CompiledFilters`, …), so you
  `use truenas_rpc::…` for filtering too.
- **`truenas-rpc-server`** — the async **server transport**: AF_UNIX / TCP / kTLS / WebSocket
  listeners, framing, the connection/session registry, and SCM_RIGHTS fd passing. Pair it with the
  core to serve a `JsonRpcProtocol`.
- **`truenas-rpc-client`** — the async **client engine**: connect over AF_UNIX / TCP / kTLS /
  WebSocket (`ws` / `wss` / ws-over-unix), authenticate (SCRAM-SHA-512-PLUS + mTLS / OAuth / bearer /
  peer-cred), call / subscribe, stream raw-fd transfers, and pass fds — driving the codegen'd typed
  client. TLS / WebSocket / SCRAM / fd-passing are opt-in features.
- **`truenas-rpc-auth`** — *optional* **authentication** mechanisms (peer-cred / mTLS / SCRAM /
  GSSAPI / OAuth / passthrough) wired onto the server's `$/sessionSetup` seam.
- **`truenas-rpc-codegen`** — a **build-dependency** (never a runtime one): the `json-idl/`
  → Rust generator, run from `build.rs` (see [Code generation](#code-generation-truenas-rpc-codegen)).
- **`truenas-rpc-pyo3`** — **optional**, only if you run `python:true` handler bodies in an
  embedded CPython interpreter. It is excluded from the workspace's default members, so a default
  `cargo build` links **zero** libpython.

The remaining crates are **internal** — `truenas-filter` (the query engine, re-exported through
`truenas-rpc`), `truenas-xdr` + `truenas-xdr-derive` (the XDR codec + its `derive` proc-macro), and
the syscall/FFI backends (`truenas-keyring`, `truenas-audit`, `truenas-gssapi`). You don't name them
directly; each is self-contained (a small dependency set) and documented in
[CRATES.md](CRATES.md#crate-details).

## Dependency graph

Arrows are Cargo dependencies (`A --> B` means A depends on B). `[opt]` marks an optional add-on,
pulled only for that capability. A **server** names `truenas-rpc-server` + `truenas-rpc`; a
**client** names `truenas-rpc-client`; both add `truenas-rpc-codegen` as a build-dependency.

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
    | (AF_UNIX/TCP/TLS/WS)   |         |    (dispatch core)    |
    +------------------------+         |                       |
    +------------------------+ [opt]   |                       |
    | truenas-rpc-client |-------->|                       |
    | (client engine)        |         |                       |
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
a filterable handler needs only the core crate. The graph above is the primary-crate subset; the
**complete** graph (auth, keyring, audit, gssapi) is in [CRATES.md](CRATES.md#dependency-graph).

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
