# truenas_jsonrpc

A JSON-RPC 2.0 **server/client protocol stack** for TrueNAS — a transport-agnostic
dispatch core, a few transports, and a matching client — with one reference
implementation per language. The **Python** implementation lives in [`python/`](python/);
**Rust** (and possibly **Go**) implementations of the same protocol are planned.

This repository is the home for those implementations and the shared protocol contract.

## What it implements

A refinement of JSON-RPC 2.0 designed for long-lived, authenticated, multiplexed
connections: a transport-agnostic **dispatch core** (`bytes` in → `bytes`/`None` out)
with pluggable transports and a back channel for server→client messages.

### The protocol

Every message is a single JSON-RPC 2.0 object; the transport frames each one (a 4-byte
length prefix on AF_UNIX/TCP, or one WebSocket message — see [Transports](#transports)).
There are four envelope shapes:

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

**Control messages** (`$/` namespace, handled by the server/runtime — not application
methods):

| message | dir | params → result |
|---|---|---|
| `$/negotiate` | C→S | `{protocol}` → `{protocol, server, available[]}` — bind one of the server's named protocols (unauthenticated) |
| `$/sessionSetup`, `$/sessionSetupContinue` | C→S | `{credentials…}` → the auth result; advances the session lifecycle (the *Continue* step is multi-step / 2FA) |
| `$/sessionClose` | C→S | — → end the session (`CLOSED`) |
| `$/serverInfo` | C→S | — → server identity (unauthenticated, opt-in) |
| `$/progress` | S→C | `{id, percent?, description?, extra?}` — progress for the in-flight request `id` (a notification) |
| `$/cancelRequest` | C→S | `{target_id}` → `true` — cancel an in-flight request **or** drop a subscription, by id |
| `$/transferReady` → `$/transferGo` | S→C, C→S | `{id, direction, result}` / `{id}` — handshake for the raw socket operations below |

**Session lifecycle.** A connection sends `$/negotiate` to pick a protocol, then
`$/sessionSetup` (+ `$/sessionSetupContinue` for multi-step / 2FA) to authenticate, then
issues calls. The session advances `NONE → INIT → ESTABLISHED → CLOSED`; once session setup
is configured, a normal method before `ESTABLISHED` is rejected `SESSION_NOT_ESTABLISHED`.
Each call also runs an **authorization** check and an opt-in **audit** record (fields
marked secret are redacted in the audit view).

**Pub/sub** reuses the request/notification shapes: a *topic* is a server→client method;
**subscribing** is a normal request to it (the `result` is a subscription UUID), and each
**publish** is a notification `{"method": "<topic>", "params": <payload>}` delivered to
that connection. `$/cancelRequest` with the subscription id unsubscribes.

**Query methods.** A method may declare its result a filterable list. Such a method takes
two optional by-name params — `query-filters` (a condition list, e.g.
`[["name", "=", "tank"], ["OR", [...]]]`) and `query-options` (`select`, `order_by`,
`offset`, `limit`, plus `count` → an integer and `get` → a single record) — that narrow
the result *at the source*. Omitting them returns the full list, so it is additive. The
filter/option grammar is the same middleware `query` syntax every binding must implement;
the full operator and option tables are in
**[ARCHITECTURE.md → Query methods](ARCHITECTURE.md#7-query-methods-filtering)**.

> **Rust note:** the Rust port intentionally omits `query-options.select` (column projection)
> and the `~` regex operator; all other filter/option behavior is byte-identical. See
> [rust/README.md → Filter-engine deviations](rust/README.md#filter-engine-deviations).

**Raw socket operations.** Two operations step *outside* JSON-RPC framing to do raw I/O
directly on the established socket, coordinated by the `$/transferReady`/`$/transferGo`
handshake (the reader pauses, the operation runs, then normal JSON-RPC resumes). They are
distinct:

- **Byte-stream transfer** — a method's handler is handed the **connection's own socket
  fd** to read or write a self-delimiting byte stream directly on the wire (e.g. a
  `zfs send`/`recv` stream, via `sendfile`/`recvfile`). Requires a plaintext fd → a
  **plain or kernel-TLS** connection (AF_UNIX **or** TCP); rejected over userspace TLS or
  WebSocket.
- **File-descriptor passing** — a handler passes **other open file descriptors** to the
  peer as `SCM_RIGHTS` ancillary data; the peer receives new fds for the same open files
  (the privilege-broker pattern). **AF_UNIX only** (`SCM_RIGHTS` does not exist elsewhere).

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

The per-message dispatch order and full semantics are in the language-agnostic
**[ARCHITECTURE.md](ARCHITECTURE.md)**.

### Transports

| Transport | Framing | Notes |
|-----------|---------|-------|
| AF_UNIX   | 4-byte big-endian length + JSON | peer credentials (uid/gid/pid) |
| TCP       | 4-byte big-endian length + JSON | optional TLS; **kernel-TLS** keeps the fd plaintext for zero-copy transfers |
| WebSocket | one JSON-RPC message per frame  | `ws://` / `wss://`; optional dependency; no raw-fd transfers |

## Architecture

The stack splits into a transport-agnostic **dispatch core** and a **transport layer**
around it. The core is a single seam — a request message in, a response message out (or
nothing, for a notification) — plus an outbound queue for server→client messages. It
owns no sockets, event loop, or threads; everything around it is the transport's job.

| Dispatch core — shared by every implementation | Transport layer — per implementation |
|------------------------------------------------|--------------------------------------|
| envelope parse + validation; the dispatch state machine | connection accept; framing; the event / read loop |
| method routing; the authorize → handler → audit pipeline | the `session → connection` registry and message routing |
| session lifecycle + gate; response/notification construction | draining the outbound queue to the wire; backpressure |

Two channels move messages over a connection:

- **Request channel** — a request is dispatched to a handler and a response comes back.
  Every request carries a UUID `id`, and responses correlate by it, so many requests can
  be in flight on one connection at once.
- **Back channel** — server→client messages that aren't responses: `$/progress` for an
  in-flight request, and pub/sub topic events. The core enqueues them; the transport
  drains that queue and routes each message to the right connection by its session id.

```
  request channel  (client -> server -> reply)

     client --frame-->  transport  -->  dispatch core  -->  handler
                                                              |
     client <--frame--  transport  <--  outbound queue  <--  response

  back channel  (server -> client:  $/progress, pub/sub)

     handler progress / topic publish
          |  enqueue
          v
     outbound queue  -->  transport  -->  client     (routed to a connection
                                                       by its session id)
```

A connection is **stateful**: it selects a protocol, authenticates, then issues calls,
walking the session lifecycle `NONE → INIT → ESTABLISHED → CLOSED` (non-pre-auth methods
are gated until `ESTABLISHED`). A typical client↔server exchange:

```
   client                                    server
     |  $/negotiate {protocol}         -----> bind a named protocol
     |  {protocol, server, available}  <-----
     |  $/sessionSetup {credentials}   -----> authenticate
     |  result (-> ESTABLISHED | INIT) <-----
     |  example.method {params}        -----> authorize -> handler -> audit
     |  $/progress {...}               <-----    (back channel, live)
     |  result                         <-----
     |  events  (subscribe)            -----> register a subscription
     |  sub_id                         <-----
     |  events {payload}               <-----    (back channel, per publish)
     |  $/cancelRequest {sub_id}       -----> drop the subscription
     |  true                           <-----
```

The full per-request pipeline (parse → resolve id → control-message intercept → method
lookup → session gate → params → **authorize → handler → audit** → response), the
control-message semantics, the concurrency contract, and the raw-fd transfer handshake
are specified in the language-agnostic
[ARCHITECTURE.md](ARCHITECTURE.md) — the contract every implementation follows.

## Implementations

- **[`python/`](python/)** — the reference implementation:
  - `truenas_pyjsonrpc` — the transport-agnostic dispatch core (pure Python, on
    [msgspec](https://jcristharif.com/msgspec/)).
  - `truenas_pyjsonrpc_server` — a turnkey asyncio AF_UNIX/TCP/WebSocket server.
  - `truenas_pyjsonrpc_client` — a thread-safe client + a typed-client generator.
  - Quickstart, full API docs, examples, and the Python integration guide
    ([python/truenas_pyjsonrpc/ARCHITECTURE.md](python/truenas_pyjsonrpc/ARCHITECTURE.md))
    all live there.
- **[`rust/`](rust/)** — *in progress*: the dispatch core (`truenas-jsonrpc`) plus the
  query-filter engine (`truenas-filter`), A/B-verified byte-for-byte against the Python
  reference. Two deliberate deviations — `query-options.select` and the `~` regex operator
  are unsupported (see [rust/README.md](rust/README.md#filter-engine-deviations)).
- **`go/`** — *planned* (not yet present).

New language implementations target the same wire contract above, so they interoperate
with the Python server and client.

## Repository layout

```
.
├── README.md                       # this file — language-agnostic overview
└── python/                         # the Python reference implementation
    ├── README.md                   # Python library docs + quickstart
    ├── ROADMAP.md                  # implementation / feature roadmap
    ├── pyproject.toml
    ├── debian/                     # Debian packaging (python3-truenas-pyjsonrpc)
    ├── truenas_pyjsonrpc/          # dispatch core (+ ARCHITECTURE.md)
    ├── truenas_pyjsonrpc_server/   # asyncio server
    ├── truenas_pyjsonrpc_client/   # thread-safe client
    ├── codegen.py                  # typed-client generator
    ├── examples/
    └── tests/
```

## Packaging

The Python implementation builds a single Debian binary package
`python3-truenas-pyjsonrpc` (all three importable packages) from `python/debian/`:

```sh
cd python && dpkg-buildpackage -us -uc -b
```

`python3-msgspec` is a hard dependency; `python3-websockets` is **`Suggests`** (only
needed for the WebSocket transport — everything else runs on msgspec alone).

## References

- [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification) — the base protocol
  this stack refines.
- [Language Server Protocol 3.18 specification](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/)
  — inspiration for the `$/` control-message namespace, progress, cancellation, and the
  extended error-code ranges.
- This stack's protocol architecture — component boundary, dispatch flow, control
  messages, the transfer handshake, error codes: **[ARCHITECTURE.md](ARCHITECTURE.md)**.
- The Python implementation's API mapping:
  [python/truenas_pyjsonrpc/ARCHITECTURE.md](python/truenas_pyjsonrpc/ARCHITECTURE.md).

## License

MIT — see [LICENSE](LICENSE).
