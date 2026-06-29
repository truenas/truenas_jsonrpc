# truenas_jsonrpc — protocol architecture

The **protocol reference** for this stack: the dispatch-core/transport boundary, the session
state machine, the per-request dispatch flow, the `$/` control messages, the server-integration
contract, the raw-fd bulk-transfer handshake, and the error taxonomy — the wire contract the Rust
implementation targets.

For the Rust implementation's concrete API mapping (the `dispatch()` seam, handler signatures, the
encoder, kTLS setup) see [truenas-jsonrpc/ARCHITECTURE.md](truenas-jsonrpc/ARCHITECTURE.md).

It is JSON-RPC 2.0 ([spec](https://www.jsonrpc.org/specification)) with deliberate
refinements (§9), and borrows its control-message namespace, progress, cancellation, and
extended error ranges from the LSP base protocol
([spec](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/)).

## Layers

This stack is a conventional RPC decomposition — raw bytes at the bottom, a typed handler call at the
top. The **same names are used throughout the code and the rest of these docs**. Five per-message
strata, bottom → top:

| # | Layer | Responsibility | Modules / types |
|---|---|---|---|
| 1 | **Transport** | Owns the file descriptor: accept loop, read/write event loop, TLS/kTLS, peer-cred identity, raw-fd (`sendfile`/`SCM_RIGHTS`) transfer, WebSocket. Moves opaque bytes. | `truenas-jsonrpc-server`: `connection.rs`, `server.rs`, `tls.rs`, `peer.rs` (`Transport`, `Peer`), `scm.rs`, `transfer.rs`, `ws.rs` |
| 2 | **Framing** | Delimits one message in the byte stream (today: a 4-byte big-endian length prefix; one WebSocket message = one frame). Yields an opaque body. | `truenas-jsonrpc-server`: `framing.rs` (`frame_into`, `FrameError`), `connection.rs::take_frame` |
| 3 | **Codec** | Bytes ↔ typed params/result for a wire. Both current wires are serde-driven (JSON via `serde_json`; the TXDR binary wire via `truenas-xdr`), but the layer is *not defined as* serde — a hand-written body parser is equally a codec. | `truenas-jsonrpc`: `method.rs` (`Codec` / `WireParams` / `WireReply`); the `truenas-xdr` crate |
| 4 | **Envelope** | The per-message header: request id, method name / opcode, error taxonomy, request↔reply correlation. On the JSON wire a top-level array is a JSON-RPC 2.0 batch — several requests in one frame (§3, §9). | `truenas-jsonrpc`: `envelope.rs` |
| 5 | **Dispatch** | Routes a decoded, authorized request to its handler through an O(1) keyed table — JSON by method name (`HashMap<Arc<str>>`), XDR by proc-id (`HashMap<u32>`), both sharing one `Arc<Method>`. Wire-neutral. | `truenas-jsonrpc`: `protocol.rs` (`dispatch` / `dispatch_xdr`, the registries, `Dispatched`), `method.rs` (`Method` / `MethodImpl`) |
| — | → **Handler** | The consumer's `Fn(Accepts, &RequestCtx) -> Result<Returns>`. | consumer code |

**Cross-cutting concerns** — named separately because they attach at a point, they are *not* strata:

- **Authentication** — establishes the peer credential (SASL/SCRAM, GSSAPI, OAuth, mTLS, peer-cred) during
  the negotiate/setup handshake. `truenas-jsonrpc-auth` (`Channel`, `Capability`, the mechanisms); the
  handshake in `setup.rs` + the server's `negotiate.rs`.
- **Authorization** — gates each call by a role-mask subset test, run *between* codec-decode and handler so
  `INVALID_PARAMS` precedes `NOT_AUTHORIZED`. The gate in `protocol.rs` + `role.rs` (`RoleMask`).
- **Control-plane** — the `$/` verbs (`$/negotiate`, `$/sessions`, `$/cancelRequest`), the session state
  machine, and server→client push. `session.rs`, `setup.rs`, the `$/` handling in `protocol.rs`.

Two layer boundaries are deliberately **negotiable**, not clean cuts — name them when reasoning about a new wire:

- **Framing ↔ Codec (where addressing lives).** *Which* layer recovers the request's opcode + id is
  protocol-dependent. Today the length prefix is framing but the TXDR `proc_id`/`rid` ride *inside* the body
  (recovered by codec/envelope); a header-carrying wire — SMB DSI's 16-byte header, ONC-RPC record marking —
  puts opcode + id in the *framing* header, so a pluggable `Framing` trait must surface `{opcode,
  request_id, body}`. See [FRAMING.md](FRAMING.md).
- **Envelope ↔ Dispatch (per-protocol vs reusable).** The dispatch op-table is wire-neutral and reusable;
  the envelope + control-plane are per-protocol. A new protocol reuses the op-table but brings its own
  envelope and control verbs — the `dyn ProtocolEngine` direction in
  [PROTOCOL_SPINE_ASSESSMENT.md](PROTOCOL_SPINE_ASSESSMENT.md) (Gaps 3–4).

Two deliberate choices: **Framing is its own layer** (not folded into transport) so it can be made pluggable
per protocol — see [FRAMING.md](FRAMING.md); and the **Control-plane** is what makes this more than bare
request/response RPC — long-lived, authenticated, multiplexed connections.

The **load-bearing seam** is between layers **1–2** (transport + framing — the `truenas-jsonrpc-server`
crate) and layers **3–5** (the transport-free **dispatch core** — the `truenas-jsonrpc` crate): one call,
`dispatch(message, session)` (framed bytes in, bytes out). The next section details exactly that boundary.

## 1. Dispatch core vs transport — the boundary

The load-bearing seam in the layer stack above is between the **dispatch core** (layers 3–5) and the
**transport layer** (layers 1–2). The core is a pure function over messages; the transport owns
everything with a file descriptor.

| Dispatch core (protocol logic) | Transport layer (server / runtime) |
|---|---|
| envelope parse + validation | connection accept; framing (length-prefix, WebSocket, …) |
| the dispatch state machine | the event / read loop; per-connection read |
| message construction (responses, `$/progress`, pub/sub) | the threads/tasks that drain the outbound + audit queues |
| authorization / audit / cancel / session hooks | routing an outbound message to the right connection |
| the session lifecycle + gate | the connection ↔ session registry; backpressure |
| the outbound + audit queues | — |

The seam is a single call:

```
response = dispatch(message, session)      # bytes/text in -> bytes out, or nothing
```

A request yields a response message; a **notification** (a message with no `id`) yields
nothing. Everything around it — sockets, framing, threads, routing — is the transport's.

## 2. Session state machine

Every connection has exactly one **session**, created when the connection binds a
protocol. The transport holds it for the connection's lifetime and passes it to every
`dispatch`; it is never serialized to the wire. It carries a unique session id, the
bound protocol name, the lifecycle state (below), and two opaque slots: a
**server-internal** state (the connection handle + the authenticated identity/permissions
that handlers and the authorizer read) and a **client-facing** state (a setup result).

### Lifecycle

```
new session --> NONE --$/sessionSetup--> (INIT --$/sessionSetupContinue-->)* ESTABLISHED

{ INIT, ESTABLISHED }  --$/sessionClose | server close-->  CLOSED
```

| state | meaning | reachable |
|---|---|---|
| `NONE` | fresh, unauthenticated | `$/serverInfo`, `$/sessionSetup`, pre-auth methods (and **all** methods if no session setup is configured) |
| `INIT` | multi-step auth in progress | `$/serverInfo`, `$/sessionSetupContinue` |
| `ESTABLISHED` | authenticated | everything |
| `CLOSED` | ended | nothing — every message → `SESSION_NOT_ESTABLISHED` |

Transitions are decided by what a setup handler **returns** (the next lifecycle + a
result) or by close. An auth failure leaves the state unchanged — a retry is allowed.

**The gate.** When session setup is configured, a non-pre-auth method requires
`ESTABLISHED`; otherwise the protocol returns `SESSION_NOT_ESTABLISHED`. With no session
setup configured the gate is off and all methods are reachable from `NONE` (mirroring
"no authorizer ⇒ open").

## 3. Per-request dispatch flow

`dispatch(message, session)` first selects the wire (the **wire-selection seam**, `protocol.rs`): a
4-byte TXDR magic → the binary wire; a top-level JSON **array** → a JSON-RPC 2.0 **batch** (each
element runs the per-request flow below and the responses are concatenated into one array; an
*empty* array → `INVALID_REQUEST`; a batch of only notifications → no reply); otherwise the
single-request JSON path. Per (single) message:

1. **Parse** the envelope. Malformed JSON → `INVALID_JSON`; a valid non-object → `INVALID_REQUEST`.
2. **Resolve `id`.** Present → must be a canonical UUID string (else `INVALID_REQUEST`).
   Absent → a **notification** (no reply).
3. **Structural checks:** `jsonrpc == "2.0"`, `method` is a non-empty string.
4. **CLOSED short-circuit:** a closed session rejects everything.
5. **Control-message interception** (`$/…`; see §4).
6. **Method lookup.** Unknown → `METHOD_NOT_FOUND` (request) / ignored (notification).
7. **Subscribe id check:** a subscribe (server→client topic) request must carry an `id`.
8. **Session gate** (§2) — only when session setup is configured.
9. **Params:** decode + validate against the method's declared input.
10. **authorize → handler → validate result.**
11. **audit** (when the method opts in and an audit hook is registered).
12. **Build** the response (or nothing, for a notification).

Faults never escape `dispatch` — every protocol/handler error becomes a wire error
object. A handler may fail with a chosen error code; any other fault becomes
`INTERNAL_ERROR`.

```
   request message  +  session (per connection)
        |
        v
   parse envelope ----------------> malformed / non-object  => error response
        |
        v
   resolve id  (a UUID, else INVALID_REQUEST;  absent => notification, no reply)
        |
        v
   CLOSED session? ---------------> yes  => SESSION_NOT_ESTABLISHED
        |
        v
   control ($/...) message? ------> yes  => control handler (section 4)
        |  no
        v
   method lookup -----------------> unknown  => METHOD_NOT_FOUND
        |
        v
   session gate: ESTABLISHED? ----> no  => SESSION_NOT_ESTABLISHED
        |       (only when session setup is configured)
        v
   decode + validate params ------> failure => INVALID_PARAMS
        |
        v
   authorize ---------------------> deny  => NOT_AUTHORIZED
        |
        v
   handler   (may emit $/progress, set an audit detail, observe cancellation,
        |     or fail with a chosen error code)
        v
   validate result
        |
        v
   audit  (when the method opts in and an audit hook is registered)
        |
        v
   response message  -->  wire        (or nothing, for a notification)
```

The **back channel** — `$/progress` and pub/sub — is decoupled from `dispatch`: the
core enqueues, and the transport drains on its own thread/task and routes by session.
Both the request channel and the back channel are **multiplexed over the single,
client-initiated connection** (a separate backchannel connection is intentionally out of
scope — the one socket is bidirectional).

```
   a handler emits progress              a publisher sends to a topic
            |                                     |  validated against the
            |  $/progress {id, ...}               |  topic's payload schema
            v                                     v
       +-------------------------------------------------+
       |   outbound queue   (one per protocol)           |
       +-------------------------------------------------+
                              |
                              v
       drain pulls (session, message)  -- on a server thread/task -->
                              |
                              v
       server routes by session id  ->  that connection's socket
```

## 4. Control messages (`$/` namespace)

The `$/` and `rpc.` prefixes are reserved — user methods can't use them. An unknown
`$/…` request → `METHOD_NOT_FOUND`; an unknown `$/…` notification → ignored.

| message | direction | id | lifecycle | authz | audited | purpose |
|---|---|---|---|---|---|---|
| `$/negotiate` | client → server | yes | pre-session | no | no | select one of the server's named protocols (server-side; see below) |
| `$/progress` | server → client | — | n/a | — | — | progress for an in-flight request |
| `$/serverInfo` | client → server | yes | any but `CLOSED` | no | no | unauthenticated server-identity probe (opt-in) |
| `$/sessionSetup` | client → server | yes | `NONE` | no (is auth) | yes | first auth step (opt-in) |
| `$/sessionSetupContinue` | client → server | yes | `INIT` | no (is auth) | yes | subsequent auth step (2FA) |
| `$/sessionClose` | client → server | yes | `INIT`, `ESTABLISHED` | no | yes | client logout → `CLOSED` |
| `$/cancelRequest` | client → server | yes | any | yes | yes | cancel an in-flight cancellable request **or** drop a subscription, by id |
| `$/transferReady`, `$/transferGo` | both | — | — | — | — | the raw-fd transfer handshake (§6) |

**`$/negotiate`** is the unauthenticated front door: a connection's first message is
`$/negotiate {protocol}`; the server binds one of its named protocols and replies
`{protocol, server, available}`, then creates the session. The full flow is `$/negotiate
→ $/sessionSetup → API calls`. (It is a server-side concern: a dispatch core embedded
directly, with a single protocol, needs no negotiation.)

**`$/sessionSetup` / `$/sessionSetupContinue`** authenticate. The handler returns the
next lifecycle + a result, records the authenticated identity on the session's
server-internal slot, and the result is validated and returned. Setup **bypasses**
authorization but is **always audited**, with secret fields redacted.

**`$/cancelRequest`** (`params: {target_id}`) resolves the id against both in-flight
requests and subscriptions (request ids are client-minted, subscription ids
server-minted — distinct UUIDs). It authorizes with the target in hand (so policy can
enforce session-scoped "cancel only your own" rules), then either cancels the request
(cooperatively) or drops the subscription (a wire-level unsubscribe).

## 5. The implementor contract

What a server / runtime MUST do to drive the core:

1. **Build the protocol once, at startup** — register methods + handlers + a name, the
   session-setup stack, server-info, etc. One protocol instance is safe for concurrent
   use.
2. **One session per connection** — create it on accept (seed its server-internal slot
   with your connection context) and pass it to every `dispatch`.
3. **Inbound loop** — for each *framed* message:
   ```
   reply = dispatch(message, session)
   if reply is not nothing:
       send(reply)
   ```
   Framing is yours; the core is frame-agnostic (bytes/text in).
4. **Outbound drain (required for progress + pub/sub)** — a loop that pulls
   `(session, message)` from the outbound queue and writes each to that session's socket:
   ```
   while running:
       (target_session, message) = poll_notification(block, timeout)
       route(target_session, message)        # via your session-id -> socket table
   ```
   It **must** run concurrently with dispatch: a request's still-queued progress is
   **purged when the request completes**, so progress is only delivered if drained live.
5. **Audit drain (optional)** — if auditing is queued rather than inline, a loop that
   pulls and runs audit records (each redacts secrets, then calls your audit hook).
6. **Publish** server→client events to a topic; the drain delivers one copy per
   subscriber.
7. **Clean up on disconnect** — close the session (sets `CLOSED`, drops its
   subscriptions). **Without this, subscriptions leak.** A client `$/sessionClose` does
   the same from the other side.

**Concurrency.** One protocol may be driven by many threads/tasks: the method table is
read-only after setup, and the outbound / in-flight / subscription registries are
guarded. A single session's setup messages should be processed **sequentially** (the
lifecycle mutates as it authenticates). Long handlers should run **off the read path**
(a worker pool), so a `$/cancelRequest` can arrive on another thread while the target
runs — cancellation is **cooperative** (a handler observes a cancel flag and stops; a
runtime can't be assumed able to force-kill a worker).

## 6. Raw-fd transfer (bulk streams)

Some operations move a **bulk, self-delimiting byte stream** that shouldn't be framed as
JSON-RPC messages and copied through the runtime — e.g. a `zfs send`/`recv` stream driven
directly on the socket fd. Such a method lends its handler **exclusive access to the
connection's raw socket fd** for one stream, then the connection resumes normal JSON-RPC.

It is a **two-step** method:

| step | runs | does |
|---|---|---|
| **negotiate** | on the dispatch path (after the gate, param decode, and authz) | validates the request; returns an interim "ready" value (any JSON), sent to the peer as `$/transferReady.params.result`; may refuse with an error |
| **transfer** | off the dispatch path (it blocks on the fd) | reads/writes the raw fd for the whole stream; returns the final result — validated, audited, and sent as the normal response |

`direction` names who **produces** the stream: `DOWNLOAD` — server produces, client
consumes; `UPLOAD` — client produces, server consumes. The transfer step does not return
a normal response from `dispatch`; the core returns a **transfer directive** and the
transport drives the wire handshake, hands the handler the fd, and sends the final
response the handler returns.

### Passing file descriptors (SCM_RIGHTS)

The same takeover can **pass open file descriptors** instead of streaming bytes — a peer
hands the other an *actual fd* (a device, a privileged file, a memfd, a socket) and the
receiver gets a new fd for the same open file (the privilege-broker pattern). It is the
identical two-step method, handshake, and `direction` (`DOWNLOAD` = server sends fds,
`UPLOAD` = client sends), but the `transfer` step does one `sendmsg`/`recvmsg` with
`SCM_RIGHTS` ancillary data rather than a stream; the `negotiate` interim result typically
carries the fd **count** so the receiver can size its receive. **AF_UNIX only** —
`SCM_RIGHTS` does not exist over TCP/WebSocket/TLS, so an fd-pass over any other transport
is rejected with `REQUEST_FAILED`. The receiver **owns** the new fds (must close them), and
passing an fd grants the peer the open file's access mode — gate it with authorization like
any method.

### The wire handshake — `$/transferReady` / `$/transferGo`

These are server-side control messages, correlated by the request id (like
`$/progress`). The **invariant:** the *consumer* must pause its reader **before** the
*producer* writes a stream byte, so every byte lands in the kernel buffer the fd-owning
handler reads from (the framing layer's userspace buffer is bypassed).

```
UPLOAD  (client produces, server consumes)        DOWNLOAD (server produces, client consumes)

  C--> request {id, method, params}               C--> request {id, method, params}
  S: negotiate -> ready                           S: negotiate -> ready
  S: pause reader   (consumer first)              S--> $/transferReady {id, result}
  S--> $/transferReady {id, result}               C: pause reader   (consumer first)
  C--> [ raw stream ]                             C--> $/transferGo {id}
  S: transfer handler reads the fd                S--> [ raw stream ]
  S--> response {id, result}                      C: transfer handler reads the fd
                                                  S--> response {id, result}
```

While the transfer handler runs, the connection's reader is paused, its writer is
suspended, and the fd is blocking; all three are restored afterwards, so a normal call
round-trips on the same connection once the transfer completes. The stream is
self-delimiting — the framework imposes no length; the handler returns when the stream is
done.

### Encryption — plaintext fd required

The handler reads/writes **plaintext** on the fd, so the fd must carry plaintext on the
wire **or** be transparently encrypted by the kernel:

- **Plain** transports (AF_UNIX, plain TCP) — no encryption.
- **Kernel TLS (kTLS)** — the handshake runs on the real fd and the kernel does the
  record crypto, so reads/writes on the fd are plaintext while the wire is encrypted.
- **Userspace TLS** (memory-BIO) puts **ciphertext** on the fd — a transfer over such a
  connection is **rejected** with `REQUEST_FAILED`. **WebSocket** likewise owns the wire,
  so it cannot host a transfer.

### Long transfers — a dedicated connection

A transfer **owns its connection** for the whole stream: the reader is paused, so no other
request, `$/progress`, or `$/cancelRequest` is processed on it until the stream ends. For
a long transfer (e.g. a multi-GB `zfs send`), run it on a **dedicated connection** — the
client opens a second connection, authenticates it, and issues the transfer there, keeping
its command connection free. Because a transfer method is a self-contained, authorized
request, this is connection management on the client (the FTP control/data split) and
needs no protocol support.

A protocol-level data channel *bound* to the command session — to skip re-auth, tie a
transfer to session state, or cancel an in-flight transfer from the command channel — is a
possible future extension; it would share one
connection-binding primitive with a separate back channel.

## 7. Query methods (filtering)

A **query method** returns a homogeneous list of records and takes two **optional**,
by-name params — `query-filters` and `query-options` — that narrow the result *at the
source* (an implementation pushes them down to its data store / iterator rather than
materializing the full set, so a million-row table is never built just to be trimmed).
Both are additive: a request that omits them gets the unfiltered list, so adding query
support to an existing method is non-breaking. Every language binding implements the
**same** grammar below — it is the wire contract, independent of the engine that
evaluates it.

### `query-filters` — the condition list

A JSON array whose top-level elements are combined with **AND**. Two element shapes:

- **leaf** `[field, op, value]` — one condition. `field` is a record key; a **dotted
  path** (`"nested.key"`) addresses a nested field.
- **node** `["OR", [<filters>, <filters>, …]]` — a disjunction whose branches are each a
  full `query-filters` array, so AND/OR nest arbitrarily.

Example: `[["name", "=", "tank"], ["OR", [["state", "=", "ONLINE"], ["readonly", "=", true]]]]`

**Operators** (`op`):

| op | match | `value` |
|---|---|---|
| `=` `!=` | (in)equality | scalar |
| `>` `>=` `<` `<=` | ordering | scalar |
| `~` | regex search | regex string |
| `in` `nin` | (not) a member of | array |
| `^` `!^` | (not) starts-with | string |
| `$` `!$` | (not) ends-with | string |
| `rin` `rnin` | (not) matching any regex in | array of regex strings |

A leading **`C`** makes a string operator case-insensitive via casefold (`C=`, `C~`, `C^`,
…; string values only). Any other operator → `INVALID_PARAMS`.

### `query-options` — result shaping

| field | type | effect |
|---|---|---|
| `select` | `[field \| [field, alias], …]` | project only these fields; `[source, alias]` renames the projected key (`source` may be a dotted path) |
| `order_by` | `[directive, …]` | sort by each directive in turn; a `-` prefix reverses (`"-id"`), `nulls_first:`/`nulls_last:` place nulls (`"nulls_last:name"`); dotted paths allowed |
| `offset` | int | skip the first N matches (0 = none) |
| `limit` | int | cap at N matches (0 = no cap) |
| `count` | bool | return the **count** of matches as an integer — counts **all** matches, ignoring `offset`/`limit` |
| `get` | bool | return the **single** first matching record; cannot be combined with `offset` or `limit > 1` |

### Result shape & errors

| options | `result` |
|---|---|
| (default) | array of records |
| `count: true` | integer |
| `get: true` | the single record — or `REQUEST_FAILED` (-32803) if nothing matched |

Evaluation is filter → `order_by` → `offset` → `limit`, then `select` projects the
surviving records; `count`/`get` reduce the matched set as above. A malformed filter or
option (unknown operator, wrong value type, an illegal `get`/`offset` combination) →
`INVALID_PARAMS` (-32602).

### On the wire

Both fields live inside the request's `params` object and are optional — a request that
omits them (or sends `"params": {}`) gets the full, unfiltered list.

```jsonc
// request — pools named "tank", newest first, first 50, projecting two fields
{"jsonrpc": "2.0", "id": "f81d4fae-…", "method": "pool.query", "params": {
  "query-filters": [["name", "=", "tank"]],
  "query-options": {"order_by": ["-id"], "limit": 50, "select": ["id", "name"]}}}

// default result — an array of records
{"jsonrpc": "2.0", "id": "f81d4fae-…", "result": [{"id": 7, "name": "tank"}]}

// same request with query-options.count: true — an integer (ignores offset/limit)
{"jsonrpc": "2.0", "id": "f81d4fae-…", "result": 1}

// same request with query-options.get: true — the single record
// (or an error response with code -32803 REQUEST_FAILED if nothing matched)
{"jsonrpc": "2.0", "id": "f81d4fae-…", "result": {"id": 7, "name": "tank"}}
```

## 8. Error codes

| name | code | meaning |
|---|---|---|
| `INVALID_JSON` | -32700 | malformed JSON ("Parse error") |
| `INVALID_REQUEST` | -32600 | bad envelope (incl. non-UUID id, empty top-level array) |
| `METHOD_NOT_FOUND` | -32601 | unknown method |
| `INVALID_PARAMS` | -32602 | params failed decode/validation (by-name only) |
| `INTERNAL_ERROR` | -32603 | unexpected handler/return fault |
| `NOT_AUTHORIZED` | -32000 | authorizer denied |
| `SESSION_NOT_ESTABLISHED` | -32002 | normal method before `ESTABLISHED`, or on `CLOSED` (LSP-derived) |
| `REQUEST_CANCELLED` | -32800 | request cancelled via `$/cancelRequest` (LSP-derived) |
| `REQUEST_FAILED` | -32803 | valid + authorized request failed for an expected reason; vs `INTERNAL_ERROR` = bug (LSP-derived) |

## 9. Deliberate divergences from JSON-RPC 2.0

- **Batch is a per-wire Envelope concern, on by default for JSON.** A top-level array is a JSON-RPC
  2.0 batch on the JSON wire (always-on — it is part of the protocol, not a toggle); an *empty*
  array stays `INVALID_REQUEST` per spec, and a batch of only notifications draws no reply. This is
  additive toward the JSON-RPC 2.0 standard (an empty array still rejects, and no client relied on
  non-empty arrays being rejected). Batching is not mandated by the
  dispatch core: a binary wire compounds differently, and the **wire-selection seam** (`is_xdr`
  today; a `dyn ProtocolEngine` in [PROTOCOL_SPINE_ASSESSMENT.md](PROTOCOL_SPINE_ASSESSMENT.md),
  Gaps 3–4) keeps a future non-JSON framing unaffected.
- **UUID-only ids** — a present `id` must be a canonical UUID string.
- **By-name params only** — `params` must be a JSON object (no positional arrays).
- **Reserved namespaces** — `rpc.` and `$/` can't be registered.
