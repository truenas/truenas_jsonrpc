# truenas_jsonrpc — protocol architecture

The **language-agnostic protocol reference** for this stack: the dispatch-core/transport
boundary, the session state machine, the per-request dispatch flow, the `$/` control
messages, the server-integration contract, the raw-fd bulk-transfer handshake, and the
error taxonomy. Every implementation — the [Python reference implementation](python/),
and future Rust/Go ports — targets this contract, so they interoperate on the wire.

For the Python implementation's concrete API mapping (the `dispatch()` /
`poll_notification()` seam, handler signatures, the encoder, kTLS setup) see
[python/truenas_pyjsonrpc/ARCHITECTURE.md](python/truenas_pyjsonrpc/ARCHITECTURE.md).

It is JSON-RPC 2.0 ([spec](https://www.jsonrpc.org/specification)) with deliberate
refinements (§8), and borrows its control-message namespace, progress, cancellation, and
extended error ranges from the LSP base protocol
([spec](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/)).

## 1. Dispatch core vs transport — the boundary

The stack separates a **dispatch core** from a **transport layer**. The core is a pure
function over messages; the transport owns everything with a file descriptor.

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

`dispatch(message, session)` runs, per message:

1. **Parse** the envelope. Malformed JSON → `INVALID_JSON`; a valid non-object (incl. a
   top-level array / batch) → `INVALID_REQUEST`.
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
| `$/negotiate` | client → server | yes | pre-session | no | no | select one of the server's named protocols (server-layer; see below) |
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
→ $/sessionSetup → API calls`. (It is a server-layer concern: a dispatch core embedded
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

These are server-layer control messages, correlated by the request id (like
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
possible future extension (see [ROADMAP](python/ROADMAP.md)); it would share one
connection-binding primitive with a separate back channel.

## 7. Error codes

| name | code | meaning |
|---|---|---|
| `INVALID_JSON` | -32700 | malformed JSON ("Parse error") |
| `INVALID_REQUEST` | -32600 | bad envelope (incl. non-UUID id, top-level array) |
| `METHOD_NOT_FOUND` | -32601 | unknown method |
| `INVALID_PARAMS` | -32602 | params failed decode/validation (by-name only) |
| `INTERNAL_ERROR` | -32603 | unexpected handler/return fault |
| `NOT_AUTHORIZED` | -32000 | authorizer denied |
| `SESSION_NOT_ESTABLISHED` | -32002 | normal method before `ESTABLISHED`, or on `CLOSED` (LSP-derived) |
| `REQUEST_CANCELLED` | -32800 | request cancelled via `$/cancelRequest` (LSP-derived) |
| `REQUEST_FAILED` | -32803 | valid + authorized request failed for an expected reason; vs `INTERNAL_ERROR` = bug (LSP-derived) |

## 8. Deliberate divergences from JSON-RPC 2.0

- **No batch** — top-level arrays are `INVALID_REQUEST`.
- **UUID-only ids** — a present `id` must be a canonical UUID string.
- **By-name params only** — `params` must be a JSON object (no positional arrays).
- **Reserved namespaces** — `rpc.` and `$/` can't be registered.
