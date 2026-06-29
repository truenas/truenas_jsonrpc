# truenas-jsonrpc — architecture & integration guide

This document is the **Rust implementation's** architecture & integration guide — the
crate/transport boundary, the **sync-vs-async execution model**, the session state
machine, the per-request dispatch flow, the `$/` control messages, the back-channel, the
configuration points, and the contract a transport must satisfy — expressed against the
Rust API (`JsonRpcProtocol::dispatch`, the `Outbound` sink, handler closures, …).

> The **protocol contract** — the wire spec this crate implements — is the repo-root
> [ARCHITECTURE.md](../ARCHITECTURE.md). Read the root for the wire; read this for the
> Rust mapping.

It is JSON-RPC 2.0 with the deliberate refinements in the root doc (§9): UUID-only ids, by-name
params only, reserved `rpc.`/`$/` namespaces, and JSON-RPC 2.0 batch on the JSON wire (an *empty*
array → `INVALID_REQUEST`).

**Status.** This crate is the transport-agnostic **dispatch core**. The required spine —
`$/sessionSetup` authentication and the normal method-call pipeline — is implemented and
proven by a differential conformance test against a committed golden corpus (§12).
Filterable/query methods, pub/sub fan-out, raw-fd transfers, the audit queue, and the
transport/server/client crates are **planned** (§13).

## 1. Crate vs transport — the boundary

`truenas-jsonrpc` is the **dispatch core**, not a server.

| In scope (this crate) | Out of scope (the transport's job) |
|---|---|
| envelope parse + validation | connection accept; framing (length-prefix, WebSocket, …) |
| the dispatch state machine + the session lifecycle/gate | the event loop / per-connection read loop |
| running handlers (sync on a blocking pool, async on the runtime) | spawning a task per request; backpressure |
| message construction (responses, `$/progress`) | writing bytes to a socket; routing the back-channel by session |
| authz / audit / cancel / session hooks | the `$/negotiate` front door + named-protocol registry |

The seam is one call:

```rust
let out: Dispatched = protocol.dispatch(wire, &session).await;
```

`&[u8]` in → a `Dispatched` out. Everything around it — sockets, framing, tasks,
routing — the transport provides.

```rust
pub enum Dispatched {
    Reply(Vec<u8>),   // send these wire bytes back (a success or error response)
    Nothing,          // a notification, or a suppressed reply — send nothing
}
```

## 2. Execution model — blocking vs. awaitable (the defining choice)

The relevant axis is **blocking vs. awaitable**, *not* "I/O-bound vs. CPU-bound." Async
(tokio) is for work that **yields a thread while it waits** (non-blocking sockets, async
drivers); it is the wrong place for **blocking** syscalls or **CPU** work, which hold the
thread. So the core offers **two method kinds**, and the author picks per method:

- **`JsonRpcMethod` (sync handler) — the default.** Covers the bulk of TrueNAS handlers,
  which block: ZFS `ioctl`s / `lzc_send`, file reads/writes, subprocess, and auth-stack
  crypto. Its whole per-request pipeline runs on a **`tokio::task::spawn_blocking`**
  blocking-pool worker.
- **`AsyncJsonRpcMethod` (async handler) — the niche.** For handlers that genuinely
  `.await` non-blocking work (an async service call, an async DB driver). It is **awaited
  inline** on the runtime; it must not block (offload any blocking/CPU work via its own
  `spawn_blocking`).

`dispatch` is `async` and **branches on the method kind**: parse/lookup/gate run inline
(cheap, sync), then a sync method's pipeline is offloaded with `spawn_blocking` while an
async method's pipeline is awaited. A transport drives concurrency by `tokio::spawn`-ing
one task per inbound frame that `dispatch(...).await`s — so a `$/cancelRequest` can be
processed on another task while a long handler runs.

| handler work | nature | runs on |
|---|---|---|
| ZFS ioctls, file I/O, subprocess | blocking | the blocking pool (`JsonRpcMethod`) |
| SCRAM/PBKDF2/bcrypt, PAM | CPU-bound | the blocking pool (`JsonRpcMethod`) |
| awaiting another async service / driver | awaitable | the runtime (`AsyncJsonRpcMethod`) |

The core depends on `tokio` only for `spawn_blocking` and being `async`; it is otherwise
transport-free (it returns `Vec<u8>` and emits the back-channel through an `Outbound`
sink — §6).

## 3. The session state machine

Every connection has exactly one `Arc<Session<S>>`, created by
`protocol.new_session(server_state, out)` and passed to **every** `dispatch`. It is never
serialized to the wire. `S` is the application's **server-internal** state (the connection
handle + the authenticated identity/permissions that handlers and the authorizer read).

| field | representation | notes |
|---|---|---|
| `id` | `uuid::Uuid` (from the injectable `IdGen`) | unique; never on the wire |
| `protocol_name` | `Arc<str>` | the owning protocol's name |
| lifecycle | `AtomicU8` | lock-free gate check on the hot path |
| server-internal `S` | `RwLock<Option<S>>` | a setup handler sets/mutates it; **not** write-once (the auth stack re-writes it across multi-step setup) |
| server-external | `RwLock<Option<Value>>` | the client-facing setup result |
| `out` | `Arc<dyn Outbound>` | the back-channel sink (§6) |

### Lifecycle

```
new --> None --$/sessionSetup--> (Init --$/sessionSetupContinue-->)* Established
{ Init, Established } --$/sessionClose | close_session--> Closed
```

| state | reachable |
|---|---|
| `None` | `$/serverInfo`, `$/sessionSetup`, `pre_auth` methods (and **all** methods if no session setup is configured) |
| `Init` | `$/serverInfo`, `$/sessionSetupContinue` |
| `Established` | everything |
| `Closed` | nothing — every message → `SESSION_NOT_ESTABLISHED` |

**The gate.** When session setup is configured, a non-`pre_auth` method requires
`Established`; otherwise `SESSION_NOT_ESTABLISHED`. With no setup configured the gate is
off and all methods are reachable from `None`.

Read identity via `session.with_internal(|id: Option<&S>| …)` (a brief read lock — never
held across an `.await`); a setup handler writes it via `session.set_internal(s)`.

## 4. Per-request dispatch flow

`dispatch(wire, &session)` runs, per message (follows the root §3 dispatch flow):

1. **Parse** the envelope. Malformed JSON → `INVALID_JSON`; a valid non-object → `INVALID_REQUEST`
   (a top-level **array** is a JSON-RPC 2.0 batch — each element runs this flow; an *empty* array →
   `INVALID_REQUEST`).
2. **Resolve `id`.** Present → must be a canonical UUID string (8-4-4-4-12 hex,
   case-insensitive; validated allocation-free). Absent → a **notification** (no reply).
3. **Structural checks:** `jsonrpc == "2.0"`; `method` a non-empty string. (Steps 1–3 are
   always answered — even a notification gets a structural-error reply.)
4. **`Closed` short-circuit** → `SESSION_NOT_ESTABLISHED`.
5. **Control interception** (`$/…`; §5).
6. **Method lookup** → unknown: `METHOD_NOT_FOUND` (request) / `Nothing` (notification).
7. **Subscribe id check** (a `SERVER_CLIENT` request needs an id) — *planned* (§13).
8. **Session gate** (§3) — only when session setup is configured.
9. **Decode + validate params** into the handler's `Accepts` (serde) → `INVALID_PARAMS`.
   This runs **before** authorization, so `INVALID_PARAMS` correctly precedes
   `NOT_AUTHORIZED`.
10. **Authorize → run handler → encode result.** A handler returns
    `Err(JsonRpcError)` to choose a code; the result type guarantees a valid `Returns`.
11. **Audit** when the method opts in (`audit`) and an audit sink is registered (secret
    fields redacted).
12. **Build** the response (or `Nothing` for a notification / suppressed reply).

**Faults never escape `dispatch`** — every protocol/handler error becomes a wire error
object. There is no `Result` on `dispatch`; the crate-level `Error` is construction-time
only (`ProtocolBuilder` rejects duplicate/reserved names). A handler panic is **the
transport's** boundary: it spawns the per-request task and, on a panicking join, can
synthesize an `INTERNAL_ERROR` reply (no `catch_unwind`-across-`.await`).

## 5. Control messages (`$/` namespace)

`$/`- and `rpc.`-prefixed names can't be registered. Handled in-core:

| message | id | lifecycle | authz | audited | purpose |
|---|---|---|---|---|---|
| `$/serverInfo` | yes | any but `Closed` | no | no | unauthenticated server-identity probe (opt-in) |
| `$/sessionSetup` | yes | `None` | no (is auth) | yes | first auth step (opt-in) |
| `$/sessionSetupContinue` | yes | `Init` | no (is auth) | yes | subsequent auth step (2FA) |
| `$/sessionClose` | yes | `Init`,`Established` | no | yes | client logout → `Closed` |
| `$/cancelRequest` | yes | any | yes (target-scoped) | yes | cancel an in-flight cancellable request **or** drop a subscription, by id |

`$/sessionSetup`/`Continue` handlers return `(SessionLifecycle, Returns)`: they
authenticate, set the session's internal identity as a side effect, and the next lifecycle
+ the validated result are committed. Setup **bypasses** the authorizer but is **always
audited** (secret fields redacted). Setup runs on the blocking pool (its crypto blocks).

`$/cancelRequest` (`params: {target_id}`) resolves the id against the in-flight registry
(and, when implemented, subscriptions), authorizes **with the target in hand** (a
`CancelTarget` exposing the target's `session_id`, so policy can enforce "cancel only your
own"), then sets the request's cooperative cancel flag and runs the optional `Canceller`.

> `$/negotiate` is a **server-side** message (the named-protocol front door, handled at the
> Transport tier); the core never sees it. A directly-embedded core picks its protocol — no
> negotiation.

## 6. The back-channel — progress + pub/sub

A handler emits `$/progress` via `request_ctx.update_progress(percent, description,
extra)`; a publisher (planned) emits a topic payload. Both go to the connection's
`Outbound` sink, **not** through `dispatch`'s return value:

```rust
pub trait Outbound: Send + Sync {
    fn send(&self, message: Vec<u8>);   // non-blocking; the transport drains it to the socket
}
```

The transport hands each session an `Outbound` at `new_session`; emission is a
**non-blocking enqueue** (so a sync handler on the blocking pool can emit progress without
`.await`).

**Ordering.** The transport funnels a connection's replies **and** its back-channel
messages through one **ordered** writer, and a handler emits all its progress **before** it
returns (so the reply is enqueued after). Per request, progress therefore precedes its
reply on the wire with no purge and no membership check — which is why the in-flight
registry is **cancellation-only**, not also progress-correlation. (Replies for concurrent
requests still interleave on the connection; the client correlates by `id`, as in any
multiplexed JSON-RPC connection — root §3.)

## 7. Configuration points (the builder)

`JsonRpcProtocolBuilder<S>` assembles a protocol from its methods, the session-setup
steps, and the authz/audit/cancellation hooks:

| call / mechanism | role |
|---|---|
| `JsonRpcProtocol::builder(name, version)` + `.authorizer(..)` `.audit_sink(..)` `.cancellation(..)` | the protocol + its authz / audit / cancellation hooks |
| `.method(JsonRpcMethod::new(def, handler))?` / `.async_method(AsyncJsonRpcMethod::new(def, handler))?` | register a sync / async method |
| `.session_setup(def, handler)` / `.session_setup_continue(def, handler)` | the two auth setup steps |
| `.server_info(handler)` | the `$/serverInfo` handler |
| `new_session` / `close_session` / `has_session_setup` (on `JsonRpcProtocol<S>`) | per-connection session lifecycle |
| `send_notification` | pub/sub fan-out *(planned — §13)* |
| the `Outbound` sink (§6) + inline audit | the back-channel + audit drain (no poll loop) |
| `.id_gen(..)` / `.clock(..)` | injectable id / clock for deterministic tests (§12) |

Per-method flags on `MethodDef`: `pre_auth`, `audit` /
`audit_message`, `cancellable`, `roles`, `doc`, `secret_fields` (the wire-names redacted
in the audit view). `build()` freezes the method table; the result is safe for concurrent
`dispatch` by many tasks.

## 8. Methods + handlers + type erasure

A handler is a **closure or `fn`** (not a trait impl), the most ergonomic form and the one
that avoids the `impl Trait for F where F: Fn(A) -> R` unconstrained-type-parameter
problem (E0207):

```rust
// sync — JsonRpcMethod (the common case)
|accepts: Accepts, cx: &RequestCtx<S>| -> Result<Returns, JsonRpcError> { … }
// async — AsyncJsonRpcMethod
|accepts: Accepts, cx: RequestCtx<S>| async move { … Ok(returns) }
```

`Accepts: DeserializeOwned + Send + 'static`, `Returns: Serialize`. Each method erases to
an internal `dyn` object behind a **two-phase** seam — `decode(params)` (typed param
validation; runs before authz so `INVALID_PARAMS` precedes `NOT_AUTHORIZED`) and `run`
(invoke the handler, encode the result) — so the protocol authorizes *between* decode and
run. Typed param/result validation lives in the `Deserialize` impl /
`#[serde(try_from)]` / the type's construction.

`RequestCtx<S>` is the per-request handle: `update_progress(...)`, `set_audit(detail)`
(joined with the static `audit_message` as `"{base} {detail}"`), and cooperative
cancellation (`is_cancelled()` / `raise_if_cancelled()` over an `Arc<AtomicBool>`).

### Hook signatures (reference)

| hook | signature |
|---|---|
| sync method | `Fn(Accepts, &RequestCtx<S>) -> Result<Returns, JsonRpcError>` |
| async method | `Fn(Accepts, RequestCtx<S>) -> impl Future<Output = Result<Returns, JsonRpcError>>` |
| `Authorizer` | `Fn(&JsonRpcRequest, &Session<S>, Option<CancelTarget>) -> AuthorizationResponse` |
| `AuditSink` | `Fn(&JsonRpcRequest, &serde_json::Value, &Session<S>, Option<&str>)` |
| `Canceller` | `Fn(&JsonRpcRequest, &Session<S>)` |
| `ServerInfoHandler` | `Fn(&Session<S>) -> Result<serde_json::Value, JsonRpcError>` |
| session setup | `Fn(Accepts, &Session<S>) -> Result<(SessionLifecycle, Returns), JsonRpcError>` |

`target` is `Some` only for `$/cancelRequest`. The authz/audit `JsonRpcRequest.params` is
a `serde_json::Value` snapshot (decoupled from the concrete `Accepts`); it is materialized
only when an authorizer or an audited method will actually read it.

## 9. Error taxonomy

`ErrorCode` is the wire code set (root §8); `JsonRpcError { code: i32, message, data }` is
what a handler returns (an `i32` code allows custom server-range codes). Mapping:

- serde param-decode failure → `INVALID_PARAMS` (short message + the detail in `data`).
- handler `Err(JsonRpcError)` → that code (e.g. `REQUEST_FAILED` for expected failures).
- result-encode failure → `INTERNAL_ERROR`.
- authorizer denial → `NOT_AUTHORIZED`.
- gate / closed → `SESSION_NOT_ESTABLISHED`; unknown method → `METHOD_NOT_FOUND`.

Error messages are stable: `Invalid params`, `Method not found`,
`Session not established`, `Session is closed`, `Request failed`, …; `error.data` is
implementation-specific detail.

## 10. The transport-integration contract

What a server/runtime MUST do to drive the core (the transport crates — §13 — will
implement this):

1. **Build the protocol once, at startup** (methods + hooks + name). One `JsonRpcProtocol`
   is safe for concurrent use by many tasks.
2. **One session per connection** — `protocol.new_session(server_state, out)` on accept,
   seeding the server-internal slot with your connection context and handing it the
   connection's `Outbound`. Pass it to every `dispatch`.
3. **Inbound loop** — for each *framed* message, `tokio::spawn` a task that does
   `match protocol.dispatch(wire, &session).await { Reply(b) => write(b), Nothing => {} }`.
   Spawning per request gives the concurrency cancellation needs.
4. **Drain the `Outbound`** — a writer that pulls the connection's back-channel messages
   and writes them to the socket, **in order with the replies** (one ordered writer per
   connection; see §6). Required for `$/progress` (and pub/sub, when implemented).
5. **Clean up on disconnect** — `protocol.close_session(&session)` (sets `Closed`, and
   drops the session's subscriptions once those exist). A client `$/sessionClose` does the
   same from the other side.

`$/negotiate` and a network transport's **authentication requirement** (a TCP/WebSocket
transport must only expose protocols that have session setup configured) are transport
concerns, not the core's.

## 11. Concurrency

- **One protocol, many tasks — safe.** The method table is frozen after `build`; the
  in-flight and (planned) subscription registries are mutex-guarded; the session lifecycle
  is atomic.
- **A session's setup messages should be sequential** — setup mutates `server_internal`
  and the lifecycle. Don't pipeline one session's `$/sessionSetup*`.
- **Long handlers run off the reactor** — sync handlers on `spawn_blocking`, so a
  `$/cancelRequest` runs on another task while the target runs. Cancellation is
  **cooperative**: a handler observes `cx.is_cancelled()` and stops; a `Canceller` can do
  active abort (e.g. close an fd) for work a flag can't interrupt.

## 12. Determinism & conformance testing

The core is deterministic given an injected `IdGen`/`Clock`, and `dispatch` is
transport-free, so a fixed request corpus runs through it with no sockets. The conformance
test (`tests/conformance.rs`) replays the committed `tests/conformance/golden.json` corpus
through the Rust dispatch core and asserts **byte-stable** responses **and** audit records
against the frozen golden — the gating proof of wire-stability. It is mutation-tested
(deliberately breaking the core must fail it) and runs in CI
(`.github/workflows/rust.yml`); line coverage is gated at **100%**.

## 13. Not yet implemented (planned)

Tracked against the full-parity plan; the wire contract for each is in the root doc:

- **Filterable/query methods** (`query-filters`/`query-options`) and the `truenas-filter`
  engine (root §7).
- **Pub/sub** — `SERVER_CLIENT` subscribe dispatch + `send_notification` fan-out (it is a
  no-op stub today); `$/cancelRequest` dropping a subscription.
- **Raw-fd transfer / SCM_RIGHTS** — a `Dispatched::Transfer` directive + the
  `$/transferReady`/`$/transferGo` handshake (root §6).
- **Audit queue** (off-path audit drain) — auditing is inline today.
- **Transports** — the `truenas-jsonrpc-server` / `-client` crates (AF_UNIX, TCP, TLS,
  WebSocket, kTLS) that satisfy §10.
- **Codegen** — a proc-macro for method definition and an OpenRPC-driven typed-client
  generator.

## 14. Notable design choices

1. **Two method kinds.** `JsonRpcMethod` (sync, on the blocking pool) is the default and
   covers the bulk of handlers; `AsyncJsonRpcMethod` (awaited on the runtime) is the niche
   for genuinely non-blocking work (§2).
2. **`Outbound` sink + one ordered per-connection writer.** A handler emits all its
   progress before it returns, so progress precedes its reply on the wire with no purge,
   and the in-flight registry is cancellation-only (§6).
3. **Closures, not a handler trait**; **two-phase erasure** (decode-before-authz);
   **`Arc<AtomicBool>`** cancel flag; **`RwLock`** session-internal (not write-once);
   **atomic** lifecycle.
4. The **client** (planned) is **async-native** (§13).

## 15. Error codes (reference)

| name | code | meaning |
|---|---|---|
| `InvalidJson` | -32700 | malformed JSON |
| `InvalidRequest` | -32600 | bad envelope (non-UUID id, empty top-level array) |
| `MethodNotFound` | -32601 | unknown method |
| `InvalidParams` | -32602 | params failed decode/validation |
| `InternalError` | -32603 | unexpected handler/return fault |
| `NotAuthorized` | -32000 | authorizer denied |
| `SessionNotEstablished` | -32002 | method before `Established`, or on `Closed` |
| `RequestCancelled` | -32800 | cancelled via `$/cancelRequest` |
| `RequestFailed` | -32803 | valid+authorized request failed for an expected reason |
