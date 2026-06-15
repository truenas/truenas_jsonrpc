# truenas_pyjsonrpc

A small, fast, **pure-Python JSON-RPC 2.0 dispatch library** built on
[msgspec](https://jcristharif.com/msgspec/). You define methods with typed
request/response `Struct`s and a handler; the protocol keeps a name-keyed dispatch
table and fuses parse + validate into a single msgspec pass.

- Python ≥ 3.11 · depends only on `msgspec`
- `truenas_pyjsonrpc` is the **dispatch core** (transport-agnostic, synchronous,
  thread-safe). The same distribution also ships **[`truenas_pyjsonrpc_server`](#server--client)**
  (a turnkey asyncio AF_UNIX/TCP/WebSocket server) and **`truenas_pyjsonrpc_client`** (a
  thread-safe client + a typed-client generator) — so you can go from a protocol to a
  running server and a strongly-typed client in a few lines.
- For a complete service, the opt-in **[`truenas_pyjsonrpc.mixins`](#a-full-application)** layer
  adds **protocol mixins** — PAM/SCRAM **authentication** and middleware-style syslog **audit** —
  that you mix into your protocol class to get authentication, authorization, and an audit trail.
- **Building a service?** → **[GUIDE.md](GUIDE.md)** is a start-to-finish walkthrough —
  declare a versioned protocol, define methods, serve it, generate a typed client and
  OpenRPC document, then evolve the API from v1 to v2.
- Embedding the core in your own loop instead? → **[ARCHITECTURE.md](truenas_pyjsonrpc/ARCHITECTURE.md)**
  covers the session state machine, the `$/` control messages, and the
  server-integration contract.

## Contents
[Quickstart](#quickstart) · [Defining methods](#defining-methods) ·
[Query methods](#query-methods-filterable-lists) ·
[Authorization & audit](#authorization--audit) · [Pub/sub](#pubsub-subscribable-methods) ·
[Cancellation](#cancellation) · [Server info](#server-info-serverinfo) ·
[Sessions & authentication](#sessions--authentication) ·
[Server & client](#server--client) · [A full application](#a-full-application) ·
[Introspection](#introspection) · [Errors](#errors) ·
[Conformance](#conformance--deliberate-refinements)

## Quickstart

```python
import msgspec
from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol

class PoolCreateArgs(msgspec.Struct):
    name: str
    size: int = 0

class PoolCreateResult(msgspec.Struct):
    id: int
    name: str

def pool_create(request: PoolCreateArgs, session_state, request_state) -> PoolCreateResult:
    return PoolCreateResult(id=7, name=request.name)

protocol = JSONRPCProtocol([
    JSONRPCMethod("pool.create", accepts=PoolCreateArgs,
                  returns=PoolCreateResult, handler=pool_create),
], name="truenas.api.v1", version="1.0.0")

uid = "550e8400-e29b-41d4-a716-446655440000"            # ids MUST be UUIDs
print(protocol.dispatch(
    b'{"jsonrpc":"2.0","method":"pool.create","id":"%s","params":{"name":"tank"}}' % uid.encode()))
# b'{"jsonrpc":"2.0","result":{"id":7,"name":"tank"},"id":"550e8400-..."}'
```

The protocol strips the JSON-RPC envelope, calls the handler **by keyword** —
`handler(request=<typed params>, session_state=..., request_state=...)` — validates
the return against `returns`, and rebuilds the envelope with the request's `id`. It
**never raises** for protocol/handler faults (they become wire error responses), and
a message with no `id` is a notification (no reply; `dispatch` returns `None`).

`dispatch(wire, session=None)` takes a per-connection `SessionState`
([Sessions & authentication](#sessions--authentication)); `None` mints a throwaway
one — fine for stateless / no-auth use.

Every `JSONRPCProtocol` requires a **`name`** (the `$/negotiate` discriminator a client
selects, and the default OpenRPC `info.title`) and a **`version`** (an arbitrary string —
the OpenRPC `info.version`; distinct from the `$/serverInfo` server/OS version). API
*versioning* is done by building a separate protocol per version.

## Defining methods

`JSONRPCMethod(name, *, accepts, returns=None, handler=None, …)`:

- **`accepts`** (required) — a `msgspec.Struct` for the params; every method is
  typed (use an empty `Struct` for a no-param method).
- **`returns`** (optional) — a `Struct` for the result; omit for bare scalars/arrays.
- **`handler`** — `handler(request, session_state, request_state)`; may be assigned
  after construction (`m.handler = fn`). It may `raise JsonRpcError(code, message,
  data)` to choose an error code; any other exception → `INTERNAL_ERROR`.
- Flags: **`audit`** / **`audit_message`** ([auditing](#authorization--audit)),
  **`roles`** (declared access roles, surfaced to the authz handler as `request.roles` —
  [authorization](#authorization--audit)), **`cancellable`** ([cancellation](#cancellation)),
  **`pre_auth`** (callable before a session is established), **`direction`**
  ([pub/sub](#pubsub-subscribable-methods)), **`accepts_validator`** / **`returns_validator`**
  (extra imperative validation that runs after the msgspec pass; raise to reject, return a
  value to replace).

### The `request_state` handle

Each handler receives a `request_state` for per-request actions:

- `update_progress(percent=, description=, extra=)` — emit a `$/progress`
  notification correlated to the request, delivered **live** by the server's drain
  thread (a no-op for a notification, or once the request has completed).
- `set_audit(detail)` — runtime audit detail (see [Audit message](#audit-message)).
- `raise_if_cancelled()` / `cancelled` / `wait_for_cancel(timeout)` / `cancel_event`
  — cooperative cancellation (see [Cancellation](#cancellation)).

### …with a decorator

`@jrpc_method(...)` builds the method from the decorated function and registers it
into each protocol in `protocols`. Pure **setup-time** sugar — **no runtime cost**
(identical objects); the function stays directly callable with the built method
attached as `func.method`.

```python
from truenas_pyjsonrpc import JSONRPCProtocol, MessageDirection, jrpc_method

public = JSONRPCProtocol(name="truenas.api.v1", version="1.0.0")   # name + version required

@jrpc_method(name="pool.create", accepts=PoolCreateArgs, returns=PoolCreateResult,
             protocols=[public])
def pool_create(request, session_state, request_state):
    return PoolCreateResult(id=7, name=request.name)

@jrpc_method(name="pool.events", accepts=NoParams, notifies=PoolEvent,
             direction=MessageDirection.SERVER_CLIENT, protocols=[public])
def pool_events():
    """Pushed when a pool changes state."""      # SERVER_CLIENT topic: body unused
```

`name` defaults to `func.__name__` (pass it explicitly for dotted names like
`"pool.create"`). `protocols=()` (the default) builds + attaches `func.method`
without registering. Duplicate and `rpc.`/`$/`-prefixed names raise via `register`.
`JRPCMethod` is an alias for `jrpc_method`.

### Query methods (filterable lists)

`FilterableJSONRPCMethod(name, *, accepts, entry, handler=None, …)` returns a homogeneous
list of `entry` records narrowed by the standard `query-filters` / `query-options`
([wire grammar](../ARCHITECTURE.md#7-query-methods-filtering)). It adds those two optional
fields to `accepts`, compiles them, and passes them to the handler as `filters` / `options`
to apply at its data source:

```python
from truenas_pyjsonrpc import FilterableJSONRPCMethod
from truenas_pyfilter import tnfilter

class Pool(msgspec.Struct):
    id: int
    name: str

def pool_query(request, session_state, request_state, filters, options):
    return tnfilter(pools(), filters=filters, options=options)

FilterableJSONRPCMethod("pool.query", accepts=NoParams, entry=Pool, handler=pool_query)
```

- **`entry`** (required) — the element `Struct`; it sets the result type, so `returns`
  stays `None`.
- The handler gains `filters`, `options` and returns the narrowed `list[entry]` (or an
  `int` for `count`); the framework applies `get`, so the effective return is
  `list[entry] | entry | int`.

The generated typed client exposes `query_filters` / `query_options` keyword args and a
`list[Pool] | Pool | int` return.

## Authorization & audit

Optional `authorization_handler` and `audit_handler` (pass to the constructor or
`register_authorization_handler` / `register_audit_handler`) wrap every method call
in an **authorize → dispatch → audit** pipeline. Both are called **by keyword**.

```python
from truenas_pyjsonrpc import AuthorizationResponse, JSONRPCRequest

def authorize(request: JSONRPCRequest, session_state) -> AuthorizationResponse:
    if session_state.server_state_internal.get("uid") == 0:
        return AuthorizationResponse(True)
    return AuthorizationResponse(False, "root session required")    # -> NOT_AUTHORIZED

def audit(request, response, session_state, audit_message=None) -> None:
    outcome = "error" if "error" in response else "ok"
    log.info("%s -> %s (%s)", request.method, outcome, audit_message)

protocol = JSONRPCProtocol(methods, name="truenas.api.v1", version="1.0.0",
                           authorization_handler=authorize, audit_handler=audit)
```

- **Authorization** must return an `AuthorizationResponse`; an `authorized=False`
  result skips dispatch and returns a `NOT_AUTHORIZED` (-32000) error from its
  `message`/`data`. Raising, or returning the wrong type, is `INTERNAL_ERROR`.
- **Roles** — declare `JSONRPCMethod(..., roles=["VM_WRITE"])` to keep the access requirement
  *with* the method; the core surfaces it as **`request.roles`** (a tuple, `()` when none) for
  the handler to intersect with the session's granted roles (OR-semantics — any one grants
  access). The protocol only carries the metadata; the role names and the allow/deny decision
  stay yours. `roles` also shows up in [`describe()`](#introspection).
- **Audit** is **opt-in per method** (`JSONRPCMethod(..., audit=True)`) and runs only
  when an `audit_handler` is registered — for that method's success, error, *and*
  denial. `response` is the full envelope dict (branch on `"error" in response`); the
  return is ignored and any exception it raises is swallowed.
- Pre-method protocol errors (bad JSON/envelope, unknown method, invalid params)
  bypass authz/audit. Notifications still run the pipeline (audit sees the would-be
  response) but produce no reply.
- The `$/` control ops have their own authz/audit rules — see
  [ARCHITECTURE.md §4](truenas_pyjsonrpc/ARCHITECTURE.md#4-control-messages--namespace).

### Audit message

Each audited call hands the audit handler a single `audit_message` (or `None`),
assembled from two optional parts:

- **Static** — `JSONRPCMethod(..., audit_message="Create pool")`: a fixed per-method
  description (a plain string, never interpolated, so a secret param can't leak in).
- **Runtime** — `request_state.set_audit("tank")` inside the handler: dynamic detail.
  **Single-valued, last call wins**, so a call emits **exactly one** message.

The handler gets `"Create pool tank"` (both, space-joined), or whichever is present,
or `None`. A denial (handler never ran) audits with the static part only. The text
is **not** redacted — keep secrets in secret *fields* (below), not in the message.

### Off the IO path

`JSONRPCProtocol(..., use_audit_queue=True)` keeps audit (and its redaction cost)
off the dispatch path: an audited call **enqueues** a job, drained by a background
thread — `rec = protocol.poll_audit(block=, timeout=); rec.run()` — where
`poll_audit` returns an `AuditRecord` (already redacted) or `None`. Default is inline.

### Secret redaction

Mark a Struct field secret with `Annotated[T, SECRET]`; the audit view masks it
(`"********"`) while the **real value still flows on the wire** and to the authz
handler. A per-type plan is compiled once (cached) over a `to_builtins` copy —
nested Structs, `Optional`, `list`/`dict`, fixed/var tuples, tagged unions, and
`rename`d fields are handled; secret-free methods pay nothing.

```python
from truenas_pyjsonrpc import SECRET

class Login(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]             # masked in audit; real on the wire
```

## Pub/sub (subscribable methods)

A method's `direction` (`MessageDirection`) marks it a normal request
(`CLIENT_SERVER`, default) or a **subscribable topic** (`SERVER_CLIENT`) — no
handler, a required `notifies` payload schema:

```python
JSONRPCMethod("pool.events", accepts=SubscribeArgs, notifies=PoolEvent,
              direction=MessageDirection.SERVER_CLIENT)
```

- **Subscribe** — a client dispatches a request (with an `id`) to the topic; it runs
  through authz + audit, and the `result` is a subscription id (a uuid).
- **Publish** — `protocol.send_notification(topic, payload)`; the payload is
  validated against `notifies`, encoded once, and fanned out to each subscriber
  (routed to the `SessionState` captured at subscribe time). Unknown / non-topic
  method → `ValueError`.
- **Unsubscribe** — `protocol.unsubscribe(sub_id)`, or
  `protocol.unsubscribe_all(session)` (by `session_uuid`) to clear a connection;
  `close_session()` does the latter for you.

How the server delivers the fanned-out messages (the drain thread) →
[ARCHITECTURE.md §5](truenas_pyjsonrpc/ARCHITECTURE.md#5-server-integration--the-contract).

## Cancellation

Cancellation is **opt-in per method** and **cooperative**. Mark a method
`cancellable=True`; each in-flight request then carries a `threading.Event` the
handler watches. Cancelling a method that didn't opt in → `REQUEST_FAILED`.

```python
@jrpc_method(accepts=Args, returns=Result, cancellable=True)
def long_task(request, session_state, request_state):
    for chunk in work:
        request_state.raise_if_cancelled()          # -> REQUEST_CANCELLED if cancelled
        process(chunk)
    return Result(...)

# or block responsively (wakes the instant a cancel arrives):
def waiter(request, session_state, request_state):
    while not done():
        if request_state.wait_for_cancel(timeout=5.0):
            request_state.raise_if_cancelled()
        poll_backend()
```

A client cancels with the `$/cancelRequest` control request
(`params: {"target_id": <in-flight id>}`). It's **advisory** — a handler that never
checks completes normally (Python can't safely force-kill a thread). Optionally
register `register_cancellation_handler(fn)` — `fn(request, target, session_state)` —
for *active* abort the event can't do alone (e.g. closing a socket).

**Session-scoped authorization.** For `$/cancelRequest` the `authorization_handler`
also gets `target=<the in-flight RequestState | None>`, so it can enforce ownership
(the canceller is `session_state`; the owner is `target.session_state`). Accept a
`target` keyword (or `**kwargs`) — otherwise the cancel fails closed.

```python
def authorize(request, session_state, target=None):
    if request.method == "$/cancelRequest":
        if session_state.server_state_internal.get("admin"):
            return AuthorizationResponse(True)                  # admin cancels anything
        if target is not None and (
                target.session_state.session_uuid == session_state.session_uuid):
            return AuthorizationResponse(True)                  # owner cancels own
        return AuthorizationResponse(False, "cannot cancel another session's request")
    ...  # normal-method authz
```

## Server info (`$/serverInfo`)

`$/serverInfo` is an **unauthenticated** control request for basic server identity a
client can call before authenticating (a probe / version check). Opt in by
registering a handler + result type:

```python
from truenas_pyjsonrpc import ServerInfo            # or your own msgspec.Struct

protocol.register_server_info(
    lambda session_state: ServerInfo(name="truenas", version="25.04"),
    returns=ServerInfo)
```

It runs **before** authorization and the session gate, takes no params, needs an
`id`, and is **not** audited. Unregistered → behaves like any unknown `$/` method.

## Sessions & authentication

Every connection has a **`SessionState`** — `protocol.new_session(server_state=...)`,
passed to every `dispatch`. It carries a `session_uuid`, the protocol `name`, a
`lifecycle`, and split opaque state: **`server_state_internal`** (server-side
identity/permissions — what handlers and authz read) and **`server_state_external`**
(client-facing). It never goes on the wire.

Authentication is opt-in via `add_session_setup(setup, continue_=None)`, binding the
`$/sessionSetup` (and optional multi-step `$/sessionSetupContinue`) control requests.
Each is a `JSONRPCMethod` (with `accepts` + `returns`) whose handler has a special
contract — it returns **`(SessionLifecycle, result)`**:

```python
from truenas_pyjsonrpc import JSONRPCMethod, SessionLifecycle

def login(request, session_state):
    if not check(request.user, request.password):
        raise JsonRpcError(JSONRPCError.NOT_AUTHORIZED, "bad credentials")
    session_state.server_state_internal = {"user": request.user}       # the identity
    return SessionLifecycle.ESTABLISHED, LoginResult(welcome=request.user)
    # ...or, for 2FA: return SessionLifecycle.INIT, OtpChallenge(...)

protocol.add_session_setup(JSONRPCMethod(
    "$/sessionSetup", accepts=Credentials, returns=LoginResult, handler=login))
```

Setup **bypasses** authz (it *is* the auth step) but is **always audited** (secret
credential fields redacted). Once setup is configured, a non-`pre_auth` method
requires an **ESTABLISHED** session (else `SESSION_NOT_ESTABLISHED`); with no setup
configured the gate is off. `$/sessionClose` (or `protocol.close_session(session)` on
a socket drop) ends the session.

> **Don't hand-roll this.** The opt-in **`truenas_pyjsonrpc.mixins`** layer productizes the
> whole pattern — a channel-aware `AuthStack` (peercred, password, SCRAM, mTLS, OTP) and a
> PAM-backed `TrueNASAuth` / `TrueNASAuthMixin` — that you mix into your protocol (or
> `install(protocol)` manually). See [A full application](#a-full-application).

→ The full lifecycle state machine, gate, and transitions:
[ARCHITECTURE.md §2](truenas_pyjsonrpc/ARCHITECTURE.md#2-the-session-state-machine).

## Server & client

The dispatch core is transport-agnostic. To actually serve a protocol, two sibling
packages ship in this distribution:

- **`truenas_pyjsonrpc_server`** — an asyncio server over **AF_UNIX, TCP, and/or
  WebSocket** (length-prefixed `4-byte length + JSON` framing on AF_UNIX/TCP; one
  JSON-RPC message per frame over WebSocket, via the optional `websockets` dependency).
  It runs each synchronous `dispatch`
  in a thread pool, bridges
  `poll_notification` back onto the loop (so `$/progress` and pub/sub are delivered
  live), and owns the `session_uuid → connection` registry. It adds one server-layer
  control message, **`$/negotiate`** (unauthenticated), giving the connection flow
  **`$/negotiate → $/sessionSetup → API calls`**: a server can host several named
  protocols and the client picks one up front. Configure a transport with `UnixConfig`,
  `TCPConfig`, or `WebSocketConfig`; TLS is the `ssl=` field of `TCPConfig` /
  `WebSocketConfig`, and the negotiated cipher and (for mutual TLS) the client
  certificate are stamped onto the connection's `Peer` (readable by a `$/sessionSetup`
  handler for cert-based auth).
- **`truenas_pyjsonrpc_client`** — a client whose connection runs on a background
  event loop while exposing a **synchronous, thread-safe** API; many app threads can
  `call()` concurrently (responses correlate by UUID id). Server→client messages
  (`$/progress`, pub/sub) arrive on a thread-safe queue or an `on_notification`
  callback.

```python
import asyncio
from truenas_pyjsonrpc_server import JSONRPCServer, UnixConfig
from truenas_pyjsonrpc_client import BaseClient, UnixConfig as ClientUnixConfig

# serve one or more named protocols over a unix socket (and/or TCP / WebSocket)
async def serve():
    async with JSONRPCServer({"truenas": protocol}, name="truenas",
                             unix_config=UnixConfig(path="/var/run/mw.sock")) as server:
        await asyncio.Event().wait()

# from any thread: negotiate -> authenticate -> call (transport configs are per-side)
client = BaseClient("truenas", unix_config=ClientUnixConfig(path="/var/run/mw.sock"))
client.connect()                                  # $/negotiate
client.setup({"token": "root-token"})             # $/sessionSetup
client.call("pool.create", {"name": "tank"})      # -> result (raises JsonRpcError on error)

# per-call progress notifications (the callback runs on the IO thread)
client.call("pool.create", {"name": "dozer"},
            progress=lambda p: print("progress:", p))
# subscribe to a pub/sub topic; the callback fires per published event
sub_id = client.subscribe("pool.events", callback=lambda event: print("event:", event))
client.unsubscribe(sub_id)                         # sends $/cancelRequest (server drops it)
client.close()
```

Callbacks (`progress`, `subscribe`, and `on_notification`) run on a **dedicated
backchannel thread** (not the IO thread), so a callback may block and may safely call
`client.call()` / `subscribe` / `unsubscribe`. Delivery is **ordered** (single thread),
so a slow callback delays later ones — hand heavy work off if that matters. A topic
with no callback (or any unrouted notification) falls back to a registered
`on_notification(method, params)` or the thread-safe `client.notifications` queue.
`unsubscribe(sub_id)` cancels the subscription **server-side** via `$/cancelRequest`.

**Typed client (codegen).** Generate a strongly-typed `BaseClient` subclass that
reuses the protocol's `accepts`/`returns` Structs (the codegen lives at the repo root,
a build-time tool):

```
python codegen.py mypkg.api:protocol --out client_gen.py
```

gives `pool_create(self, request: PoolCreateArgs) -> PoolCreateResult`,
`subscribe_<topic>(...)`, and a `TOPICS` map (topic → payload type) for decoding
notifications. Transfer methods become `file_download(self, request, *, callback) ->
Result`. See **[`examples/`](examples/)**: `serve_async.py` / `serve_ws.py` (servers),
`client_async.py` / `client_ws.py` (self-contained end-to-end demos), and the generated
`client_gen.py`.

**OpenRPC document.** Emit a spec-valid [OpenRPC](https://spec.open-rpc.org/) service
description (a sibling build-time tool at the repo root) for docs, validators, mock
servers, and cross-language generators:

```
python openrpc_gen.py mypkg.api:protocol --out openrpc.json
```

`info.title` / `info.version` come from the protocol's `name` / `version`; each method
becomes by-name `params` (decomposed from `accepts`) plus a `result` (from `returns`),
with pub/sub, fd-transfer, and `roles` metadata as `x-*` extensions and the shared
Structs under `components.schemas`. Override with `--title` / `--version`.

**Raw-fd transfers (bulk streams).** For a self-delimiting bulk stream — e.g. piping a
`zfs send`/`recv` stream through libzfs (`lzc_send` / `lzc_receive`) directly on the
socket — a `JSONRPCFdTransferMethod` lends its handler the connection's **raw socket
fd**, then resumes normal JSON-RPC. The server runs the `$/transferReady` handshake and
the transfer callback for you; the client drives one with `client.transfer(method,
params, callback=...)`. Over encryption, enable **kTLS** (`ssl.OP_ENABLE_KTLS`) so the
fd stays plaintext to the handler while the wire is encrypted (ordinary memory-BIO
`ssl=` puts ciphertext on the fd and is rejected). A complete, runnable bi-directional
example (a `lookup` + `get`/`put` file share) is in
[`examples/fileshare.py`](examples/fileshare.py) +
[`fileshare_demo.py`](examples/fileshare_demo.py). →
[ARCHITECTURE.md §6](truenas_pyjsonrpc/ARCHITECTURE.md#6-raw-fd-transfer-bulk-streams).

→ Client usage in depth (concurrency, backchannel callbacks, subscriptions, TLS):
**[truenas_pyjsonrpc_client/README.md](truenas_pyjsonrpc_client/README.md)**.

→ Building a server (sample methods + a middlewared-style **authentication stack**):
**[truenas_pyjsonrpc_server/README.md](truenas_pyjsonrpc_server/README.md)**.

## A full application

The core and server are deliberately **policy-free** — you bring authentication,
authorization, and audit. The opt-in **`truenas_pyjsonrpc.mixins`** layer productizes the
TrueNAS/middlewared patterns as **protocol mixins**, so a real service is a class declaration
rather than a re-implementation. (It is batteries-included, not batteries-required — importing
`truenas_pyjsonrpc` does **not** pull it in, so the dispatch core stays dependency-light.)

```python
from truenas_pyjsonrpc import JSONRPCProtocol
from truenas_pyjsonrpc.mixins import TrueNASAuthMixin, TrueNASAuditMixin

class ZFSDProtocol(TrueNASAuthMixin, TrueNASAuditMixin, JSONRPCProtocol):
    audit_service = "zfsd"
    auth_scram_service = "truenas-api-key"
```

List the mixins you want **before** `JSONRPCProtocol`; each wires itself up at construction.

- **`TrueNASAuthMixin`** (or the generic `AuthStackMixin`) installs a channel-aware,
  middlewared-style **authentication stack** — `$/sessionSetup` (+ `$/sessionSetupContinue`)
  with **SCRAM** (RFC 5802), **GSSAPI** (Kerberos — a stub to override), **mTLS**, and an
  optional **OTP** second factor after SCRAM, plus **channel binding** (mTLS needs a client
  cert; SCRAM/GSSAPI are replay-resistant and need no secure channel). The TrueNAS flavor
  delegates to **PAM** (`pam_truenas`) — SCRAM against the host's PAM files, so the service
  stores no credentials. For a custom store, subclass `AuthStack` (override
  `scram_credentials`/`gssapi_step`/`client_certificate`/`otp`/`peercred`) and return it from
  `make_auth_stack()`. PAM/SCRAM are optional deps, loaded lazily (`PAM_AVAILABLE` /
  `SCRAM_AVAILABLE`).

- **`TrueNASAuditMixin`** (or the generic `AuditMixin`) registers a `SyslogAuditHandler` and
  enables the audit queue, emitting each audited call to **syslog** as middleware's
  `@cee:`/`TNAUDIT` JSON: an `EVENT_TYPE` (`METHOD_CALL` vs `CONTROL_MESSAGE`), the
  user/origin/session, success vs error, the (already-redacted) params, and the required
  `roles`. Set `audit_service`/`audit_address` or override `make_audit_handler()` to customize.

- **Authorization** stays yours: declare per-method [`roles`](#authorization--audit), read
  `request.roles` in your `authorization_handler`, and intersect with the session identity's
  granted roles. The identity is whatever your auth stack recorded on
  `session_state.server_state_internal` (`TrueNASAuth` records `{username, account_attributes,
  origin, …}`).

Everything stays usable the manual way too (`AuthStack.install(protocol)`,
`audit_handler=SyslogAuditHandler(...)` + `use_audit_queue=True`) — the mixins are just the
ergonomic composition. Putting it together — PAM auth + role authorization + syslog audit over
TCP+TLS — is the runnable **[`examples/serve_truenas_app.py`](examples/serve_truenas_app.py)** +
**[`client_truenas_app.py`](examples/client_truenas_app.py)** pair (a SCRAM-only variant is
**[`serve_truenas_scram.py`](examples/serve_truenas_scram.py)**). Subpackage docs:
**[mixins/auth/README.md](truenas_pyjsonrpc/mixins/auth/README.md)** ·
**[mixins/audit/README.md](truenas_pyjsonrpc/mixins/audit/README.md)**.

## Introspection

`protocol.describe()` → a JSON-serializable catalog for codegen / client discovery:
`{name: {direction, doc, accepts, returns, notifies, roles}}` with JSON-Schema bodies
(`msgspec.json.schema`); `doc` defaults to the handler docstring and `roles` is the
(possibly empty) list of declared role names.

## Errors

A handler raises `JsonRpcError(code, message, data)` to return a chosen code (e.g. a
custom `-32000..-32099`, or the LSP-derived `REQUEST_FAILED` for an expected
operation failure vs an `INTERNAL_ERROR` bug). All codes live in one `JSONRPCError`
`IntEnum`. → Full taxonomy: [ARCHITECTURE.md §8](truenas_pyjsonrpc/ARCHITECTURE.md#8-error-codes-reference).

## Conformance & deliberate refinements

This is the transport-agnostic **dispatch core** (`bytes`/`str` in, `bytes`/`None`
out); the async transport + thread-safe client ship as the sibling
`truenas_pyjsonrpc_server` / `truenas_pyjsonrpc_client` packages. It implements
JSON-RPC 2.0 single request/response with deliberate refinements:

- **No batch** — top-level Arrays → Invalid Request.
- **By-name params only** — `params` must be a JSON object; positional arrays →
  Invalid params.
- **UUID-only ids** — a present `id` must be a UUID string.
- **Reserved names** — `rpc.`- and `$/`-prefixed names can't be registered; `$/` is
  the control namespace ([ARCHITECTURE.md §4](truenas_pyjsonrpc/ARCHITECTURE.md#4-control-messages--namespace)).

## Development

Run from this directory (`python/` — the Python implementation root):

```sh
python -m pytest tests/          # WebSocket / PAM tests skip unless their deps are present
python -m mypy truenas_pyjsonrpc truenas_pyjsonrpc_server truenas_pyjsonrpc_client codegen.py openrpc_gen.py
python examples/serve.py

pip install -e .[websocket]      # optional: enable the WebSocket transport
dpkg-buildpackage -us -uc -b     # build the Debian package (python3-truenas-pyjsonrpc)
```
