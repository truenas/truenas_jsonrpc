# truenas_pyjsonrpc_server

A turnkey **asyncio server** for a [`truenas_pyjsonrpc`](../README.md)
`JSONRPCProtocol`, over **AF_UNIX, TCP, and/or WebSocket** (optionally TLS). You declare
a protocol (methods + an authentication stack), point the server at a socket, and
`serve_forever()`. The server runs each synchronous `dispatch` in a thread pool,
delivers `$/progress` and pub/sub live, captures peer credentials, and owns the
session registry — everything in the [integration contract](../truenas_pyjsonrpc/ARCHITECTURE.md#5-server-integration--the-contract)
is handled for you.

Connection flow: **`$/negotiate` → `$/sessionSetup` [→ `$/sessionSetupContinue`] →
API calls**. `$/negotiate` (this package's only server-layer control message, always
unauthenticated) binds the connection to one of the server's named protocols;
everything after it is handled by that protocol's `dispatch`.

- [Architecture](#architecture) · [Quickstart](#quickstart) ·
  [Defining methods](#defining-methods) ·
  [Authentication stack](#authentication-stack-middlewared-style) ·
  [Peer credentials](#peer-credentials-unix--tls) · [Transports & TLS](#transports--tls) ·
  [Raw-fd transfers](#raw-fd-transfers-sendfilerecvfile) · [Client](#client--codegen)

## Architecture

Two channels move messages between a client and the server: the **request channel**
(client -> server -> reply) and the **back channel** (server -> client: `$/progress`
and pub/sub). The synchronous `protocol.dispatch` runs in a thread pool (handlers may
block); the blocking `protocol.poll_notification` is drained on its own thread and
routed back onto the event loop.

```
request channel  (client -> server -> reply)

   client --frame-->  asyncio loop  -->  run_in_executor  -->  +------------------------+
                                                               |  dispatch thread pool  |
   client <--frame--  writer  <-- outbound queue <-- reply --  |  protocol.dispatch()   |
                                                               +------------------------+

back channel  (server -> client:  $/progress, pub/sub)

   request_state.update_progress()  /  protocol.send_notification()
        |  enqueue
        v
   protocol.poll_notification()  -->  per-protocol drain thread
       (blocks)                            |  session_uuid -> Connection  (registry)
                                           v
              conn.enqueue_outbound  -->  outbound queue  -->  writer  -->  client
```

The server owns the `session_uuid -> Connection` **registry** the drain routes
through, the per-connection outbound queue (shared by replies and notifications), and
the `$/negotiate` front door. Each connection walks a small state machine:

```
   +------------------+  $/negotiate {protocol}   +-------------------+
   | AWAIT_NEGOTIATE  | ------------------------> |       BOUND       |
   | only $/negotiate |                           | protocol.dispatch |
   +------------------+                           +-------------------+
                                                           |  EOF / error
                                                           v
                                                       +--------+
                                                       | CLOSED |
                                                       +--------+
```

Inside `BOUND`, the protocol's own **session lifecycle** gates API calls (when
`add_session_setup` is configured -- see [auth](#authentication-stack-middlewared-style)):

```
   NONE  -$/sessionSetup->  ESTABLISHED                                   (single-step)
   NONE  -$/sessionSetup->  INIT  -$/sessionSetupContinue->  ESTABLISHED  (two-factor)
   ESTABLISHED  -$/sessionClose->  CLOSED
   (a non-pre_auth method before ESTABLISHED  ->  SESSION_NOT_ESTABLISHED)
```

End-to-end message flow:

```
   client                                       server
     |  $/negotiate {protocol}            ----> bind the named protocol
     |  {protocol, server, available}     <----
     |  $/sessionSetup {credentials}      ----> authenticate
     |  result  (-> ESTABLISHED | INIT)   <----
     |  pool.create {...}                 ----> authorize -> handler -> audit
     |  $/progress {...}                  <----   (back channel, live)
     |  result                            <----
     |  zpool.events  (subscribe)         ----> register a subscription
     |  sub_id                            <----
     |  zpool.events {payload}            <----   (back channel, per publish)
     |  $/cancelRequest {target_id}       ----> drop the subscription
     |  true                              <----
```

## Quickstart

```python
import asyncio
import msgspec
from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol
from truenas_pyjsonrpc_server import JSONRPCServer, UnixConfig


class PingArgs(msgspec.Struct):
    pass

class Pong(msgspec.Struct):
    pong: bool = True


def ping(request, session_state, request_state) -> Pong:
    return Pong()


protocol = JSONRPCProtocol([
    JSONRPCMethod("core.ping", accepts=PingArgs, returns=Pong, handler=ping),
], name="truenas.api.v1")


async def main() -> None:
    async with JSONRPCServer(
            {"truenas.api.v1": protocol}, name="truenas",
            unix_config=UnixConfig(path="/var/run/truenas-api.sock")) as server:
        await asyncio.Event().wait()          # serve until cancelled


if __name__ == "__main__":
    asyncio.run(main())
```

`JSONRPCServer(protocols, *, name=None, unix_config=None, tcp_config=None,
websocket_config=None, max_workers=None, limit=...)`. `protocols` maps each
**negotiable name** to a `JSONRPCProtocol`; the client picks one with `$/negotiate`.
Configure at least one transport via `UnixConfig`, `TCPConfig`, and/or
`WebSocketConfig` (several may be combined).

## Defining methods

Methods are plain `truenas_pyjsonrpc` methods — see the
[main README](../README.md#defining-methods) for the full semantics (handlers, the
`request_state` handle, validation, audit, cancellation). Two kinds:

```python
import time
from truenas_pyjsonrpc import MessageDirection


class PoolCreateArgs(msgspec.Struct):
    name: str

class PoolCreateResult(msgspec.Struct):
    id: int
    name: str

class PoolEvent(msgspec.Struct):
    name: str
    state: str


def pool_create(request: PoolCreateArgs, session_state, request_state) -> PoolCreateResult:
    request_state.set_audit(request.name)                       # runtime audit detail
    for pct, msg in ((0, "starting"), (100, "created")):
        request_state.update_progress(percent=pct, description=msg)   # streamed live
        time.sleep(0.05)
    return PoolCreateResult(id=7, name=request.name)


methods = [
    # a normal request/response method (CLIENT_SERVER)
    JSONRPCMethod("pool.create", accepts=PoolCreateArgs, returns=PoolCreateResult,
                  handler=pool_create, audit=True, audit_message="Create pool"),
    # a subscribable pub/sub topic (SERVER_CLIENT): no handler, a payload schema
    JSONRPCMethod("pool.events", accepts=PingArgs, notifies=PoolEvent,
                  direction=MessageDirection.SERVER_CLIENT),
]
```

Publish to subscribers from anywhere with `protocol.send_notification("pool.events",
{"name": "tank", "state": "ONLINE"})`; the server fans it out to every subscribed
connection.

## Authorization & roles

A protocol-level `authorization_handler(request, session_state) -> AuthorizationResponse`
runs after the session-established gate and before every method handler; a denial returns
`NOT_AUTHORIZED` (-32000) and is audited. The handler is the **single place** your access
policy lives — the protocol enforces nothing itself.

To keep the access requirement **with the method**, declare `roles=[...]` on a
`JSONRPCMethod`. The core surfaces them to the handler (and the audit record) as
`request.roles` — a tuple, empty when none are declared — and stops there: the role *names*,
how a caller's granted roles are derived, and the allow/deny decision are all yours. The
conventional reading is OR-semantics (any one listed role grants access):

```python
JSONRPCMethod("vm.create", accepts=VmArgs, returns=Vm, handler=vm_create, roles=["VM_WRITE"]),
JSONRPCMethod("vm.query",  accepts=VmArgs, returns=Vm, handler=vm_query,  roles=["VM_READ", "VM_WRITE"]),

def authorize(request, session_state):
    granted = session_state.server_state_internal["roles"]     # however your app stores them
    if not request.roles or set(request.roles) & set(granted):
        return AuthorizationResponse(True)
    return AuthorizationResponse(False, "missing required role")
```

`roles` also appears in `protocol.describe()` for introspection / tooling. (This mirrors
middleware's `@api_method(roles=[...])` *declaration*; the registry, role hierarchy, and
enforcement remain the application's, by design.)

## Authentication stack (middlewared-style)

Authentication is configured **on the protocol** with `add_session_setup(...)` and
runs as the `$/sessionSetup` (+ optional `$/sessionSetupContinue`) control requests.
Once configured, the protocol **gates** every non-`pre_auth` method: a call before the
session is `ESTABLISHED` is rejected with `SESSION_NOT_ESTABLISHED` (-32002).

> **Don't want to hand-roll this?** The opt-in
> [`truenas_pyjsonrpc.mixins.auth`](../truenas_pyjsonrpc/mixins/auth) layer productizes exactly
> the pattern below — a channel-aware `AuthStack` (peercred over AF_UNIX, login mechanisms +
> mTLS over TCP/WS, the two-step OTP flow) you subclass and `install(protocol)`, or mix in via
> `TrueNASAuthMixin` / `AuthStackMixin`. The rest of this section shows how to build it by hand.

The session moves through a small lifecycle, and a setup handler returns the **next
state** plus the client reply:

| step | allowed at | handler returns | meaning |
|---|---|---|---|
| `$/sessionSetup` | `NONE` | `(ESTABLISHED, result)` | authenticated in one step |
| | | `(INIT, result)` | first factor ok, needs a second (2FA) |
| | | `(NONE, result)` | failed — client may retry from the top |
| `$/sessionSetupContinue` | `INIT` | `(ESTABLISHED, result)` | second factor ok |
| | | `(INIT, result)` | second factor failed — retry the OTP |

This is the shape of middlewared's `auth.login_ex` / `auth.login_ex_continue`:
**tagged-union mechanisms** in, **tagged-union responses** out, with a two-step OTP
flow. Model the credentials and responses as `msgspec` tagged unions (the discriminant
mirrors middlewared's `mechanism` / `response_type`), and mark every secret field with
`SECRET` so it is redacted in the audit trail:

```python
from typing import Annotated, Union
from truenas_pyjsonrpc import (
    JSONRPCError, JsonRpcError, SECRET, SessionLifecycle,
)

# --- login mechanisms (tagged union on "mechanism") ----------------------------
class PasswordPlain(msgspec.Struct, tag_field="mechanism", tag="PASSWORD_PLAIN"):
    username: str
    password: Annotated[str, SECRET]

class TokenPlain(msgspec.Struct, tag_field="mechanism", tag="TOKEN_PLAIN"):
    token: Annotated[str, SECRET]                      # a previously-minted reconnect token

class OtpToken(msgspec.Struct, tag_field="mechanism", tag="OTP_TOKEN"):
    otp_token: Annotated[str, SECRET]

class SetupArgs(msgspec.Struct):
    login_data: Union[PasswordPlain, TokenPlain]       # first factor

class ContinueArgs(msgspec.Struct):
    login_data: OtpToken                               # second factor

# --- responses (tagged union on "response_type") -------------------------------
class AuthSuccess(msgspec.Struct, tag_field="response_type", tag="SUCCESS"):
    username: str

class OtpRequired(msgspec.Struct, tag_field="response_type", tag="OTP_REQUIRED"):
    username: str

class AuthErr(msgspec.Struct, tag_field="response_type", tag="AUTH_ERR"):
    pass

class LoginResult(msgspec.Struct):
    response: Union[AuthSuccess, OtpRequired, AuthErr]
```

The handlers authenticate `request`, record the resulting identity on the session,
and return `(lifecycle, result)`. `session_state.server_state_internal` is the
session's server-side state: it **starts as the connection's
[`Peer`](#peer-credentials-unix--tls)** and you replace it with your identity as auth
progresses (downstream method/authorization handlers then read the identity there):

```python
def session_setup(request: SetupArgs, session_state) -> tuple:
    peer = session_state.server_state_internal         # the Peer (uid/gid/cert/tls)
    data = request.login_data

    # local AF_UNIX root is trusted without credentials (middlewared UNIX_SOCKET)
    if peer is not None and peer.transport == "unix" and peer.uid == 0:
        session_state.server_state_internal = {"user": "root"}
        return (SessionLifecycle.ESTABLISHED,
                LoginResult(AuthSuccess(username="root")))

    if isinstance(data, TokenPlain):
        user = check_token(data.token)                 # validate a reconnect/auth token
        if user is None:
            return SessionLifecycle.NONE, LoginResult(AuthErr())
        session_state.server_state_internal = {"user": user}
        return (SessionLifecycle.ESTABLISHED,
                LoginResult(AuthSuccess(username=user)))

    # PASSWORD_PLAIN
    if not check_password(data.username, data.password):
        return SessionLifecycle.NONE, LoginResult(AuthErr())     # stays unauthenticated
    if needs_two_factor(data.username):
        session_state.server_state_internal = {"pending_user": data.username}
        return SessionLifecycle.INIT, LoginResult(OtpRequired(username=data.username))
    session_state.server_state_internal = {"user": data.username}
    return (SessionLifecycle.ESTABLISHED,
            LoginResult(AuthSuccess(username=data.username)))


def session_setup_continue(request: ContinueArgs, session_state) -> tuple:
    pending = session_state.server_state_internal["pending_user"]   # set in step 1
    if not check_otp(pending, request.login_data.otp_token):
        return SessionLifecycle.INIT, LoginResult(AuthErr())        # retry the OTP
    session_state.server_state_internal = {"user": pending}
    return (SessionLifecycle.ESTABLISHED,
            LoginResult(AuthSuccess(username=pending)))
```

Wire them onto the protocol:

```python
protocol = JSONRPCProtocol(methods, name="truenas.api.v1", audit_handler=audit)
protocol.add_session_setup(
    JSONRPCMethod("$/sessionSetup", accepts=SetupArgs, returns=LoginResult,
                  handler=session_setup),
    JSONRPCMethod("$/sessionSetupContinue", accepts=ContinueArgs, returns=LoginResult,
                  handler=session_setup_continue),       # omit for single-step auth
)
```

Notes:
- **Failure handling.** Return `AUTH_ERR` (a normal result, session stays
  un-`ESTABLISHED`) for a *bad credential* — like middlewared. Reserve
  `raise JsonRpcError(JSONRPCError.NOT_AUTHORIZED, ...)` for a hard error you want
  surfaced as a JSON-RPC error rather than an auth response.
- **Always audited.** Setup bypasses the `authorization_handler` (it *is* the auth
  step) but is **always** sent to the `audit_handler`, with `SECRET` fields redacted —
  including secrets nested inside the tagged-union mechanisms.
- **Single-step.** Omit the second argument to `add_session_setup` if you don't need
  a continue/2FA step; then `$/sessionSetup` simply returns `ESTABLISHED`.
- After `ESTABLISHED`, the identity you stored is on `session_state.server_state_internal`
  for your `authorization_handler` and method handlers; the `result` is echoed to the
  client and kept on `server_state_external`.

> **Emitting the audit trail?** The opt-in
> [`truenas_pyjsonrpc.mixins.audit`](../truenas_pyjsonrpc/mixins/audit) layer is a drop-in
> `audit_handler` that writes middleware-style `@cee:`/`TNAUDIT` JSON to syslog — `METHOD_CALL`
> vs `CONTROL_MESSAGE` events, secrets already redacted. Pass `SyslogAuditHandler(service="…")`
> as `audit_handler=` with `use_audit_queue=True`, or mix in `TrueNASAuditMixin`.

## Peer credentials (UNIX & TLS)

Every connection carries a `Peer` (seeded as the session's `server_state_internal`
before setup), so a setup handler can authenticate by transport instead of, or in
addition to, credentials:

```python
class Peer(NamedTuple):        # truenas_pyjsonrpc_server.Peer
    transport: str            # "unix" | "tcp"
    uid: int | None           # AF_UNIX peer (SO_PEERCRED) — e.g. 0 == local root
    gid: int | None
    pid: int | None
    address: object           # TCP peer address
    tls: bool                 # True when the (TCP) connection is encrypted
    peercert: object          # client certificate dict for mutual TLS
    cipher: object            # negotiated (name, tls_version, bits)
```

- **`UNIX_SOCKET`** auth: trust `peer.uid == 0` on `transport == "unix"` (above).
- **mTLS** auth: read `peer.peercert` (requires a server `ssl` context with
  `verify_mode = CERT_REQUIRED`) and map the certificate subject to a user.
- **`secure_transport`**: gate sensitive mechanisms on `peer.tls`.

## Transports & TLS

```python
import ssl
from truenas_pyjsonrpc_server import TCPConfig, UnixConfig, WebSocketConfig

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("server.pem", "server.key")
# ctx.verify_mode = ssl.CERT_REQUIRED; ctx.load_verify_locations("ca.pem")  # mTLS

server = JSONRPCServer(
    {"truenas.api.v1": protocol},
    name="truenas",
    unix_config=UnixConfig(path="/var/run/truenas-api.sock", mode=0o660),  # group-accessible
    tcp_config=TCPConfig(host="0.0.0.0", port=6000, ssl=ctx),              # length-prefixed TLS
    websocket_config=WebSocketConfig(host="0.0.0.0", port=6443, ssl=ctx),  # wss:// (needs extra)
)
```

`ssl` is configured **per transport** (the `ssl=` field of `TCPConfig` /
`WebSocketConfig`; AF_UNIX uses peer credentials). You can run several transports at
once — e.g. an unauthenticated-by-uid local socket *and* a TLS TCP port. The
**WebSocket** transport (`WebSocketConfig`, `ws://` / `wss://`) needs the optional
`websockets` dependency (`pip install truenas_pyjsonrpc[websocket]`) and does **not**
support raw-fd transfers (see below).

## Raw-fd transfers (sendfile/recvfile)

For a **bulk, self-delimiting stream** — e.g. piping a `zfs send`/`recv` stream through
libzfs (`lzc_send` / `lzc_receive`) directly on the socket — a `JSONRPCFdTransferMethod`
hands its handler the connection's **raw socket fd** for the duration of the stream,
then the connection resumes normal JSON-RPC. The server runs the wire handshake and the
transfer callback (in the thread pool) for you; see
[ARCHITECTURE §6](../truenas_pyjsonrpc/ARCHITECTURE.md#6-raw-fd-transfer-bulk-streams)
for the protocol.

Define one with a `negotiate` callback (validates the request, returns an interim
"ready" value) and a `transfer` callback (gets a `FileTransfer` carrying the fd):

```python
import hashlib, tempfile
from truenas_pyjsonrpc import JSONRPCFdTransferMethod, TransferDirection

class SendArgs(msgspec.Struct):
    dataset: str

class SendResult(msgspec.Struct):
    sent: int

def send_negotiate(request: SendArgs, session_state):
    return {"dataset": request.dataset}          # -> client as $/transferReady result

def send_transfer(ft) -> SendResult:             # runs in the thread pool (it blocks)
    # ft.fileno() is the blocking, plaintext socket fd — hand it to libzfs:
    #   sent = lzc_send(ft.params.dataset, fromsnap, ft.fileno(), flags)
    # (here: a stand-in that os.sendfile()s a temp file straight onto the wire)
    with tempfile.TemporaryFile() as f:
        ...
        sent = ft.sendfile(f)
    return SendResult(sent=sent)

method = JSONRPCFdTransferMethod(
    "replication.send", accepts=SendArgs, returns=SendResult,
    direction=TransferDirection.DOWNLOAD,        # server produces, client consumes
    negotiate=send_negotiate, transfer=send_transfer,
    audit=True, audit_message="zfs send")
```

`UPLOAD` (client produces, server consumes) is symmetric — the `transfer` callback
**reads** the fd (`ft.recvfile(...)` / `lzc_receive(ft.fileno(), ...)`). Transfer
methods are gated and authorized exactly like normal methods, and the final result is
validated and audited the same way.

**Encryption & transport.** The fd carries plaintext, so a transfer needs a **plain**
(AF_UNIX / plain TCP) **or kTLS** connection; over ordinary asyncio `ssl=` (memory-BIO)
the fd is ciphertext, and over a **WebSocket** the `websockets` library owns the wire —
both **reject** the transfer (`REQUEST_FAILED`). For encryption enable kTLS — the kernel
does the record crypto, so the fd stays plaintext to your handler:

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("server.pem", "server.key")
ctx.options |= ssl.OP_ENABLE_KTLS                # kernel TLS: plaintext fd, encrypted wire
server = JSONRPCServer({"truenas.api.v1": protocol}, name="truenas",
                       tcp_config=TCPConfig(host="0.0.0.0", port=6000, ssl=ctx))
```

kTLS needs OpenSSL built with kTLS, the kernel `tls` module, and an AES-GCM/ChaCha20
cipher; the server disables TLS 1.3 session tickets (`num_tickets = 0`) automatically
(they would break the peer's kernel-side RX). If kTLS can't engage the handshake fails
**loudly** rather than silently leaving ciphertext on the fd.

A complete, runnable server (a `lookup` + `get`/`put` file share, both directions) is in
[`examples/fileshare.py`](../examples/fileshare.py), driven end-to-end by
[`examples/fileshare_demo.py`](../examples/fileshare_demo.py).

**A transfer owns its connection.** While one runs, that connection processes nothing else
— no other request, `$/progress`, or `$/cancelRequest` — until the stream ends. For long
transfers the recommended client pattern is a **dedicated connection** (run the transfer
on its own connection, keep a separate command connection free); a protocol-level data
channel bound to the command session is a possible future extension (see
[ROADMAP](../ROADMAP.md)).

**Passing file descriptors (`JSONRPCFdPassMethod`).** Over an **AF_UNIX** connection a
method can hand the peer an *actual open fd* (a device, a privileged file, a memfd) via
`SCM_RIGHTS` instead of streaming bytes — the privilege-broker pattern. It's a transfer
method whose `transfer` callback calls `ft.send_fds([...])` / `ft.recv_fds(maxfds)`:

```python
from truenas_pyjsonrpc import JSONRPCFdPassMethod, TransferDirection

def open_negotiate(request, session_state):
    return {"count": 1}                                  # client sizes recv_fds from this

def open_transfer(ft):
    fd = os.open(f"/dev/{ft.params.name}", os.O_RDONLY)  # the privileged open
    try:
        ft.send_fds([fd])
    finally:
        os.close(fd)
    return OpenResult(count=1)

JSONRPCFdPassMethod("dev.open", accepts=OpenArgs, returns=OpenResult,
                    direction=TransferDirection.DOWNLOAD,
                    negotiate=open_negotiate, transfer=open_transfer)
```

**AF_UNIX only** (rejected `REQUEST_FAILED` over TCP/WebSocket/TLS); the receiver owns the
passed fds. Gate which fd a caller may obtain with the usual authorization handler — passing
an fd grants the peer the open file's access.

## Client & codegen

The companion `truenas_pyjsonrpc_client.BaseClient` is a thread-safe client that
drives this flow (`connect()` → `setup(...)` → `call(...)`), over the matching
transport (`UnixConfig` / `TCPConfig` / `WebSocketConfig`). It also routes
server→client messages: `subscribe(topic,
callback=...)` delivers each pub/sub event to a callback, and `call(..., progress=cb)`
delivers that call's `$/progress` notifications — both invoked on a dedicated
backchannel thread (so a callback may block and may re-enter `call()`/`unsubscribe()`).
`unsubscribe(sub_id)` cancels the subscription server-side via `$/cancelRequest`.
Generate a strongly-typed client
(one method per protocol method — including `subscribe_<topic>(request, callback=...)`
with a typed payload — reusing the protocol's Structs) with:

```
python codegen.py mypkg.api:protocol --out client_gen.py
```

See the [client README](../truenas_pyjsonrpc_client/README.md), the
[`examples/`](../examples/) directory (`serve_async.py`, `client_async.py`,
`serve_ws.py`, `client_ws.py`, generated `client_gen.py`), and the
[Server & client](../README.md#server--client) overview for a full round-trip.
