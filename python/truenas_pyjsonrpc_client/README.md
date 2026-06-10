# truenas_pyjsonrpc_client

A **thread-safe client** for a [`truenas_pyjsonrpc_server`](../truenas_pyjsonrpc_server)
endpoint (JSON-RPC over AF_UNIX, TCP, or WebSocket, optionally TLS). The connection runs on a
dedicated asyncio loop in a background thread, but the public API is **synchronous and
thread-safe**: open one connection, then have arbitrary application threads issue calls
concurrently. Designed for the "one shared connection to a microservice, many worker
threads" pattern.

- [How it works](#how-it-works) · [Quickstart](#quickstart) ·
  [Concurrency](#concurrency) ·
  [Backchannel: notifications, progress, subscriptions](#backchannel-notifications-progress-subscriptions) ·
  [TLS](#tls) · [Raw-fd transfers](#raw-fd-transfers) · [Naming](#naming) ·
  [Typed client (codegen)](#typed-client-codegen)

## How it works

The connection lives on one asyncio **IO loop thread**; application threads call the
synchronous API, which hands work to that loop and blocks on the result. Server->client
messages are handed to a separate **backchannel thread** that runs your callbacks (so a
callback may block, and may re-enter `call()`):

```
   app threads                       IO loop thread (asyncio)            server
   -----------                       ------------------------            ------
   t1  -call()--+                    owns the one socket:
   t2  -call()--+--run_coroutine-->  - writes request frame  -------->   (socket)
   tN  -call()--+   _threadsafe      - reads frames          <--------   (socket)
        ^                            - response -> resolves the call's Future
        |  result (or raises)              |
        +----------------------------------+
                                     - server->client message
                                           |  enqueue
                                           v
                                     backchannel thread  -->  your callbacks
                                     (drains queue, ordered;   (progress / sub events
                                      may re-enter call())      / notifications)
```

Connect once, then call concurrently:

```
   connect()             setup()                  call() / subscribe()
   --$/negotiate-->      --$/sessionSetup-->      (concurrent, thread-safe)
   bind the protocol     authenticate
                         (-> ESTABLISHED)
```

## Quickstart

```python
from truenas_pyjsonrpc_client import BaseClient, TCPConfig, UnixConfig

client = BaseClient("truenas.api.v1",
                    unix_config=UnixConfig(path="/var/run/truenas-api.sock"))
client.connect()                                  # $/negotiate the protocol
client.setup({})                                  # $/sessionSetup: AF_UNIX peer credentials
result = client.call("pool.create", {"name": "tank"})   # -> result
client.close()                                    # $/sessionClose + tear down
```

Or as a context manager (`connect` on enter, `close` on exit):

```python
with BaseClient("truenas.api.v1",
                tcp_config=TCPConfig(host="127.0.0.1", port=6000)) as client:
    client.setup({...})
    client.call("core.ping")
```

The flow is **`connect()` → `setup()` [→ `setup_continue()`] → `call()`** — see the
[server's auth stack](../truenas_pyjsonrpc_server/README.md#authentication-stack-middlewared-style).
`call(method, params)` returns the result or raises
`truenas_pyjsonrpc.JsonRpcError` on an error response; a transport/protocol fault
raises `ClientError`.

## Concurrency

`call()` is **safe to invoke from many threads at once** on a single client — requests
correlate to responses by a per-call UUID id, so responses can't cross wires. Establish
the session once (`connect` + `setup`, single-threaded), then fan the client out to
worker threads:

```python
def worker(c):
    for job in jobs:
        c.call("pool.create", {"name": job})     # concurrent calls are fine

threads = [threading.Thread(target=worker, args=(client,)) for _ in range(8)]
```

(`connect`/`setup`/`close` are lifecycle operations — do them once, not concurrently.)

## Backchannel: notifications, progress, subscriptions

Server→client messages are handled on a dedicated **backchannel thread** (separate
from the IO loop), so a callback **may block and may safely call `client.call()`** (or
`subscribe`/`unsubscribe`). Delivery is **ordered** (single thread) — hand heavy work
off if a slow callback would hold up later ones. An inbound server->client frame is
routed (on the backchannel thread) by:

```
   $/progress {id, ...}   --by request id-->   the call(..., progress=cb) callback
   <topic> {payload}      --by topic name-->   subscribe(topic, callback=cb) callback(s)
   (anything unrouted)    ------------------>   on_notification(method, params)
                                                (or the notifications queue, if no handler)
```

The three routes in code:

```python
# 1. per-call progress: this call's $/progress notifications -> progress(params)
client.call("pool.create", {"name": "tank"},
            progress=lambda p: print(p["percent"], p.get("description")))

# 2. pub/sub: subscribe to a topic; callback fires per published event
sub_id = client.subscribe("zpool.events", callback=lambda event: handle(event))
client.unsubscribe(sub_id)        # sends $/cancelRequest -> server stops publishing

# 3. fallback: anything not routed above goes to on_notification, or the queue
client = BaseClient(..., on_notification=lambda method, params: ...)
#   ...or, with no callback, poll the thread-safe queue:
method, params = client.notifications.get()
```

`unsubscribe(sub_id)` is a real **wire-level** unsubscribe: it sends `$/cancelRequest`
so the server drops the subscription (and clears the local callback). Subscriptions are
also dropped server-side automatically when the connection closes.

## TLS

```python
import ssl
from truenas_pyjsonrpc_client import TCPConfig, WebSocketConfig
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations("ca.pem")               # ctx.load_cert_chain(...) for mTLS
client = BaseClient("truenas.api.v1",
                    tcp_config=TCPConfig(host="truenas", port=6000,
                                         ssl=ctx, server_hostname="truenas"))
# ...or over wss:// (needs the optional `websockets` dependency):
wss = BaseClient("truenas.api.v1",
                 websocket_config=WebSocketConfig(host="truenas", port=6443,
                                                  ssl=ctx, server_hostname="truenas"))
```

## Raw-fd transfers

To consume or produce a **bulk, self-delimiting stream** over the connection's raw
socket fd (e.g. drive libzfs `lzc_receive` / `lzc_send` for `zfs recv`/`send`), use
`transfer()`. It sends the request, runs the `$/transferReady` handshake, then calls
your `callback(file_transfer)` **on the calling thread** with exclusive access to the
plaintext socket fd (`file_transfer.fileno()`), and returns the server's final result:

```python
import io
buf = io.BytesIO()
result = client.transfer(
    "file.download", {"path": "/data/blob"},     # a DOWNLOAD: the server produces
    callback=lambda ft: ft.recvfile(buf, ft.result["size"]))
#   ^ ft.fileno() is the blocking, plaintext fd; ft.result is what the server's
#     negotiate returned in $/transferReady (here, the byte count to read off it)
```

For an `UPLOAD` the callback **produces** the stream (`ft.sendfile(f)` /
`lzc_send(..., ft.fileno(), ...)`). The negotiated interim value is on `ft.result` —
the server's channel to tell the client about the stream (a `DOWNLOAD` byte count, an
offset, …); the request you sent is on `ft.params`. A transfer **monopolizes the
connection** — no concurrent `call()` while it runs (it raises `ClientError` if one is
already in flight). `recvfile` / `sendfile` are convenience helpers for the plain-file
case; the real use is handing `fileno()` to a C library. The generated client
([codegen](#typed-client-codegen)) exposes each transfer method as a typed
`file_download(request, *, callback) -> Result`. A complete, runnable bi-directional
example (a `lookup` + `get`/`put` file share) is in
[`examples/fileshare.py`](../examples/fileshare.py) +
[`fileshare_demo.py`](../examples/fileshare_demo.py).

**Long transfers — use a dedicated connection.** A transfer owns its connection for the
whole stream, so a long one (e.g. a multi-GB `zfs send`) blocks other `call()`s,
`$/progress`, and even cancellation on that connection until it finishes. To keep a
command channel responsive, run the transfer on a **separate** `BaseClient` (its own
connection) and keep the first free — a transfer is a self-contained, authorized request,
so this is pure client-side connection management (the FTP control/data split) and needs
no protocol support. (A protocol-level data channel bound to the command session is a
possible future extension — see [ROADMAP](../ROADMAP.md).)

**Encryption & transport.** Like the server, a transfer needs a **plain or kTLS**
connection (over ordinary `ssl=` the fd is ciphertext, and over a **WebSocket** the
`websockets` library owns the wire — both reject the transfer). Enable kTLS to match a
kTLS server — the kernel does the crypto, so the fd stays plaintext:

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations("ca.pem")
ctx.options |= ssl.OP_ENABLE_KTLS                # plaintext fd, encrypted wire
client = BaseClient("truenas.api.v1",
                    tcp_config=TCPConfig(host="truenas", port=6000,
                                         ssl=ctx, server_hostname="truenas"))
```

**Passing / receiving file descriptors.** Against a `JSONRPCFdPassMethod` over an
**AF_UNIX** connection, `recv_fds(method, params) -> (result, fds)` receives fds the server
passes (you **own** them and must close them) and `send_fds(method, params, fds=[...]) ->
result` passes fds to the server:

```python
result, fds = client.recv_fds("dev.open", {"name": "null"})
try:
    ...                              # fds are new fds for the server's open files
finally:
    for fd in fds:
        os.close(fd)
```

Both require an AF_UNIX client (`ClientError` otherwise).

## Naming

`name` (default: the protocol name) labels the client's threads
(`jsonrpc-client[<name>]` and `…-backchannel`), so a process holding several clients is
easy to read in `threading.enumerate()` / a debugger:

```python
ds = BaseClient("directoryservices.v1",
                unix_config=UnixConfig(path="/run/ds.sock"), name="ds")
# threads: "jsonrpc-client[ds]", "jsonrpc-client[ds]-backchannel"
```

## Typed client (codegen)

Generate a strongly-typed `BaseClient` subclass from a protocol — one method per
protocol method, reusing the protocol's `accepts`/`returns`/`notifies` Structs — with
the repo's build-time tool:

```
python codegen.py mypkg.api:protocol --out client_gen.py
```

It emits `pool_create(self, request: PoolCreateArgs, *, progress=None) ->
PoolCreateResult`, `subscribe_<topic>(self, request, *, callback=...) -> str` (the
callback receives the decoded `notifies` Struct), and a `TOPICS` map. Regenerate when
the protocol changes; the generated module imports only this package + the protocol's
Struct modules. See [`examples/`](../examples/) (`client_async.py`, `client_ws.py`,
`client_gen.py`) and the [Server & client](../README.md#server--client) overview.
