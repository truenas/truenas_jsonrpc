# Building a service with truenas_pyjsonrpc

A start-to-finish walkthrough for standing up a project on this library and **evolving
it across API versions**. It is the ordered "what do I do, in what order" companion to
the two reference docs:

- **[README.md](README.md)** — the per-feature reference (methods, authz/audit, pub/sub,
  cancellation, server, client, codegen, OpenRPC). This guide links into it rather than
  repeating it.
- **[truenas_pyjsonrpc/ARCHITECTURE.md](truenas_pyjsonrpc/ARCHITECTURE.md)** — the
  internals (session state machine, `$/` control messages, server-integration contract).

The shape of a project is five steps, then two operational habits that keep the whole
thing honest as it grows:

[1. Declare a protocol per API version](#step-1-declare-a-protocol-per-api-version) ·
[2. Declare your methods](#step-2-declare-your-methods) ·
[3. Set up the server](#step-3-set-up-the-server) ·
[4. Generate the client](#step-4-generate-the-client) ·
[5. Generate the OpenRPC document](#step-5-generate-the-openrpc-document) ·
[Keep generated code in a dedicated directory](#keep-generated-code-in-a-dedicated-directory) ·
[Catch drift in CI](#catch-drift-in-ci) ·
[Evolving the API: from v1 to v2](#evolving-the-api-from-v1-to-v2) ·
[Recap](#recap)

The running example is a fictional `myapp` package. (Class names use the real API —
your shorthand "JSONProtocol" is `JSONRPCProtocol`.)

## Step 1: Declare a protocol per API version

A **`JSONRPCProtocol`** is one API version: a name-keyed table of methods plus two
required identity fields.

- **`name`** — the discriminator a client selects at `$/negotiate` (and the default
  OpenRPC `info.title`). Make it version-bearing, e.g. `"myapp.v1"`.
- **`version`** — an arbitrary contract string (the default OpenRPC `info.version`).

**Versioning is per-protocol, not per-method**: each API version is its own
`JSONRPCProtocol` instance, and the server can host several at once (see
[Evolving the API](#evolving-the-api-from-v1-to-v2)). Keep your request/response
`msgspec.Struct`s and the protocol that references them in an **importable module** —
steps 4 and 5 import this module by path, and they reject types defined in `__main__`.

```python
# myapp/api/v1.py — the v1 surface: request/response Structs + the protocol.
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


protocol = JSONRPCProtocol(
    [
        JSONRPCMethod("pool.create", accepts=PoolCreateArgs,
                      returns=PoolCreateResult, handler=pool_create),
    ],
    name="myapp.v1",          # the $/negotiate key clients select
    version="1.0.0",          # arbitrary contract version string
)
```

`JSONRPCProtocol(methods=(), *, name, version, authorization_handler=None,
audit_handler=None, cancellation_handler=None, use_audit_queue=False)` — `name` and
`version` must be non-empty.

## Step 2: Declare your methods

Each method is a **`JSONRPCMethod`** binding a wire name to typed `accepts`/`returns`
Structs and a handler:

```python
JSONRPCMethod(name, *, accepts, returns=None, handler=None, doc=None,
              pre_auth=False, audit=False, audit_message=None, cancellable=False,
              roles=(), direction=MessageDirection.CLIENT_SERVER, notifies=None, ...)
```

The protocol always calls the handler **by keyword** —
`handler(request=<typed accepts>, session_state=..., request_state=...)` — and validates
its return against `returns` (omit `returns` for a void method). A method that takes no
params still declares an empty Struct:

```python
class NoParams(msgspec.Struct):
    pass
```

You rarely need more than that to start. Reach for these as the API grows — each links
to the full treatment in the README so this guide stays short:

| Want to… | Use | Reference |
| --- | --- | --- |
| Declare a method from its handler | `@jrpc_method(accepts=…, protocols=[protocol])` | [Defining methods](README.md#defining-methods) |
| Authorize / audit a call | `roles=[…]`, `audit=True`, `audit_message="…"` | [Authorization & audit](README.md#authorization--audit) |
| Push server→client events (pub/sub) | `direction=MessageDirection.SERVER_CLIENT`, `notifies=Event` | [Pub/sub](README.md#pubsub-subscribable-methods) |
| Let a long call be aborted | `cancellable=True` | [Cancellation](README.md#cancellation) |
| Allow a call before login (e.g. auth) | `pre_auth=True` | [Sessions & authentication](README.md#sessions--authentication) |
| Stream bulk bytes over the raw fd | `JSONRPCFdTransferMethod` / `JSONRPCFdPassMethod` | [ARCHITECTURE §6](truenas_pyjsonrpc/ARCHITECTURE.md#6-raw-fd-transfer-bulk-streams) |

[`examples/serve.py`](examples/serve.py) shows a protocol exercising most of these in
one place (a normal audited call, a pub/sub topic, and a raw-fd transfer).

## Step 3: Set up the server

The dispatch core is transport-agnostic; `truenas_pyjsonrpc_server` is the turnkey
asyncio server. Hand it a **`{name: protocol}` map** (the keys are what clients
negotiate) and at least one transport config:

```python
# myapp/server.py
import asyncio
from truenas_pyjsonrpc_server import JSONRPCServer, UnixConfig

from myapp.api import v1


async def main() -> None:
    async with JSONRPCServer({"myapp.v1": v1.protocol}, name="myapp",
                             unix_config=UnixConfig(path="/var/run/myapp.sock")) as server:
        print(f"serving {server.protocol_names}")
        await asyncio.Event().wait()          # run until interrupted


asyncio.run(main())
```

Transports: **`UnixConfig(path, mode=0o660)`**, **`TCPConfig(host, port, ssl=None)`**,
**`WebSocketConfig(host, port, ssl=None, …)`** (pass more than one to serve several at
once; TLS is the `ssl=` field). The connection flow is
**`$/negotiate → $/sessionSetup → calls`**.

> **Network transports require authentication.** Configuring `tcp_config` or
> `websocket_config` for a protocol that has no session setup raises `ValueError` at
> construction. AF_UNIX is exempt (it relies on peer credentials). Add authentication by
> registering a `$/sessionSetup` method on the protocol:
>
> ```python
> from truenas_pyjsonrpc import JSONRPCMethod
> v1.protocol.add_session_setup(JSONRPCMethod(
>     "$/sessionSetup", accepts=LoginArgs, returns=LoginResult, handler=login))
> ```
>
> For a real authentication stack (PAM/SCRAM via the opt-in mixins), see
> [A full application](README.md#a-full-application) and
> **[truenas_pyjsonrpc_server/README.md](truenas_pyjsonrpc_server/README.md)**.

Runnable servers: [`examples/serve_async.py`](examples/serve_async.py) (AF_UNIX),
[`examples/serve_ws.py`](examples/serve_ws.py) (WebSocket).

## Step 4: Generate the client

`codegen.py` introspects a live protocol and emits a strongly-typed
`BaseClient` subclass that **reuses your `accepts`/`returns` Structs** (it imports them
from their defining module, so the client validates against the exact same types the
server does). It is a **build-time tool** run from a place where both
`truenas_pyjsonrpc` and your `myapp` package are importable:

```sh
python codegen.py myapp.api.v1:protocol --out generated/v1_client.py
```

Flags: `--class-name` (default: derived from the protocol name), `--protocol-name` (the
name to `$/negotiate`, default: the protocol's own `name`), `--out` (default: stdout).
The output carries a `# Generated … do not edit by hand.` header; each method becomes a
typed call, each pub/sub topic a `subscribe_*` plus a `TOPICS` map, and each transfer a
callback method:

```python
# Generated by truenas_pyjsonrpc codegen — do not edit by hand.
class MyappV1Client(BaseClient):
    def pool_create(self, request: PoolCreateArgs, *, progress=None) -> PoolCreateResult:
        return self._typed_call('pool.create', request, PoolCreateResult, progress=progress)
    # subscribe_<topic>(...) and TOPICS appear here for SERVER_CLIENT methods
```

```python
client = MyappV1Client(unix_config=UnixConfig(path="/var/run/myapp.sock"))
client.connect()                                   # $/negotiate
client.setup({"token": "…"})                       # $/sessionSetup
result = client.pool_create(PoolCreateArgs(name="tank"))   # typed in, typed out
client.close()
```

> Because the generated client `import`s your Structs, they must live in an **importable
> module — never `__main__`** — and no two Structs may share a `__name__` (codegen
> rejects the collision). This is the main reason Step 1 keeps Structs in `myapp/api/`.

**Or hand-write the client.** The generated class is a thin typed shell over
`BaseClient`. If your client needs custom batching, retry, caching, multiplexing, or
wraps several protocols, subclass `BaseClient` directly and use its primitives —
`connect()`, `setup()`, `call(method, params, *, progress=…)`,
`subscribe(topic, params, *, callback=…)`, `transfer(method, params, *, callback=…)`,
`close()`. See [Server & client](README.md#server--client) and
**[truenas_pyjsonrpc_client/README.md](truenas_pyjsonrpc_client/README.md)**.

## Step 5: Generate the OpenRPC document

`openrpc_gen.py` emits a spec-valid [OpenRPC](https://spec.open-rpc.org/) service
description — the JSON-RPC analogue of OpenAPI — usable for docs, request validators,
mock servers, and **cross-language** client generators. Same build-time invocation:

```sh
python openrpc_gen.py myapp.api.v1:protocol --out openrpc/myapp.v1.json
```

It produces an `openrpc: "1.3.2"` document whose `info.title`/`info.version` default to
the protocol's `name`/`version` (override with `--title`/`--version`). Each method's
`accepts` is decomposed into by-name `params`; `returns` becomes the `result` (omitted
for void / pub-sub methods); pub/sub, fd-transfer, and `roles` metadata surface as `x-*`
extensions; and every Struct lands once under `components.schemas`. Other flags:
`--openrpc-version`, `--no-errors` (drop the error taxonomy). Like codegen this is
build-time — there is no over-the-wire discovery RPC.

> **Both generators ship as scripts, not installed console commands** (there is no
> `[project.scripts]` entry point). Vendor `codegen.py` and `openrpc_gen.py` into your
> project (e.g. a `tools/` dir) and run them with `python tools/codegen.py …`. They need
> `truenas_pyjsonrpc` importable and your `myapp` package on the path.
>
> *In this repo* you can run them against the bundled example to see real output:
> ```sh
> PYTHONPATH=examples python3 codegen.py serve:protocol --out /tmp/client.py
> PYTHONPATH=examples python3 openrpc_gen.py serve:protocol --out /tmp/openrpc.json
> ```

## Keep generated code in a dedicated directory

Both generators are **pure functions of your protocol** — same protocol in, same bytes
out. That makes their output a checked-in *artifact of the contract*, not source to
edit. Give it a dedicated directory and **commit it**, so a protocol change shows up as
a reviewable diff of the client and the OpenRPC doc:

```
myapp/
  api/
    __init__.py
    v1.py            # Structs + protocol = JSONRPCProtocol(name="myapp.v1", version="1.0.0")
  server.py          # JSONRPCServer({"myapp.v1": v1.protocol}, ...)
  generated/         # committed, CI-checked — DO NOT EDIT
    v1_client.py
  openrpc/
    myapp.v1.json
  tools/             # vendored build-time generators
    codegen.py
    openrpc_gen.py
```

Wire the regen into one command so it is trivial to rerun (a `Makefile` target works
well):

```sh
# make codegen
python tools/codegen.py     myapp.api.v1:protocol --out generated/v1_client.py
python tools/openrpc_gen.py myapp.api.v1:protocol --out openrpc/myapp.v1.json
```

## Catch drift in CI

A committed artifact is only trustworthy if CI guarantees it matches the protocol. Add a
job that **regenerates and diffs**: if a method or Struct changed without someone
rerunning codegen, `git diff --exit-code` fails the build. This turns "I forgot to
regenerate the client" into a red check instead of a silently stale contract.

A starting-point GitHub Actions workflow (adapt paths/versions to your project — this is
a template, not a file this repo ships):

```yaml
name: API contract check
on: [pull_request, push]
jobs:
  codegen-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.13" }
      - run: pip install msgspec   # plus truenas_pyjsonrpc and your package
      - name: Regenerate client + OpenRPC artifacts
        run: |
          python tools/codegen.py     myapp.api.v1:protocol --out generated/v1_client.py
          python tools/openrpc_gen.py myapp.api.v1:protocol --out openrpc/myapp.v1.json
      - name: Fail if artifacts are stale (rerun codegen and commit)
        run: git diff --exit-code -- generated/ openrpc/
```

## Evolving the API: from v1 to v2

Because each version is a separate protocol negotiated by name, you can run v1 and v2
**side by side** and migrate clients on their own schedule. The gameplan:

1. **Freeze v1.** Leave `api/v1.py` (`name="myapp.v1"`, `version="1.0.0"`) and its
   committed `generated/v1_client.py` untouched. Existing clients keep negotiating
   `"myapp.v1"` and keep their exact validated types.
2. **Add `api/v2.py`** with `protocol = JSONRPCProtocol([...], name="myapp.v2",
   version="2.0.0")`. **Reuse** unchanged Structs by importing them from a shared module;
   **fork** only the ones whose shape changes (e.g. a new `PoolCreateArgsV2`) so a v1
   client's contract never shifts under it. Add, remove, or rename methods freely in v2.
3. **Register both** on the server — the map can hold any number of versions:
   ```python
   from myapp.api import v1, v2
   JSONRPCServer({"myapp.v1": v1.protocol, "myapp.v2": v2.protocol}, name="myapp", ...)
   ```
   Old clients hit v1, new clients negotiate v2. (On a network transport each protocol
   still needs its own `add_session_setup`.)
4. **Generate v2 artifacts** into the same dedicated dir
   (`generated/v2_client.py`, `openrpc/myapp.v2.json`) and commit them; the CI drift
   check now covers every live version.
5. **Diff the contracts.** The two `openrpc/*.json` files are a machine-readable diff of
   exactly what changed between versions — handy for changelogs and consumer review.
6. **Deprecate on your timeline.** When telemetry shows no clients negotiate `"myapp.v1"`,
   drop it from the server map and delete `api/v1.py` and its generated artifacts.

## Recap

1. Declare a **`JSONRPCProtocol`** per API version (`name`/`version`), Structs in an
   importable module.
2. Declare **`JSONRPCMethod`**s with typed `accepts`/`returns` and handlers.
3. Serve them with **`JSONRPCServer({name: protocol}, …)`** (auth required on network
   transports).
4. Generate the typed **client** (`codegen.py`) — or hand-write one over `BaseClient`.
5. Generate the **OpenRPC** doc (`openrpc_gen.py`).
6. Commit generated output to a dedicated dir and **CI-diff it** so the contract can't
   drift.
7. Evolve by adding a **new protocol per version**, served alongside the old.

Where to go next: **[README.md](README.md)** for per-feature depth ·
**[ARCHITECTURE.md](truenas_pyjsonrpc/ARCHITECTURE.md)** for the dispatch internals ·
**[truenas_pyjsonrpc_server/README.md](truenas_pyjsonrpc_server/README.md)** and
**[truenas_pyjsonrpc_client/README.md](truenas_pyjsonrpc_client/README.md)** for serving
and consuming · **[`examples/`](examples/)** for runnable end-to-end demos.
