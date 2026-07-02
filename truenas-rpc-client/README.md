# truenas-rpc-client

The async **client engine** for [`truenas-rpc`](../truenas-rpc) — the mirror of the server's
neutral-core / per-protocol-layer split. A protocol-agnostic `Client<P>` owns the connection (a
receive task, a writer task, reply correlation, notification fan-out); a `ProtocolRuntime` supplies
the wire specifics, and optional **capability traits** each unlock one method. The built-in
`JsonRpcClient` is the engine over the hand-written JSON-RPC runtime; a codegen'd typed client
(`truenas-rpc-codegen`) rides the neutral `CallEngine` seam.

It does socket I/O (and kTLS / `SCM_RIGHTS` behind features), so — like `truenas-rpc-server` — it is
excluded from the workspace default members and held to a behavioral coverage **floor** (the
workspace's `coverage-client.sh`), not the core `coverage.sh` line floor.

## Transports

Build an `Endpoint` and `JsonRpcClient::connect_negotiate(&endpoint, protocol, config)`:

| `Endpoint::` | Transport | Feature | Raw-fd transfer |
|---|---|---|---|
| `unix(path)` | AF_UNIX | — | ✅ |
| `tcp("host:port")` | plain TCP | — | ✅ |
| `tls("host:port", server_name, ClientTls)` | kernel TLS | `tls` | ✅ (plaintext fd) |
| `ws("host:port", "/path")` | WebSocket / TCP | `websocket` | ❌ |
| `ws_unix(path)` | WebSocket / AF_UNIX | `websocket` | ❌ |
| `wss("host:port", server_name, "/path", ClientTls)` | WebSocket / userspace TLS | `tls` + `websocket` | ❌ |

A direct `tls://` connection uses **kernel TLS** and fails closed if the kernel doesn't install the
record crypto (no silent ciphertext-fd fallback). `ws`/`wss` carry one JSON-RPC frame per message.

## Capabilities

- **Call / subscribe** — `Client::call`, `call_with_progress` (streams `$/progress`), the generated
  `subscribe_*` (notifications arrive on the `NotificationStream`), and `Client::unsubscribe`.
- **Authenticate** — `authenticate_scram(user, password)` (SCRAM-SHA-512-PLUS, bound to the TLS
  channel binding; feature `scram`), plus `authenticate_mtls` / `_oauth` / `_bearer` / `_peercred` /
  `_otp`, or a custom `Mechanism` via `authenticate_with`.
- **Raw-fd transfer** — `Client::transfer` lends the blocking connection fd to a callback for a
  self-delimiting bulk stream (`sendfile` / `splice` zero-copy). AF_UNIX / kTLS only.
- **fd passing** (feature `fd-passing`) — `send_fds` / `recv_fds` over `SCM_RIGHTS`. AF_UNIX only.
- **Close** — `Client::close` (`$/sessionClose`); dropping a call future fires a best-effort
  `$/cancelRequest` (cancel-on-drop). There is **no per-call timeout** — a request is outstanding
  until answered; wrap the future in `tokio::time::timeout` to bound it.

A capability a transport can't host is refused, not silently ignored: `transfer` / `send_fds` over
TLS-userspace or WebSocket return `ClientError::NoTransfer`.

## Features

`tls` (system OpenSSL, kTLS), `websocket` (tokio-tungstenite), `scram` (implies `tls`), `fd-passing`
(`SCM_RIGHTS` via `nix`). A default build pulls **none** of them (AF_UNIX + TCP only).

## Dependencies

`truenas-rpc` (the shared `JsonRpcError` / `Secret` / `QueryFilters` / `QueryOptions`), `truenas-xdr`
(the binary sub-wire), `tokio`, `socket2`, plus the per-feature crates above. See `examples/demo` for
an end-to-end generated-client-against-a-live-server round-trip.
