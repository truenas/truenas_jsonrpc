# truenas-rpc-server

The optional async server transport for `truenas-rpc`. It accepts connections, frames
messages, selects a protocol per connection with `$/negotiate`, and pumps the dispatch loop.

## Public API

- `TruenasRpcServer<S>` / `TruenasRpcServerBuilder<S>`:
  - `.protocol(name, JsonRpcProtocol<S>)` — register a named protocol (the `$/negotiate`
    discriminator).
  - `.state_from_peer(|&Peer| -> Option<S>)` — derive the per-connection session state from
    the peer (defaults to `None`).
  - `.message_limit(usize)` — inbound frame cap (default 4 MiB).
  - `.allow_unauthenticated_network()` — opt a server out of the network-auth guard (below).
  - `serve_unix(UnixConfig, wire)` / `serve_tcp(addr, wire)` — bind + accept loop, serving a typed
    **`Wire`** value: `JsonRpc` (the default engine), or `OncRpc::protocol("…")` for RFC 5531 over
    AF_UNIX. Split forms (`bind_unix` + `serve_unix_listener`, `bind_tcp` + `serve_tcp_listener`) let a
    caller bind before signalling readiness. `serve_unix_listener` is trusted-local;
    `serve_proxied_unix_listener` and the TCP/TLS methods are network-facing (bound `W: NetworkWire`, so
    the AF_UNIX-only `OncRpc` is a compile error there). The server is `Clone` (an `Arc` handle), so a
    clone moves into each transport's task.
- `Peer` { `transport`, `ucred: Option<Ucred>`, `addr: Option<SocketAddr>` }, `Transport`,
  `Ucred` (pid/uid/gid from `SO_PEERCRED`).
- `UnixConfig` (path + post-bind `mode`).
- `framing` — the wire: a 4-byte big-endian length prefix over compact JSON (`frame`,
  `read_message`, `DEFAULT_LIMIT`).
- *(feature `tls`)* `TlsConfig` (+ `TlsMode::{Kernel, Userspace}`) and
  `serve_tls(addr, tls, wire)` / `serve_tls_listener` — encrypted TCP via system OpenSSL.
- `FileTransferExt` — for a `transfer` callback: blocking `write_all` / `read_exact` on the
  fd, zero-copy `sendfile` / `recvfile` (`sendfile(2)` / `splice(2)`, staying zero-copy over
  kTLS), and `send_fds` / `recv_fds` (`SCM_RIGHTS`) for a `RpcFdPassMethod` over AF_UNIX.
- *(feature `websocket`)* `serve_websocket` / `serve_websocket_listener` — JSON-RPC over
  `ws://` (one frame per WebSocket message; raw-fd transfer is refused on these connections);
  with `tls` too, `serve_wss` / `serve_wss_listener` for `wss://` (WebSocket over userspace TLS).

## Behaviour

- Per connection: an `AWAIT_NEGOTIATE → BOUND` read loop. Dispatch is pipelined (each message
  spawned) so a `$/cancelRequest` is read while a handler runs. All outbound bytes — replies
  plus pub/sub notifications pushed through the session's `Outbound` — funnel through one
  unbounded channel drained by a writer task (single ordered writer).
- Notifications are push-based via the session's `Outbound` (no drain threads).
- **Network-auth guard**: `serve_tcp` / `serve_tls` / `serve_websocket` / `serve_wss` (and their
  `*_listener` forms) refuse — returning `io::ErrorKind::InvalidInput` before accepting — to serve
  a registered protocol that has no `$/sessionSetup`, so an unauthenticated remote client can't
  reach gated methods. **AF_UNIX is exempt** (local peer-credential / filesystem trust). The check
  runs at serve time (the transport is chosen per `serve_*` call).
  Opt out with `.allow_unauthenticated_network()` when a protocol is deliberately unauthenticated.

## Status

Implemented: AF_UNIX + plain TCP, length-prefixed JSON, `$/negotiate`, `SO_PEERCRED`, pub/sub
push, pipelined dispatch/cancel, and the raw-fd **transfer takeover** — the
`$/transferReady` / `$/transferGo` handshake and the blocking fd handoff for byte-stream
download/upload over plain Unix or TCP, `SCM_RIGHTS` fd passing (`send_fds` / `recv_fds`) over
AF_UNIX, and **TLS** via system OpenSSL (the `tls` feature) in two modes (`TlsMode`): **kernel
TLS** (kTLS — handshake in userspace, then the raw kernel-encrypted fd, so the bulk transfer
stays out of userspace and raw-fd transfer works over the encrypted link; fails closed if
kTLS doesn't engage) or a **userspace** `tokio-openssl` pump (works anywhere, but no raw-fd
transfer); zero-copy `sendfile` / `recvfile` (the bulk path stays out of userspace, including
over kTLS); and **WebSocket** — `ws://` (the `websocket` feature) and `wss://` (WebSocket over
userspace TLS, with `tls` + `websocket`), one JSON-RPC frame per WS message, no raw-fd transfer
over either. All planned transport work is in.

## Usage

```rust
let proto = JsonRpcProtocol::<()>::builder("conf", "1").method(/* … */).build();
let server = TruenasRpcServer::<()>::builder("my-server")
    .protocol("main", proto)
    .build();
server.serve_unix(UnixConfig::new("/run/my.sock"), JsonRpc).await?;
```

## Dependencies / build

Default: `truenas-rpc`, `serde`, `serde_json`, `tokio` (`net` etc. → `mio` + `socket2`),
`libc` (`SO_PEERCRED`, the kTLS `getsockopt` probe, the blocking-fd toggle), `bytes` (the
cancel-safe read buffer), and `nix` (`SCM_RIGHTS` `sendmsg`/`recvmsg`). The `tls` feature adds
the system-OpenSSL crates (`openssl`, `openssl-sys`, `tokio-openssl`, `foreign-types`); the
`websocket` feature adds `tokio-tungstenite` (+ its WebSocket deps). A default build pulls none
of these. The crate sets `unsafe_code = "deny"` (not the workspace
`forbid`) for its audited syscall / FFI blocks (peercred, fd blocking-mode, the kTLS socket
BIO + `getsockopt`); the cmsg/SCM_RIGHTS construction is `nix`'s.

Not in the workspace `default-members` (its socket / kTLS / `SCM_RIGHTS` I/O can't be
unit-tested deterministically): it is covered behaviorally (`tests/{roundtrip,transfer,tls,ws}.rs`,
real sockets) and excluded from the line-coverage gate. Build/test it with
`cargo {build,test,clippy} -p truenas-rpc-server` (add `--features "tls websocket"` for the
TLS / WebSocket paths).
