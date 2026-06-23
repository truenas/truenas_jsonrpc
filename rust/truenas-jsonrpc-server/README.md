# truenas-jsonrpc-server

The optional async server transport for `truenas-jsonrpc`. A Rust port of Python's
`truenas_pyjsonrpc_server`. It accepts connections, frames messages, selects a protocol per
connection with `$/negotiate`, and pumps the dispatch loop.

## Public API

- `JsonRpcServer<S>` / `JsonRpcServerBuilder<S>`:
  - `.protocol(name, JsonRpcProtocol<S>)` — register a named protocol (the `$/negotiate`
    discriminator).
  - `.state_from_peer(|&Peer| -> Option<S>)` — derive the per-connection session state from
    the peer (defaults to `None`).
  - `.message_limit(usize)` — inbound frame cap (default 4 MiB).
  - `serve_unix(UnixConfig)` / `serve_tcp(addr)` — bind + accept loop. Split forms
    (`bind_unix` + `serve_unix_listener`, `bind_tcp` + `serve_tcp_listener`) let a caller bind
    before signalling readiness. The server is `Clone` (an `Arc` handle), so a clone moves into
    each transport's task.
- `Peer` { `transport`, `ucred: Option<Ucred>`, `addr: Option<SocketAddr>` }, `Transport`,
  `Ucred` (pid/uid/gid from `SO_PEERCRED`).
- `UnixConfig` (path + post-bind `mode`).
- `framing` — the wire: a 4-byte big-endian length prefix over compact JSON (`frame`,
  `read_message`, `DEFAULT_LIMIT`), byte-identical to the Python server.
- *(feature `tls`)* `TlsConfig` (+ `TlsMode::{Kernel, Userspace}`) and
  `serve_tls` / `serve_tls_listener` — encrypted TCP via system OpenSSL.
- `FileTransferExt` — for a `transfer` callback: blocking `write_all` / `read_exact` on the
  fd (download writes the stream, upload reads it), plus `send_fds` / `recv_fds` (`SCM_RIGHTS`)
  for a `JsonRpcFdPassMethod` over AF_UNIX.

## Behaviour

- Per connection: an `AWAIT_NEGOTIATE → BOUND` read loop. Dispatch is pipelined (each message
  spawned) so a `$/cancelRequest` is read while a handler runs. All outbound bytes — replies
  plus pub/sub notifications pushed through the session's `Outbound` — funnel through one
  unbounded channel drained by a writer task (single ordered writer).
- Notifications are push-based via the session's `Outbound` (no drain threads, unlike Python).

## Status

Implemented: AF_UNIX + plain TCP, length-prefixed JSON, `$/negotiate`, `SO_PEERCRED`, pub/sub
push, pipelined dispatch/cancel, and the raw-fd **transfer takeover** — the
`$/transferReady` / `$/transferGo` handshake and the blocking fd handoff for byte-stream
download/upload over plain Unix or TCP, `SCM_RIGHTS` fd passing (`send_fds` / `recv_fds`) over
AF_UNIX, and **TLS** via system OpenSSL (the `tls` feature) in two modes (`TlsMode`): **kernel
TLS** (kTLS — handshake in userspace, then the raw kernel-encrypted fd, so the bulk transfer
stays out of userspace and raw-fd transfer works over the encrypted link; fails closed if
kTLS doesn't engage) or a **userspace** `tokio-openssl` pump (works anywhere, but no raw-fd
transfer). Not yet: zero-copy `sendfile` / `splice` (the byte-stream path works without them),
and WebSocket.

## Usage

```rust
let proto = JsonRpcProtocol::<()>::builder("conf", "1").method(/* … */).build();
let server = JsonRpcServer::<()>::builder("my-server")
    .protocol("main", proto)
    .build();
server.serve_unix(UnixConfig::new("/run/my.sock")).await?;
```

## Dependencies / build

Default: `truenas-jsonrpc`, `serde`, `serde_json`, `tokio` (`net` etc. → `mio` + `socket2`),
`libc` (`SO_PEERCRED`, the kTLS `getsockopt` probe, the blocking-fd toggle), `bytes` (the
cancel-safe read buffer), and `nix` (`SCM_RIGHTS` `sendmsg`/`recvmsg`). The `tls` feature adds
the system-OpenSSL crates (`openssl`, `openssl-sys`, `tokio-openssl`, `foreign-types`); a
default build pulls none of them. The crate sets `unsafe_code = "deny"` (not the workspace
`forbid`) for its audited syscall / FFI blocks (peercred, fd blocking-mode, the kTLS socket
BIO + `getsockopt`); the cmsg/SCM_RIGHTS construction is `nix`'s.

Not in the workspace `default-members` (its socket / kTLS / `SCM_RIGHTS` I/O can't be
unit-tested deterministically): it is covered behaviorally (`tests/{roundtrip,transfer,tls}.rs`,
real sockets) and excluded from the line-coverage gate. Build/test it with
`cargo {build,test,clippy} -p truenas-jsonrpc-server` (add `--features tls` for the TLS paths).
