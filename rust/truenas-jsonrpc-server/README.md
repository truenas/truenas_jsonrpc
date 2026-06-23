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
download/upload over plain Unix or TCP, and `SCM_RIGHTS` fd passing (`send_fds` / `recv_fds`)
over AF_UNIX. Not yet: zero-copy `sendfile` / `splice` (the byte-stream path works without
them), TLS + kTLS, and WebSocket.

## Usage

```rust
let proto = JsonRpcProtocol::<()>::builder("conf", "1").method(/* … */).build();
let server = JsonRpcServer::<()>::builder("my-server")
    .protocol("main", proto)
    .build();
server.serve_unix(UnixConfig::new("/run/my.sock")).await?;
```

## Dependencies / build

`truenas-jsonrpc`, `serde`, `serde_json`, `tokio` (`net` etc. → `mio` + `socket2`), and `libc`
(`SO_PEERCRED`; the only `unsafe` so far — one audited block). The crate sets
`unsafe_code = "deny"` (not the workspace `forbid`) for that and the syscalls coming in later
phases.

Not in the workspace `default-members` (its socket / kTLS / `SCM_RIGHTS` I/O can't be
unit-tested deterministically): it is covered behaviorally (`tests/roundtrip.rs`, real Unix +
TCP sockets) and excluded from the line-coverage gate. Build/test it with
`cargo {build,test,clippy} -p truenas-jsonrpc-server`.
