# truenas-jsonrpc

Transport-agnostic JSON-RPC 2.0 dispatch core for TrueNAS. A Rust port of the Python
`truenas_pyjsonrpc.JSONRPCProtocol`. It takes inbound bytes plus a session and returns the
reply bytes (or a directive); it owns no socket. For a runnable transport see
`truenas-jsonrpc-server`.

## Public API

- `JsonRpcProtocol<S>` / `JsonRpcProtocolBuilder<S>` — register methods, `build()`, then
  `dispatch(wire, &session) -> Dispatched`. `S` is the per-session server state.
- `dispatch` returns `Dispatched::{Reply(Vec<u8>), Nothing, Transfer(Transfer)}`.
- Method kinds:
  - `JsonRpcMethod` — synchronous handler (run on `spawn_blocking`).
  - `AsyncJsonRpcMethod` — async handler (awaited). Rust-only; Python has no async methods.
  - `FilterableJsonRpcMethod` — query method (`query-filters` / `query-options`); returns
    `Filtered<E>`.
  - `SubscriptionDef` — a `SERVER_CLIENT` pub/sub topic; publish via
    `JsonRpcProtocol::send_notification`.
  - `JsonRpcFdTransferMethod` / `JsonRpcFdPassMethod` — raw-fd transfer / `SCM_RIGHTS`
    contract (`negotiate` + `transfer` callbacks). The core emits a `Transfer` directive; the
    server drives the wire handshake and the fd. See `FileTransfer` / `TransferDirection`.
- `MethodDef` — per-method flags: `pre_auth`, `audit`, `audit_message`, `cancellable`,
  `roles`, `doc`, `secret_fields`, and `xdr(proc_id)` (also expose over the binary wire).
- Control messages: `$/serverInfo`, `$/sessionSetup` (+`Continue`), `$/sessionClose`,
  `$/cancelRequest`, `$/describe`, `$/sessions` (a **FULL_ADMIN** listing of active sessions — the
  core gates + audits it and returns a `Dispatched::Sessions` directive that the server fulfills by
  walking every protocol's session registry, so the list is **server-wide** across protocols). Each
  entry's core base carries `session_id`, the monotonic `age_seconds` + derived wall-clock
  `created_at`, `lifecycle`, `protocol`, `current` (the calling session), and — when the server/auth
  set them — the connection `origin` / `secure_transport` / `internal` and a standardized
  `credential` (`{ description, uid }`).
- Authorization is a native role gate, not a callback: `Roles` interns role *names* to a
  `RoleMask` — a `u64` bitset, so **at most 64 roles**. A method's `roles` become its required
  mask, a session's granted mask is set once at `sessionSetup`, and dispatch checks
  `required ⊆ granted` (subset / AND semantics). `RoleMask::FULL_ADMIN` (all-ones) satisfies
  every gate and may cancel anything; resource / parameter checks are the handler's job.
- Wires: JSON-RPC (text) and XDR (binary, selected by a leading TXDR magic).
- Seams: `AuditSink` — called with a structured `AuditOutcome` (`Success` | `Failure(&JsonRpcError)`)
  and the request params (secrets already redacted), **not** a re-parsed response envelope, so the
  dispatch path never serializes-then-reparses the reply just to audit it; covers method calls plus
  the `$/sessionSetup` / `$/sessionClose` / `$/cancelRequest` / `$/sessions` control ops. Other
  seams: `Canceller`, `ServerInfoHandler`, `SessionInfo` (**augments** each `$/sessions` entry —
  returns a JSON object of extra fields the generic core can't see, e.g. the per-connection identity,
  which is merged on top of the core base), `Outbound` (the
  pub/sub / `$/progress` back-channel), `PyDispatcher` (runs `python:true` bodies), `Secret<T>`
  (audit redaction).

## Dependencies

`serde`, `serde_json`, `uuid`, `thiserror`, `tokio` (`rt` feature only), `async-trait`, and
the sibling `truenas-filter` + `truenas-xdr`. The filter API (`tnfilter`, `Filtered`,
`CompiledFilters`, …) is re-exported, so a consumer needs only this crate to write filterable
handlers.

## Notes

- `#![forbid(unsafe_code)]`.
- Gated at 100% line coverage (`../coverage.sh`).
- A/B differential conformance against the Python reference (`tests/conformance.rs` + golden
  vectors).
- Deliberate parity gaps live in `truenas-filter` (no `select`, no `~` regex).
- Wire contract: `ARCHITECTURE.md`.
