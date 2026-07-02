# Workspace crates

The full inventory of the `truenas_rpc` Cargo workspace: every crate's purpose, its internal
(path) and external (third-party) dependencies, feature flags, and where it sits in the build and
coverage model. For the *consumer's* view ("what goes in my `Cargo.toml`") see the
[README](README.md#crates); for the layering rationale see [ARCHITECTURE.md](ARCHITECTURE.md#layers).

## At a glance

| Crate | Purpose | Build | Coverage |
|---|---|---|---|
| [`truenas-rpc`](#truenas-rpc) | Transport-agnostic JSON-RPC 2.0 dispatch core | default | **≥99.5% floor** |
| [`truenas-filter`](#truenas-filter) | `query-filters` / `query-options` engine | default | **≥99.5% floor** |
| [`truenas-xdr`](#truenas-xdr) | Byte-exact serde XDR (RFC 4506) codec + TXDR frame | default | **≥99.5% floor** |
| [`truenas-xdr-derive`](#truenas-xdr-derive) | `#[derive(XdrEnum/XdrUnion)]` proc-macro | default | behavioral (via `truenas-xdr`) |
| [`truenas-rpc-codegen`](#truenas-rpc-codegen) | `json-idl` → Rust (server + client) + OpenRPC generator | default | **≥99.5% floor** |
| [`truenas-rpc-server`](#truenas-rpc-server) | Async server transport (AF_UNIX/TCP/TLS/WS) | opt-in | behavioral |
| [`truenas-rpc-client`](#truenas-rpc-client) | Async client engine | opt-in | behavioral (≥85% floor) |
| [`truenas-rpc-auth`](#truenas-rpc-auth) | Auth mechanisms (peer-cred / mTLS / SCRAM / …) | opt-in | behavioral |
| [`truenas-rpc-pyo3`](#truenas-rpc-pyo3) | Embedded-CPython bridge for `python:true` bodies | opt-in | behavioral |
| [`truenas-rpc-pyclient`](#truenas-rpc-pyclient) | Runtime for the generated Python client | opt-in | behavioral |
| [`truenas-rpc-utils-unsafe`](#truenas-rpc-utils-unsafe) | Opt-in unsafe utils: kernel keyring / audit / GSSAPI FFI | opt-in | behavioral |
| [`examples/demo`](#examplesdemo) | End-to-end codegen demo / integration test | default | ignored (`/examples/`) |

**Build** — *default* crates build and test with a plain `cargo build` / `cargo test` (they are the
workspace [`default-members`](Cargo.toml)); *opt-in* crates are workspace members excluded from that
set (they link libpython / krb5 or do socket-and-syscall I/O), built only when named
(`cargo … -p <crate>`, `cargo clippy --workspace`) or pulled by a consumer. See
[the coverage model](#coverage-model) for what "≥99.5% floor" vs "behavioral" means.

## Crate details

Versions below are the declared `Cargo.toml` requirements. Dependencies shared across the workspace
are pinned once in `[workspace.dependencies]` (`Cargo.toml`): `serde` 1, `serde_json` 1
(`raw_value`), `uuid` 1 (`v4`), `thiserror` 2, `tokio` 1 (`rt`), `async-trait` 0.1.

### truenas-rpc
Transport-agnostic JSON-RPC 2.0 **dispatch core** — envelope parse/validate, session lifecycle +
authorization gate, the authorize → handler → audit pipeline, `$/` control messages, pub/sub, and
filterable (query) methods. Re-exports the filter API.
- **Internal:** `truenas-filter`, `truenas-xdr`.
- **External:** `serde`, `serde_json`, `uuid`, `thiserror`, `tokio` (`rt` only — sync handlers run on
  `spawn_blocking`, async handlers are awaited), `async-trait`.
- **Features:** none.

### truenas-filter
The `query-filters` / `query-options` **engine**, matching the TrueNAS middleware's `truenas_pyfilter`
C engine (byte-for-byte, minus `select` and the `~` regex operator). Re-exported through `truenas-rpc`.
- **Internal:** none.
- **External:** `serde`, `serde_json`.
- **Features:** none.

### truenas-xdr
A byte-exact, dependency-light serde **XDR (RFC 4506) codec** + the TXDR binary frame for the JSON-RPC
binary wire. Implements `Serializer`/`Deserializer` by hand (no `serde_derive`).
- **Internal:** `truenas-xdr-derive` (optional, via the `derive` feature).
- **External:** `serde` (traits only, `default-features = false`), `thiserror`.
- **Features:** `default = ["derive"]` — pulls the `#[derive(XdrEnum/XdrUnion)]` macros; opt out with
  `default-features = false`.

### truenas-xdr-derive
The **proc-macro** crate behind `truenas-xdr`'s `derive` feature: `#[derive(XdrEnum)]` /
`#[derive(XdrUnion)]` encode a type's explicit `#[repr(iN)]` discriminants byte-exactly (required for
RFC-4506 enums/unions with discriminant gaps). A proc-macro must be its own crate, so you never depend
on it directly.
- **Internal:** none.
- **External:** `syn` 2, `quote` 1, `proc-macro2` 1 (all already transitive — zero new crates).
- **Features:** none.

### truenas-rpc-codegen
The `json-idl` → **Rust (server + client) + OpenRPC** generator. Emits source *text* (it is not a
proc-macro), so it carries only `serde` + `serde_json`. Used as a `build-dependency` via `Build`, or
as a CLI (`cargo run --example codegen`). *This is the crate the new `emit_pyclient` emitter lives in.*
- **Internal:** none.
- **External:** `serde`, `serde_json`.
- **Features:** none.

### truenas-rpc-server
The optional async **server transport**: length-prefixed JSON framing + `$/negotiate` over AF_UNIX /
TCP, with kTLS and WebSocket behind features, the connection/session registry, and SCM_RIGHTS fd
passing.
- **Internal:** `truenas-rpc`, `truenas-xdr`.
- **External:** `tokio` (`net`, `io-util`, `sync`, `rt`, `macros`, `time`), `serde`, `serde_json`,
  `libc` 0.2, `bytes` 1, `nix` 0.29 (`socket`, `uio`), `futures-util` 0.3; **opt (`tls`):** `openssl`
  0.10, `openssl-sys` 0.9, `tokio-openssl` 0.6, `foreign-types` 0.3; **opt (`websocket`):**
  `tokio-tungstenite` 0.24, `http` 1.
- **Features:** `tls`, `websocket`, `passthrough` (SCM_RIGHTS control-frame primitives; no new deps).
- **Lint:** `unsafe_code = "deny"` (per-site allow) — makes syscalls.

### truenas-rpc-client
The optional async **client engine**: connect over AF_UNIX / TCP / kTLS / WebSocket, authenticate,
call / subscribe, stream raw-fd transfers, pass fds — and drive the codegen'd typed client via
`CallEngine`.
- **Internal:** `truenas-rpc`, `truenas-xdr`.
- **External:** `serde`, `serde_json`, `uuid`, `thiserror`, `async-trait`, `bytes` 1, `socket2` 0.5,
  `libc` 0.2, `tokio` (`net`, `io-util`, `sync`, `time`, `macros`, `rt`, `rt-multi-thread`); **opt:**
  `nix` 0.29 (`fd-passing`), `openssl` 0.10 / `openssl-sys` 0.9 / `foreign-types` 0.3 (`tls`),
  `tokio-tungstenite` 0.24 / `futures-util` 0.3 / `tokio-openssl` 0.6 (`websocket`).
- **Features:** `tls`, `websocket`, `scram` (⇒ `tls`), `fd-passing`. Default pulls **none** (AF_UNIX +
  TCP only).
- **Lint:** `unsafe_code = "deny"` (per-site allow) — socket I/O (`fcntl` O_NONBLOCK).

### truenas-rpc-auth
The optional **authentication** layer: an `AuthStack` of pluggable challenge-response `Mechanism`s
(AF_UNIX peer-cred by default; mTLS / SCRAM-SHA-512-PLUS / GSSAPI / OAuth / passthrough declared)
wired onto the core's `$/sessionSetup` seam.
- **Internal:** `truenas-rpc`, `truenas-rpc-server`; **opt:** `truenas-rpc-utils-unsafe`
  (`keyring`, `gssapi`).
- **External:** `serde`, `serde_json`; **opt:** `openssl` 0.10 (`scram` / `oauth` / `gssapi`), `nix`
  0.29 `user` (`nss`).
- **Features:** `scram`, `keyring` (⇒ `scram`), `nss`, `oauth`, `gssapi`, `passthrough`.

### truenas-rpc-pyo3
The optional **embedded-CPython bridge** that runs `python:true` method bodies in an embedded
interpreter, implementing the core's `PyDispatcher` seam via the raw CPython C-API — **no pyo3
framework, no proc-macros**. Excluded from default members, so a default build links zero libpython.
- **Internal:** `truenas-rpc`.
- **External:** `pyo3-ffi` 0.23 (raw C-API + libpython linking; *not* `extension-module`),
  `serde_json`.
- **Lint:** `unsafe_code = "deny"` (per-site allow) — raw C-API.

### truenas-rpc-pyclient
The runtime for the **generated Python client** (`truenas-rpc-codegen`'s `emit_pyclient`) — the Python
analogue of `truenas-rpc-client`. A hand-written **sync bridge** that connects + hands the engine to
the generated Rust typed client, then drives its typed async methods on a shared multi-thread tokio
runtime with the GIL released (`block_on`); plus `to_py`/`from_py` (the serde struct↔Python boundary),
the reusable `Endpoint` / `ClientConfig` classes, and the `RpcError` exception the generated
`#[pyclass]`es register. Built with the *high-level* pyo3 framework (`#[pyclass]`/`#[pymethods]`),
unlike `truenas-rpc-pyo3`.
- **Internal:** `truenas-rpc`, `truenas-rpc-client`.
- **External:** `pyo3` 0.23 (high-level framework; no `extension-module` — the consumer's cdylib
  enables it), `pythonize` 0.23 (the struct↔Python serde boundary), `tokio` (`rt-multi-thread`, `net`,
  `time`, …), `serde`, `serde_json`.
- **Lint:** `unsafe_code = "allow"` — the pyo3 macros expand to `unsafe` trampolines that can't be
  per-site annotated.

### truenas-rpc-utils-unsafe
The workspace's opt-in **unsafe utilities** — direct kernel syscalls / FFI, quarantined in one crate so
the rest of the workspace stays `unsafe_code = "forbid"`. Three independent, feature-gated modules:
- `keyring` — a config-driven Linux kernel-keyring store for SCRAM verifiers / peer credentials, via
  `add_key(2)` / `keyctl(2)`.
- `audit` — a `truenas_rpc::AuditSink` writing one record per audited call to `NETLINK_AUDIT` (auditd →
  `/var/log/audit/audit.log`) on a dedicated drain thread.
- `gssapi` — a minimal FFI to the system GSSAPI (MIT krb5) acceptor (~6 RFC 2744 functions, bound
  directly to avoid `libgssapi` → `bindgen` → `libclang`); reserves the native lib via
  `links = "gssapi_krb5"`.

Each feature pulls only its own dependencies, so a consumer wanting one module never links the others'.
- **Internal:** `truenas-rpc` (`audit` only).
- **External:** `libc` 0.2 (`keyring` / `audit`), plus `serde` / `serde_json` / `thiserror` / `uuid`
  per module; **build:** `pkg-config` 0.3 (`gssapi`; `krb5-config` fallback).
- **Features:** `keyring`, `audit`, `gssapi` (all off by default).
- **Lint:** `unsafe_code = "deny"` (per-site allow + `// SAFETY:`).

### examples/demo
`demo-consumer` — the documented `json-idl` + `build.rs` codegen layout, exercised as a live
integration test (`cargo test -p demo-consumer`). Not published; lives under `examples/` so the
coverage gate ignores it.
- **Internal:** `truenas-rpc`, `truenas-rpc-utils-unsafe` (audit), `truenas-rpc-client`; **dev:**
  `truenas-rpc-server`, `truenas-xdr`; **build:** `truenas-rpc-codegen`.
- **External:** `serde`, `serde_json`.

## Dependency graph

Arrows are Cargo dependencies (`A → B` = A depends on B). `[opt]` marks a member excluded from
`default-members`, pulled only when a consumer names it.

```text
                         consumer service crate
                   (generated Handlers, json-idl/ spec)
                      |                          |
             build-dep|                          | runtime
                      v                          |
       +--------------------------+              |
       |   truenas-rpc-codegen    |              |
       |  json-idl -> Rust (build |              |
       |  time; output uses rpc)  |              |
       +--------------------------+              v
   [opt] +----------------------+     +-----------------------+
         | truenas-rpc-server   |---->|                       |
         +----------------------+     |                       |
   [opt] +----------------------+     |                       |
         | truenas-rpc-client   |---->|      truenas-rpc      |
         +----------------------+     |    (dispatch core)    |
   [opt] +----------------------+     |                       |
         | truenas-rpc-pyo3     |---->|                       |
         +----------------------+     |                       |
   [opt] +----------------------+     |                       |
         | utils-unsafe (audit) |---->|                       |
         +----------------------+     +----+-------------+----+
   [opt] +----------------------+          |             |
         | truenas-rpc-auth     |--> rpc + server        |
         +----------+-----------+                        |
           [opt]    |  \--> utils-unsafe (keyring)       |
                    |   \-> utils-unsafe (gssapi)        |
                    v                                    v
              (auth mechanisms)              +----------------+  +--------------------+
                                             | truenas-filter |  |     truenas-xdr    |
                                             | (query engine) |  |  (XDR codec+frame) |
                                             +----------------+  +---------+----------+
                                                                "derive"   | feature
                                                                           v
                                                                 +---------------------+
                                                                 | truenas-xdr-derive  |
                                                                 |   (proc-macro)      |
                                                                 +---------------------+
```

`truenas-rpc-utils-unsafe` (shown as `utils-unsafe`) collects the three direct-syscall/FFI surfaces
(keyctl, netlink, krb5) as feature-gated modules — the `audit` module backs generated servers, while
`keyring`/`gssapi` back the auth mechanisms — rather than three separate crates.

## External dependency audit

Every third-party crate in the workspace, where it is used, and why. The workspace keeps this set
deliberately small; several "new" deps are already transitive (noted).

| Crate | Ver | Used by | Why |
|---|---|---|---|
| `serde` / `serde_json` | 1 | all | Serialization; `serde_json` `raw_value` for zero-copy passthrough |
| `uuid` | 1 | rpc, utils-unsafe (audit) | Request-id (`v4`) generation/validation |
| `thiserror` | 2 | rpc, xdr, client, utils-unsafe | Error enums |
| `tokio` | 1 | rpc (`rt`), server, client | Async runtime; transports add `net`/`io-util`/… |
| `async-trait` | 0.1 | rpc, client | The async handler / `CallEngine` traits |
| `syn` / `quote` / `proc-macro2` | 2 / 1 / 1 | xdr-derive | Proc-macro implementation |
| `libc` | 0.2 | server, client, utils-unsafe | Direct syscalls (SO_PEERCRED, kTLS, `keyctl`, netlink, `fcntl`) |
| `nix` | 0.29 | server, client (`fd-passing`), auth (`nss`) | Safe `sendmsg`/`recvmsg` SCM_RIGHTS; `getpwnam_r` |
| `bytes` | 1 | server, client | Cancel-safe framed reads |
| `socket2` | 0.5 | client | Socket options on connect |
| `openssl` / `openssl-sys` / `foreign-types` | 0.10 / 0.9 / 0.3 | server (`tls`), client (`tls`), auth (`scram`/`oauth`/`gssapi`) | System OpenSSL: kTLS handshake + crypto/base64 |
| `tokio-openssl` | 0.6 | server (`tls`), client (`websocket`) | Userspace-TLS `SslStream` pump |
| `tokio-tungstenite` | 0.24 | server / client (`websocket`) | WebSocket framing |
| `http` | 1 | server (`websocket`) | Upgrade-request header parsing |
| `futures-util` | 0.3 | server, client (`websocket`) | `FuturesUnordered`, stream `split()` |
| `pyo3-ffi` | 0.23 | pyo3 | Raw CPython C-API + libpython linking |
| `pyo3` | 0.23 | pyclient | High-level `#[pyclass]`/`#[pymethods]` to expose the generated client to Python |
| `pythonize` | 0.23 | pyclient | serde struct↔Python object conversion (no JSON-string hop) |
| `pkg-config` | 0.3 (build) | utils-unsafe (gssapi) | Locate system MIT krb5 |

## Coverage model

Two scripts, mirroring the build split:

- **`coverage.sh` (≥99.5% line floor).** Runs the `default-members` test suite under
  `-C instrument-coverage` and asserts **≥99.5%** merged line coverage over their `src/`, excluding
  (its IGNORE regex) the proc-macro crate and the socket/FFI crates. Net effect: **`truenas-rpc`,
  `truenas-filter`, `truenas-xdr`, and `truenas-rpc-codegen` are held near-total** — the small
  remainder is `?`-error / `assert!`-panic branches that rustfmt isolates onto their own lines, so
  line coverage can't credit them (the run prints the exact percentage + every uncovered line).
- **`coverage-client.sh` (≥85% floor).** A behavioral floor for `truenas-rpc-client` (the remaining
  gaps are hard-to-inject I/O-error and WebSocket-poll edges); runs serially.

Everything else — `truenas-rpc-server`, `truenas-rpc-auth`, `truenas-rpc-pyo3`,
`truenas-rpc-pyclient`, `truenas-rpc-utils-unsafe` — is **behavioral
only**: excluded from the line gate because it does socket I/O, FFI, or links libpython/krb5 (not
unit-testable to 100% deterministically), but still built by `cargo clippy --workspace` and exercised
with `cargo test -p <crate>`.
