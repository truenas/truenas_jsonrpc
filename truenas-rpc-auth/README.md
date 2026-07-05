# truenas-rpc-auth

Authentication for `truenas-rpc`, wired onto the core's `$/sessionSetup` seam — **not** a
per-message layer. You declare the mechanisms a protocol accepts as an `AuthStack`, `install` it
onto the protocol, and the normal session lifecycle (`None → Init → Established`) carries the
handshake. Off by default, per-mechanism feature-gated.

## Declaring mechanisms

Build an `AuthStack` (chain one call per mechanism), `install` it onto the protocol builder, then
map the per-connection session state with `AuthSession::from_peer`:

```rust
use std::sync::Arc;
use serde_json::json;
use truenas_rpc::JsonRpcProtocol;
use truenas_rpc_auth::{install, AuthSession, AuthStack};
use truenas_rpc_server::TruenasRpcServer;

let stack = AuthStack::builder()
    .peercred(|ch| ch.ucred.map(|c| json!({ "uid": c.uid })))   // AF_UNIX (tag UNIX_SOCKET)
    .scram(credential_source)                                   // SCRAM-SHA-512-PLUS (tag SCRAM)
    .build();

let proto = install(JsonRpcProtocol::<AuthSession>::builder("myproto", "1"), stack)
    .method(/* … your typed methods … */)
    .build();

let server = TruenasRpcServer::<AuthSession>::builder("myservice")
    .state_from_peer(AuthSession::from_peer)
    .protocol("myproto", proto)
    .build();
```

`install` attaches the `$/sessionSetup` / `$/sessionSetupContinue` handlers. Because the protocol
now has a `$/sessionSetup`, it also satisfies the server's network-auth guard (so it may be served
over TCP / proxied AF_UNIX / TLS / `wss`).

## Mechanism menu

Each fluent method registers a handler under a wire **tag**; combine by chaining. `.mechanism(tag,
impl Mechanism)` adds a custom one. The session state is always `AuthSession`.

| Builder call | tag | needs | feature |
|---|---|---|---|
| `.peercred(|ch| Option<Value>)` | `UNIX_SOCKET` | genuinely-local AF_UNIX `SO_PEERCRED` | always on |
| `.mtls(|der| Option<(Identity, Principal)>)` | `CLIENT_CERTIFICATE` | TLS client cert | always on |
| `.scram(source)` / `.scram_bound(source, binding)` | `SCRAM` | an encrypted channel + a `tls-server-end-point` binding | `scram` |
| `.gssapi()` | `GSSAPI_TAG` | Kerberos/GSSAPI | `gssapi` |
| `.oauth(config, jwks)` | `OAUTH_TAG` | bearer / OIDC id-token | `oauth` |
| `.passthrough(broker)` | `PASSTHROUGH_TAG` | AF_UNIX fd hand-off to a broker | `passthrough` |
| `.mechanism(tag, m)` | your tag | whatever `m.required()` declares | — |

Each mechanism declares `Mechanism::required()` — a set of `Channel` `Capability`s (`Local`,
`Encrypted`, `Peercred`, `ClientCert`) the stack checks **before** running it, rejecting with
`DENIED` if the transport can't provide them (e.g. SCRAM is never offered on an unencrypted channel).

## Negotiation

There is no server-advertised menu: the client **picks** a mechanism by putting its tag in the
`$/sessionSetup` `mechanism` field, and the stack routes by tag or refuses. Single-shot mechanisms
(mTLS, OAuth, peer-cred) finish in one round; challenge-response mechanisms (SCRAM, GSSAPI) return
`AuthResponse::Challenge` and continue over `$/sessionSetupContinue`. Server outcomes are
`Success` / `Challenge` / `OtpRequired` / `Denied` / `AuthErr` / `Expired`.

## SCRAM-SHA-512-PLUS channel binding

SCRAM here is always the **-PLUS** variant: the client must request `p=tls-server-end-point`
binding, and its `c=` must echo the server's binding value — so the exchange is cryptographically
bound to the TLS certificate and a relay/MITM on a different channel is rejected. The binding value
is `tls-server-end-point` (RFC 5929): a hash of the **server certificate**, so it is publishable.

Where the server obtains that value depends on the transport:

- **Server-terminated TLS** (kTLS, userspace `wss://`): the server holds the cert, so the binding is
  read directly from the connection (`Channel::channel_binding`, from `peer.tls`). Use `.scram(source)`.
- **TLS terminated upstream** (a reverse-proxied AF_UNIX socket, or a proxied `wss://` forwarded over
  a unix socket): the server terminated no TLS, so it has no binding of its own. It reads the active
  cert's published `tls-server-end-point` from an out-of-band `ChannelBindingSource` — in production
  the per-service kernel keyring. Use `.scram_bound(source, KeyringChannelBinding::new(store.root()))`.

The fallback is **strictly gated**: an out-of-band source is consulted **only** when
`Channel::binding_terminated_upstream()` holds — i.e. `TransportPosture::ProxiedUnix`. It is never
consulted on a server-terminated-TLS channel (the binding is already present) nor on a trusted-local
AF_UNIX socket (which authenticates by peer-cred), so a proxied binding can't leak onto a local
session.

```rust
use truenas_rpc_auth::{AuthStack, KeyringChannelBinding, KeyringCredentials};
use truenas_rpc_utils_unsafe::keyring::{KeyringConfig, KeyringStore};

let store = KeyringStore::open(&KeyringConfig::from_json(
    r#"{ "keyring_type": "persistent", "keyring_identifier": 0 }"#,
)?)?;
let stack = AuthStack::builder()
    .peercred(|ch| ch.ucred.map(|c| json!({ "uid": c.uid })))   // local admin socket
    .scram_bound(                                               // reverse-proxied socket
        KeyringCredentials::new(store.server_keys()),          // verifiers from the keyring
        KeyringChannelBinding::new(store.root()),              // published binding from the keyring
    )
    .build();
```

`KeyringChannelBinding` re-reads the value (default key `tls-server-end-point`, override with
`with_key`) on every lookup, so a certificate rotation that republishes it is picked up without a
restart.

## Authorization (RBAC)

`.roles(Roles)` registers the role vocabulary; `.role_source(|uid, mechanism| Vec<String>)` (or
`.roles_from_keyring(...)`) maps an authenticated `(uid, mechanism)` to granted role names, so the
*same* account can hold different roles per mechanism (e.g. `FULL_ADMIN` over the local socket,
read-only over mTLS). `FULL_ADMIN` grants every privilege.

## Features

`scram` (SCRAM, pulls OpenSSL) · `keyring` (kernel-keyring `CredentialSource` +
`KeyringChannelBinding`; implies `scram`) · `nss` (`getpwnam` username→uid) · `oauth` (offline JWT
verification) · `gssapi` (native MIT krb5 acceptor) · `passthrough` (broker fd hand-off). All off by
default; **mTLS and peer-cred are always compiled**.

## Status

Implemented: peer-cred, mTLS, SCRAM-SHA-512-PLUS (server-terminated *and* keyring-published binding),
GSSAPI, OAuth/OIDC, passthrough broker, the `$/sessionSetup` / `$/sessionSetupContinue` lifecycle,
per-mechanism capability gating, and `(uid, mechanism) → roles` authorization.
