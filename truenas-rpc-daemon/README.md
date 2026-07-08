# truenas-rpc-daemon

A turn-key, systemd-native **daemon harness** for `truenas-rpc-server`. Give it your config mapping,
your codegen'd protocols + handlers, and your lifecycle hooks; it owns everything undifferentiated —
the tokio runtime, INI config loading with `SIGHUP` reload, UNIX signal handling (`nix` signalfd via
tokio `AsyncFd`), graceful shutdown, and systemd `sd_notify` readiness. Excluded from the workspace
default members (it owns a runtime and does signal / socket I/O); needs **no `unsafe`**.

## Turn-key service

A production service is a config mapping, your protocols/handlers, a small `main.rs`, and a systemd
unit. The example below shares **one server and one session table** across a trusted-local socket
(peer-cred) and a reverse-proxied socket (SCRAM-SHA-512-PLUS, channel binding from the per-service
keyring — see [`truenas-rpc-auth`](../truenas-rpc-auth/README.md)):

```rust
use std::time::Duration;
use truenas_rpc_auth::{install, AuthSession, AuthStack, KeyringChannelBinding, KeyringCredentials};
use truenas_rpc_daemon::{ConfigFile, Daemon, DaemonError, Service, TruenasRpcServer};
use truenas_rpc_utils_unsafe::keyring::{KeyringConfig, KeyringStore};

fn protocol(store: &KeyringStore) -> truenas_rpc::JsonRpcProtocol<AuthSession> {
    let stack = AuthStack::builder()
        .peercred(|ch| ch.ucred.map(|c| serde_json::json!({ "uid": c.uid })))  // local socket
        .scram_bound(                                                          // proxied socket
            KeyringCredentials::new(store.server_keys()),                     // verifiers (keyring)
            KeyringChannelBinding::new(store.root()),                         // tls-server-end-point
        )
        .build();
    install(truenas_rpc::JsonRpcProtocol::<AuthSession>::builder("myproto", "1"), stack)
        .method(/* … your codegen'd handlers … */)
        .build()
}

fn main() -> Result<(), DaemonError> {
    Daemon::<MyConfig>::builder("myservice")
        .config_path("/etc/myservice/config.ini")     // INI; re-read on SIGHUP
        .parse(MyConfig::from_configfile)              // &ConfigFile -> MyConfig
        .services(|_h| {
            let store = KeyringStore::open(&KeyringConfig::from_json(
                r#"{ "keyring_type": "persistent", "keyring_identifier": 0 }"#).unwrap()).unwrap();
            let server = TruenasRpcServer::<AuthSession>::builder("myservice")
                .state_from_peer(AuthSession::from_peer)
                .protocol("myproto", protocol(&store))
                .build();
            vec![
                Service::builder(server.clone()).listen_unix("/run/myservice/sock").build(),
                Service::builder(server).listen_unix_proxied("/run/myservice/public.sock").build(),
            ]
        })
        .on_init(|_ctx| async move { Ok(()) })
        .periodic("gc", Duration::from_secs(60), |_ctx| async move { Ok(()) })
        .build()
        .run()                                         // owns runtime + signals + readiness; serves forever
}
```

```ini
# /etc/systemd/system/myservice.service
[Service]
Type=notify
ExecStart=/usr/bin/myservice
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
```

## Public API

- `Daemon::<C>::builder(name)` → `DaemonBuilder<C>`, generic only over the app config type `C` (each
  `Service` erases its server's session type, so heterogeneous servers coexist):
  - **config** — `.config_path(s)` + `.parse(|&ConfigFile| -> C)` (INI, re-read on `SIGHUP`, keeps
    last-good config on a bad reload), or `.load_config(|| …)`.
  - **services** — `.services(|&DaemonHandle<C>| -> Vec<Service>)`; build a server with
    `Service::builder(server).listen_unix(path) / .listen_unix_proxied(path) / .listen_tcp(addr) /
    .build()`. `listen_tcp` / `listen_unix_proxied` require `W: NetworkWire<S>`, preserving the server
    crate's compile-time transport safety.
  - **lifecycle (all additive)** — `.on_init` / `.on_shutdown` (reverse) / `.on_reload`,
    `.periodic(name, every, …)` (each an independent task), `.task(…)`, `.on_signal(Signal, …)`.
  - **tuning** — `.shutdown_grace(Duration)`, `.worker_threads(n)`.
- `Ctx<C>` (per hook): `.config()` / `.config_rx()`, `.is_shutting_down()`, `.shutdown().await`,
  `.trigger_shutdown()`, `.until_shutdown(fut).await`.
- `.run()` owns a multi-thread runtime and blocks the handled signals before workers spawn (the
  race-free signalfd precondition); `.run_async()` runs on an existing runtime (advanced).

## Behaviour

- `SIGTERM`/`SIGINT` → graceful shutdown; `SIGHUP` → config reload; `SIGUSR1`/`SIGUSR2` and RT signals
  → `on_signal` hooks. `sd_notify` sends `READY=1` once listeners are bound, `RELOADING=1` on `SIGHUP`,
  `STOPPING=1` on shutdown (a no-op off systemd).
- Startup binds every listener **before** `READY`; a bind or `on_init` failure aborts before it.
- Shutdown is best-effort drain: serve loops stop accepting, tasks observe the shutdown signal, and
  the daemon waits up to `shutdown_grace` before aborting. In-flight connection draining would need a
  seam inside `truenas-rpc-server` (the accept loop detaches per-connection tasks).

## Examples

- `examples/rpc_daemon.rs` — config, one JSON-RPC protocol, `SIGHUP` reload, `SIGUSR2` → operations
  dump, lifecycle hooks.
- `examples/rpc_daemon_auth.rs` — one server + session table across a trusted-local (peer-cred) and a
  reverse-proxied socket; declaring auth via [`truenas-rpc-auth`](../truenas-rpc-auth/README.md).
- `examples/myservice.service` — a `Type=notify` systemd unit.

## Status

Implemented: INI config + `SIGHUP` reload, signalfd handling, init / periodic / shutdown / custom-signal
hooks, bind-then-serve of one or more servers over AF_UNIX (trusted-local + proxied) and TCP, graceful
shutdown, and `sd_notify` readiness. TLS-serving `listen_*` helpers and true in-flight drain are
follow-ups.
