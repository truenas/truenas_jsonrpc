//! A complete, turn-key daemon on `truenas-rpc-daemon`: INI config (with live reload), one JSON-RPC
//! protocol whose handler reads the *live* config, init / periodic / shutdown hooks, a `SIGHUP`
//! reload hook, and `SIGUSR2` wired to the server's operations dump.
//!
//! Run it, then drive it with signals from another shell:
//!
//! ```text
//! cargo run -p truenas-rpc-daemon --example rpc_daemon
//! # ... prints its PID and socket path, then serves ...
//! kill -HUP  <pid>   # reload config (edit /etc/rpc_daemon/config.ini first)
//! kill -USR2 <pid>   # write the operations dump
//! kill -TERM <pid>   # graceful shutdown
//! ```
//!
//! With no config file present the `[service]` defaults are used (missing files are skipped, like
//! `configparser`). Under systemd, pair it with the sibling `myservice.service` (`Type=notify`).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_daemon::{ConfigFile, Daemon, DaemonError, Service, Signal, TruenasRpcServer};

/// Application config, mapped from the INI `[service]` section (every key optional, with defaults).
#[derive(Debug)]
struct Config {
    greeting: String,
    dump_path: String,
}

impl Config {
    fn from_ini(cfg: &ConfigFile) -> Result<Self, DaemonError> {
        Ok(Config {
            greeting: cfg
                .get("service", "greeting")?
                .unwrap_or_else(|| "hello".to_string()),
            dump_path: cfg
                .get("service", "dump_path")?
                .unwrap_or_else(|| "/tmp/rpc_daemon.operations.json".to_string()),
        })
    }
}

#[derive(Deserialize, Serialize)]
struct HelloArgs {
    name: String,
}

#[derive(Serialize)]
struct HelloResult {
    greeting: String,
}

/// The demo protocol: one method whose greeting comes from the *live* config, so a `SIGHUP` that
/// changes `greeting` changes replies without a restart (the handler reads the `watch` receiver).
fn demo_protocol(config: watch::Receiver<Arc<Config>>) -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("greeting.hello"),
            move |a: HelloArgs, _cx: &RequestCtx<()>| {
                let greeting = config.borrow().greeting.clone();
                Ok::<_, JsonRpcError>(HelloResult {
                    greeting: format!("{greeting}, {}!", a.name),
                })
            },
        ))
        .unwrap()
        .build()
}

fn main() -> Result<(), DaemonError> {
    let sock_path = std::env::temp_dir().join("rpc_daemon.sock");
    let _ = std::fs::remove_file(&sock_path); // clear a stale socket from a previous run
    eprintln!(
        "rpc_daemon: pid {} serving on {}",
        std::process::id(),
        sock_path.display()
    );

    // A shared slot lets the SIGUSR2 hook reach the server that is built inside `.services(..)`.
    let server_slot: Arc<OnceLock<TruenasRpcServer<()>>> = Arc::new(OnceLock::new());
    let slot_services = server_slot.clone();
    let slot_signal = server_slot;
    let sock = sock_path;

    Daemon::<Config>::builder("rpc-daemon")
        // A missing config file falls back to the defaults in `Config::from_ini`.
        .config_path("/etc/rpc_daemon/config.ini")
        .parse(Config::from_ini)
        .services(move |h| {
            let server = TruenasRpcServer::<()>::builder("rpc-daemon")
                .protocol("demo", demo_protocol(h.config_rx()))
                .build();
            let _ = slot_services.set(server.clone());
            vec![Service::builder(server).listen_unix(&sock).build()]
        })
        .on_init(|_ctx| async move {
            eprintln!("rpc-daemon: init complete");
            Ok(())
        })
        .on_reload(|ctx| async move {
            eprintln!(
                "rpc-daemon: config reloaded (greeting is now {:?})",
                ctx.config().greeting
            );
            Ok(())
        })
        .on_signal(Signal::SIGUSR2, move |ctx| {
            let slot = slot_signal.clone();
            async move {
                if let Some(server) = slot.get() {
                    let path = ctx.config().dump_path.clone();
                    match server.write_operations_dump(&path) {
                        Ok(()) => eprintln!("rpc-daemon: wrote operations dump to {path}"),
                        Err(e) => eprintln!("rpc-daemon: operations dump failed: {e}"),
                    }
                }
                Ok(())
            }
        })
        .periodic("heartbeat", Duration::from_secs(30), |ctx| async move {
            eprintln!("rpc-daemon: alive (greeting={:?})", ctx.config().greeting);
            Ok(())
        })
        .on_shutdown(|_ctx| async move {
            eprintln!("rpc-daemon: shutting down");
            Ok(())
        })
        .build()
        .run()
}
