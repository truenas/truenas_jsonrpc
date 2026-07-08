//! A turn-key, systemd-native **daemon harness** for [`truenas-rpc-server`](truenas_rpc_server).
//!
//! The workspace has a dispatch core, a server transport, an IDL codegen, and a client — but nothing
//! that turns those into a running service. This crate is that missing piece: give it your config
//! mapping, your [`TruenasRpcServer`]s (built from codegen'd protocols + your handlers), and your
//! lifecycle hooks, and it owns everything undifferentiated — the tokio runtime, INI config loading
//! with `SIGHUP` reload, UNIX signal handling (via `nix` signalfd), graceful shutdown, and systemd
//! `sd_notify` readiness.
//!
//! ```no_run
//! use std::time::Duration;
//! use truenas_rpc_daemon::{ConfigFile, Daemon, DaemonError, Service, TruenasRpcServer};
//!
//! # struct MyConfig;
//! # impl MyConfig { fn from_ini(_: &ConfigFile) -> Result<Self, DaemonError> { Ok(MyConfig) } }
//! # fn demo_protocol() -> truenas_rpc::JsonRpcProtocol<()> { unimplemented!() }
//! fn main() -> Result<(), DaemonError> {
//!     Daemon::<MyConfig>::builder("myservice")
//!         .config_path("/etc/myservice/config.ini")   // INI; re-read on SIGHUP
//!         .parse(MyConfig::from_ini)                   // &ConfigFile -> MyConfig
//!         .services(|_h| {
//!             let server = TruenasRpcServer::<()>::builder("myservice")
//!                 .protocol("myproto", demo_protocol())
//!                 .build();
//!             vec![Service::builder(server).listen_unix("/run/myservice/sock").build()]
//!         })
//!         .periodic("gc", Duration::from_secs(60), |_ctx| async move { Ok(()) })
//!         .build()
//!         .run()                                       // owns runtime + signals + readiness; serves forever
//! }
//! ```
//!
//! Pair it with a `Type=notify` systemd unit whose `ExecReload=/bin/kill -HUP $MAINPID`; the daemon
//! sends `READY=1` once its listeners are bound, `RELOADING=1` on `SIGHUP`, and `STOPPING=1` on exit.
//! Like the other transport-touching crates it is excluded from the workspace default members.

mod config;
mod ctx;
mod daemon;
mod error;
mod hooks;
mod service;
mod signals;
mod systemd;

pub use ctx::{Ctx, DaemonHandle};
pub use daemon::{Daemon, DaemonBuilder};
pub use error::DaemonError;
pub use service::{Service, ServiceBuilder};

/// The UNIX signal identifier accepted by [`DaemonBuilder::on_signal`] (re-exported from `nix`).
pub use nix::sys::signal::Signal;

/// The INI parser handed to [`DaemonBuilder::parse`] (re-exported from `truenas_ros`).
pub use truenas_ros::configfile::ConfigFile;

// The server-side essentials a `services` closure needs, re-exported so a consumer's `main.rs` can
// build servers without also naming `truenas-rpc-server` in its manifest.
pub use truenas_rpc_server::{JsonRpc, NetworkWire, TruenasRpcServer, UnixConfig, Wire};
