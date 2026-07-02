//! Optional async **server transport** for [`truenas-rpc`](truenas_rpc).
//!
//! The dispatch core is deliberately transport-free (you hand it bytes, it hands you bytes).
//! This crate is the **Transport** (layer 1) and **Framing** (layer 2) of the `ARCHITECTURE.md`
//! layer stack: it accepts connections, frames messages, selects
//! a protocol per connection with `$/negotiate`, and pumps the dispatch loop — pipelining so a
//! `$/cancelRequest` is read while a long handler runs, and pushing pub/sub notifications out
//! through each session's [`Outbound`](truenas_rpc::Outbound).
//!
//! The wire is a 4-byte big-endian length prefix framing compact JSON (see [`framing`]).
//! AF_UNIX and plain TCP need no dependency beyond
//! tokio's networking; TLS/kTLS and WebSocket are available behind opt-in features.
//!
//! This crate is excluded from the workspace default members (its socket / kTLS / SCM_RIGHTS
//! I/O can't be unit-tested deterministically; it's covered behaviorally), so the core builds
//! and tests without it.

mod connection;
mod engine;
pub mod framing;
mod negotiate;
mod oncrpc;
mod peer;
#[cfg(feature = "passthrough")]
pub mod scm;
mod server;
#[cfg(feature = "tls")]
mod tls;
mod transfer;
mod wire;
#[cfg(feature = "websocket")]
mod ws;

pub use engine::{AsyncStream, ConnContext, ProtocolEngine};
pub use oncrpc::OncRpc;
pub use peer::{ForwardedOrigin, Peer, TlsPeer, Transport, TransportPosture, Ucred, UnixTrust};
pub use server::{TruenasRpcServer, TruenasRpcServerBuilder, UnixConfig};
#[cfg(feature = "tls")]
pub use tls::{TlsConfig, TlsMode};
pub use transfer::FileTransferExt;
pub use wire::{CustomWire, JsonRpc, NetworkWire, Wire, WireHost};
