//! Optional async **server transport** for [`truenas-jsonrpc`](truenas_jsonrpc) — the Rust
//! peer of Python's `truenas_pyjsonrpc_server`.
//!
//! The dispatch core is deliberately transport-free (you hand it bytes, it hands you bytes).
//! This crate wraps it in a runnable server: it accepts connections, frames messages, selects
//! a protocol per connection with `$/negotiate`, and pumps the dispatch loop — pipelining so a
//! `$/cancelRequest` is read while a long handler runs, and pushing pub/sub notifications out
//! through each session's [`Outbound`](truenas_jsonrpc::Outbound).
//!
//! The wire is **byte-compatible with the Python server**: a 4-byte big-endian length prefix
//! framing compact JSON (see [`framing`]). AF_UNIX and plain TCP need no dependency beyond
//! tokio's networking; TLS/kTLS and WebSocket arrive behind opt-in features in later phases.
//!
//! This crate is excluded from the workspace default members (its socket / kTLS / SCM_RIGHTS
//! I/O can't be unit-tested deterministically; it's covered behaviorally), so the core builds
//! and tests without it.

pub mod framing;
mod connection;
mod negotiate;
mod peer;
mod server;

pub use peer::{Peer, Transport, Ucred};
pub use server::{JsonRpcServer, JsonRpcServerBuilder, UnixConfig};
