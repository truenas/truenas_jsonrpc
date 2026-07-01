//! Async **client engine** for [`truenas-rpc`](truenas_rpc) — the client mirror of the server's
//! neutral-core / per-protocol-layer split.
//!
//! [`Client<P>`] is **protocol-agnostic**: it owns the connection, a receive task (frame → classify →
//! route), a writer task (frame + coalesce), and the reply-correlation registry. A
//! [`ProtocolRuntime`] supplies the wire specifics (framing + envelope), and **optional capability
//! traits** ([`Negotiates`], [`Authenticates`], [`GracefulClose`]) each unlock one engine method — so
//! a protocol implements only what it has (the client analogue of the server's `NetworkWire: Wire`).
//!
//! The built-in [`JsonRpcClient`] is the engine over the hand-written JSON-RPC runtime (AF_UNIX + TCP;
//! `$/negotiate` / `$/sessionSetup` / `$/sessionClose`). A generated typed client sits on the neutral
//! [`CallEngine`] seam.
//!
//! This crate does socket I/O, so (like `truenas-rpc-server`) it is excluded from the workspace
//! default members and covered behaviorally.

mod config;
mod engine;
mod error;
mod jsonrpc;
mod transport;

pub use config::{ClientConfig, Endpoint};
pub use engine::{
    Authenticates, CallEngine, Client, EncodedCall, Framing, GracefulClose, Inbound, MethodKey,
    Negotiates, NotificationStream, ProtocolRuntime, QueryResult, SubId,
};
pub use error::ClientError;
pub use jsonrpc::{JsonRpcClient, JsonRpcMethod, JsonRpcRuntime, LengthPrefix, Negotiated};

/// XDR (de)serialization for the binary sub-wire, re-exported so a generated client can encode a
/// `MethodKey::Proc` call's params / decode its reply without a direct `truenas-xdr` dependency.
pub use truenas_xdr::{from_bytes as from_xdr, to_bytes as to_xdr};
