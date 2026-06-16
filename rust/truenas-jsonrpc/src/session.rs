//! Per-connection [`Session`] state, the [`Outbound`] back-channel sink, and the
//! injectable [`IdGen`] / [`Clock`] seams (default UUIDv4 / system time) that make
//! dispatch deterministic for unit tests and the A/B harness.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};

use crate::types::SessionLifecycle;

/// A session / subscription / connection identifier.
pub type SessionId = uuid::Uuid;

/// Generates ids (session ids, subscription ids). Injectable so tests and the A/B
/// harness can pin them; the default is a random UUIDv4.
pub trait IdGen: Send + Sync {
    fn new_id(&self) -> uuid::Uuid;
}

/// Default [`IdGen`]: a random UUIDv4 per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct UuidGen;

impl IdGen for UuidGen {
    fn new_id(&self) -> uuid::Uuid {
        uuid::Uuid::new_v4()
    }
}

/// Wall clock for audit timestamps. Injectable for determinism.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch (UTC), sub-second precision.
    fn now_unix(&self) -> f64;
}

/// Default [`Clock`]: the system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }
}

/// The connection's outbound back-channel sink — where `$/progress` and pub/sub
/// messages go. The transport implements this over its per-connection channel; calls
/// are **non-blocking** (drop on backpressure), so a sync handler can emit progress
/// without `.await`.
pub trait Outbound: Send + Sync {
    fn send(&self, message: Vec<u8>);
}

/// An [`Outbound`] that discards everything — for embedding/tests with no back channel.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullOutbound;

impl Outbound for NullOutbound {
    fn send(&self, _message: Vec<u8>) {}
}

struct AtomicLifecycle(AtomicU8);

impl AtomicLifecycle {
    fn new(l: SessionLifecycle) -> Self {
        Self(AtomicU8::new(encode(l)))
    }
    fn load(&self) -> SessionLifecycle {
        decode(self.0.load(Ordering::Acquire))
    }
    fn store(&self, l: SessionLifecycle) {
        self.0.store(encode(l), Ordering::Release)
    }
}

fn encode(l: SessionLifecycle) -> u8 {
    match l {
        SessionLifecycle::None => 0,
        SessionLifecycle::Init => 1,
        SessionLifecycle::Established => 2,
        SessionLifecycle::Closed => 3,
    }
}

fn decode(v: u8) -> SessionLifecycle {
    match v {
        0 => SessionLifecycle::None,
        1 => SessionLifecycle::Init,
        2 => SessionLifecycle::Established,
        _ => SessionLifecycle::Closed,
    }
}

/// Per-connection context. `S` is the application **server-internal** state (the
/// connection handle + the authenticated identity/permissions handlers read).
///
/// Shared across per-request tasks as `Arc<Session<S>>`. The `lifecycle` is an atomic
/// (lock-free gate check); `internal` is a `RwLock` (the auth stack re-writes it across
/// multi-step setup — **not** write-once). Guards are held only briefly and never across
/// an `.await`.
pub struct Session<S> {
    id: SessionId,
    protocol_name: Arc<str>,
    lifecycle: AtomicLifecycle,
    internal: RwLock<Option<S>>,
    external: RwLock<Option<serde_json::Value>>,
    out: Arc<dyn Outbound>,
}

impl<S> Session<S> {
    pub(crate) fn new(
        id: SessionId,
        protocol_name: Arc<str>,
        internal: Option<S>,
        out: Arc<dyn Outbound>,
    ) -> Self {
        Self {
            id,
            protocol_name,
            lifecycle: AtomicLifecycle::new(SessionLifecycle::None),
            internal: RwLock::new(internal),
            external: RwLock::new(None),
            out,
        }
    }

    /// The protocol-generated session id (never serialized to the wire).
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// The owning protocol's `name`.
    pub fn protocol_name(&self) -> &str {
        &self.protocol_name
    }

    /// The current authentication lifecycle state (lock-free).
    pub fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.load()
    }

    pub(crate) fn set_lifecycle(&self, l: SessionLifecycle) {
        self.lifecycle.store(l);
    }

    /// Read the server-internal state (identity/permissions/connection handle). The
    /// closure runs under a brief read lock; do not `.await` inside it.
    pub fn with_internal<R>(&self, f: impl FnOnce(Option<&S>) -> R) -> R {
        f(self.internal.read().unwrap().as_ref())
    }

    /// Replace the server-internal state (a setup handler sets the identity here).
    pub fn set_internal(&self, state: S) {
        *self.internal.write().unwrap() = Some(state);
    }

    /// Mutate the server-internal state in place (e.g. enrich an identity across setup
    /// rounds).
    pub fn with_internal_mut<R>(&self, f: impl FnOnce(&mut Option<S>) -> R) -> R {
        f(&mut self.internal.write().unwrap())
    }

    /// The client-facing setup result (`server_state_external`), if any.
    pub fn external(&self) -> Option<serde_json::Value> {
        self.external.read().unwrap().clone()
    }

    pub(crate) fn set_external(&self, value: serde_json::Value) {
        *self.external.write().unwrap() = Some(value);
    }

    pub(crate) fn outbound(&self) -> &Arc<dyn Outbound> {
        &self.out
    }
}
