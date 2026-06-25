//! Per-connection [`Session`] state, the [`Outbound`] back-channel sink, and the
//! injectable [`IdGen`] / [`Clock`] seams (default UUIDv4 / system time) that make
//! dispatch deterministic for unit tests and the A/B harness.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use crate::role::RoleMask;
use crate::types::SessionLifecycle;

/// A session / subscription / connection identifier.
pub type SessionId = uuid::Uuid;

/// Generates ids (session ids, subscription ids). Injectable so tests and the A/B
/// harness can pin them; the default is a random UUIDv4.
pub trait IdGen: Send + Sync {
    /// Generate a fresh id.
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
    /// Enqueue one outbound message (non-blocking; may drop on backpressure).
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
        Self(AtomicU8::new(l as u8))
    }
    fn load(&self) -> SessionLifecycle {
        decode(self.0.load(Ordering::Acquire))
    }
    fn store(&self, l: SessionLifecycle) {
        self.0.store(l as u8, Ordering::Release)
    }
}

/// Inverse of `SessionLifecycle as u8`. The cell is only ever written via that cast
/// (values 0–3), so any other byte is genuinely unreachable — fail loudly rather than
/// silently coercing a future/garbage variant to `Closed`.
fn decode(v: u8) -> SessionLifecycle {
    match v {
        0 => SessionLifecycle::None,
        1 => SessionLifecycle::Init,
        2 => SessionLifecycle::Established,
        3 => SessionLifecycle::Closed,
        _ => unreachable!("invalid SessionLifecycle discriminant: {v}"),
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
    // The granted-roles [`RoleMask`] (u64): written once at `sessionSetup` (`set_roles`), read
    // lock-free on every gated call (`granted_roles`).
    roles: AtomicU64,
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
            roles: AtomicU64::new(0),
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
        f(self.internal.read().unwrap_or_else(PoisonError::into_inner).as_ref())
    }

    /// Replace the server-internal state (a setup handler sets the identity here).
    pub fn set_internal(&self, state: S) {
        *self.internal.write().unwrap_or_else(PoisonError::into_inner) = Some(state);
    }

    /// Mutate the server-internal state in place (e.g. enrich an identity across setup
    /// rounds).
    pub fn with_internal_mut<R>(&self, f: impl FnOnce(&mut Option<S>) -> R) -> R {
        f(&mut self.internal.write().unwrap_or_else(PoisonError::into_inner))
    }

    /// The client-facing setup result (`server_state_external`), if any.
    pub fn external(&self) -> Option<serde_json::Value> {
        self.external.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub(crate) fn set_external(&self, value: serde_json::Value) {
        *self.external.write().unwrap_or_else(PoisonError::into_inner) = Some(value);
    }

    /// Set the session's granted roles. A `$/sessionSetup` handler calls this once it has
    /// authenticated the identity (with any role hierarchy already expanded into `roles`); the
    /// per-call authorization gate reads it via [`granted_roles`](Self::granted_roles).
    pub fn set_roles(&self, roles: RoleMask) {
        self.roles.store(roles.bits(), Ordering::Release);
    }

    /// The session's granted roles (empty until `sessionSetup` sets them). The dispatch gate checks
    /// a method's required roles against this; a handler may also read it for resource-level checks.
    pub fn granted_roles(&self) -> RoleMask {
        RoleMask::from_bits(self.roles.load(Ordering::Acquire))
    }

    pub(crate) fn outbound(&self) -> &Arc<dyn Outbound> {
        &self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_after_the_epoch() {
        assert!(SystemClock.now_unix() > 0.0);
    }

    #[test]
    fn null_outbound_send_discards() {
        NullOutbound.send(vec![1, 2, 3]);
    }

    #[test]
    fn lifecycle_round_trips_through_the_atomic_cell() {
        for l in [
            SessionLifecycle::None,
            SessionLifecycle::Init,
            SessionLifecycle::Established,
            SessionLifecycle::Closed,
        ] {
            let cell = AtomicLifecycle::new(l);
            assert_eq!(cell.load(), l);
            let other = AtomicLifecycle::new(SessionLifecycle::None);
            other.store(l);
            assert_eq!(other.load(), l);
        }
    }

    #[test]
    #[should_panic(expected = "invalid SessionLifecycle discriminant")]
    fn decode_rejects_unknown_discriminant() {
        // Only 0..=3 are ever written (via `as u8`); any other byte is corruption.
        let _ = decode(4);
    }
}
