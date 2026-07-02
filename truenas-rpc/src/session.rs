//! Per-connection [`Session`] state — the **Control-plane** concern's session state machine — plus
//! the [`Outbound`] back-channel sink and the injectable [`IdGen`] / [`Clock`] seams (default
//! UUIDv4 / system time) that make dispatch deterministic for unit tests and the A/B harness.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::role::RoleMask;
use crate::types::SessionLifecycle;

/// A session / subscription / connection identifier.
pub type SessionId = uuid::Uuid;

/// Where a connection came from, for the `$/sessions` admin listing. The **server** attaches this
/// from the connection's peer at session creation (via [`Session::set_origin`]); the generic core
/// stores it opaquely — it never names a transport type itself.
#[derive(Clone, Debug)]
pub struct SessionOrigin {
    /// The transport the connection arrived on (`"unix"` / `"tcp"`).
    pub transport: &'static str,
    /// The TCP peer address (`"addr:port"`), or `None` on AF_UNIX.
    pub remote: Option<String>,
    /// The AF_UNIX peer uid (`SO_PEERCRED`), or `None` on TCP.
    pub uid: Option<u32>,
    /// Whether the transport is confidential (TLS, or AF_UNIX local trust).
    pub secure: bool,
}

/// A standardized summary of the credential a session authenticated with, for the `$/sessions`
/// listing. The **auth stack** sets this at `$/sessionSetup` (via [`Session::set_credential`]):
/// `description` names the mechanism + principal (e.g. `"UNIX_SOCKET uid=0"`, `"SCRAM user=alice"`),
/// `uid` is the resolved account uid if any.
#[derive(Clone, Debug)]
pub struct Credential {
    /// A human-readable credential description (mechanism + principal).
    pub description: String,
    /// The authenticated account uid, if resolved.
    pub uid: Option<u32>,
}

/// The kind of a long-lived [operation](Session::track_operation) tracked on a session — a mode
/// switch that takes over the connection for an extended, admin-visible span. **Normal method calls
/// are deliberately not tracked**: they complete in microseconds, so recording each one would put a
/// lock on the dispatch hot path for no admin value. Only these rare hand-offs are registered, which
/// is why the observability adds nothing to the request/reply fast path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    /// A raw-fd transfer: the handler was lent the connection's socket fd for a self-delimiting bulk
    /// stream (e.g. a dataset send/receive), which can run for minutes or hours.
    Transfer,
    /// A passthrough auth take-over: a `$/sessionSetup` handler took the connection fd to finish
    /// authentication out-of-band.
    Passthrough,
}

impl OperationKind {
    /// A stable, lowercase label for the `$/sessions` listing and the admin dump.
    pub fn as_str(self) -> &'static str {
        match self {
            OperationKind::Transfer => "transfer",
            OperationKind::Passthrough => "passthrough",
        }
    }
}

/// One live operation recorded on a session (held under the session's operation lock).
struct OperationRecord {
    id: u64,
    kind: OperationKind,
    label: Arc<str>,
    started: Instant,
}

/// A session's operation registry: a monotonic id source + the live records. The lock guarding it is
/// taken **only** when a transfer/passthrough begins or ends, or when an admin snapshots the tree —
/// never on the normal request/reply path.
#[derive(Default)]
struct OpRegistry {
    next_id: u64,
    live: Vec<OperationRecord>,
}

/// A point-in-time view of one in-flight [operation](OperationKind) on a session, for the
/// `$/sessions` listing and the server's SIGUSR2 dump.
#[derive(Clone, Debug)]
pub struct OperationInfo {
    /// A per-session monotonic id (also the start order).
    pub id: u64,
    /// What kind of operation this is.
    pub kind: OperationKind,
    /// The label — the method that initiated the operation.
    pub label: Arc<str>,
    /// How long it has been running.
    pub age: Duration,
}

/// RAII guard returned by [`Session::track_operation`]: ends the operation (removes it from the
/// session registry) when dropped, so a completed, panicked, or dropped/cancelled hand-off always
/// clears. Held for the operation's lifetime — dropping it immediately ends the operation.
#[must_use = "dropping the guard immediately ends the operation; hold it for the operation's lifetime"]
pub struct OperationGuard<S> {
    session: Arc<Session<S>>,
    id: u64,
}

impl<S> Drop for OperationGuard<S> {
    fn drop(&mut self) {
        self.session.end_operation(self.id);
    }
}

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
    // When the session was created — a **monotonic** `Instant` (the session registry is in-memory
    // and dies on reboot, so age + ordering is what matters, not wall-clock; immune to NTP jumps).
    created: Instant,
    lifecycle: AtomicLifecycle,
    internal: RwLock<Option<S>>,
    external: RwLock<Option<serde_json::Value>>,
    // The granted-roles [`RoleMask`] (u64): written once at `sessionSetup` (`set_roles`), read
    // lock-free on every gated call (`granted_roles`).
    roles: AtomicU64,
    // Connection origin (set once by the server at connect) + the authenticated credential summary
    // (set by the auth stack at setup). Both are surfaced by the `$/sessions` default listing.
    origin: OnceLock<SessionOrigin>,
    credential: RwLock<Option<Credential>>,
    out: Arc<dyn Outbound>,
    // Live long-lived operations (raw-fd transfers / passthrough take-overs) for the `$/sessions`
    // listing and the SIGUSR2 dump. The lock is taken only when such an operation begins/ends or an
    // admin reads the tree — never on the normal dispatch path, so request/reply pays nothing for it.
    op_registry: Mutex<OpRegistry>,
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
            created: Instant::now(),
            lifecycle: AtomicLifecycle::new(SessionLifecycle::None),
            internal: RwLock::new(internal),
            external: RwLock::new(None),
            roles: AtomicU64::new(0),
            origin: OnceLock::new(),
            credential: RwLock::new(None),
            out,
            op_registry: Mutex::new(OpRegistry::default()),
        }
    }

    /// The protocol-generated session id (never serialized to the wire).
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// When the session was created, as a **monotonic** [`Instant`]. The session registry is
    /// in-memory (it doesn't survive a reboot), so what matters is age + ordering, not an absolute
    /// wall-clock time; this is also immune to NTP / clock adjustments. Age is `created().elapsed()`.
    pub fn created(&self) -> Instant {
        self.created
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
        f(self
            .internal
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref())
    }

    /// Replace the server-internal state (a setup handler sets the identity here).
    pub fn set_internal(&self, state: S) {
        *self
            .internal
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(state);
    }

    /// Mutate the server-internal state in place (e.g. enrich an identity across setup
    /// rounds).
    pub fn with_internal_mut<R>(&self, f: impl FnOnce(&mut Option<S>) -> R) -> R {
        f(&mut self
            .internal
            .write()
            .unwrap_or_else(PoisonError::into_inner))
    }

    /// The client-facing setup result (`server_state_external`), if any.
    pub fn external(&self) -> Option<serde_json::Value> {
        self.external
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set_external(&self, value: serde_json::Value) {
        *self
            .external
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(value);
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

    /// Attach the connection [`SessionOrigin`]. The server calls this once at connect, from the
    /// peer; origin is fixed per connection, so a second call is ignored.
    pub fn set_origin(&self, origin: SessionOrigin) {
        let _ = self.origin.set(origin);
    }

    /// The connection [`SessionOrigin`], if the server attached one (surfaced by `$/sessions`).
    pub fn origin(&self) -> Option<&SessionOrigin> {
        self.origin.get()
    }

    /// Set the authenticated [`Credential`] summary. The auth stack calls this at `$/sessionSetup`
    /// (re-settable across multi-round auth).
    pub fn set_credential(&self, credential: Credential) {
        *self
            .credential
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(credential);
    }

    /// Read the [`Credential`] summary (set by the auth stack); the closure runs under a brief read
    /// lock — do not `.await` inside it.
    pub fn with_credential<R>(&self, f: impl FnOnce(Option<&Credential>) -> R) -> R {
        f(self
            .credential
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref())
    }

    /// Begin tracking a long-lived [operation](OperationKind) (a raw-fd transfer or a passthrough
    /// take-over) on this session, returning an RAII [`OperationGuard`] that unregisters it on drop —
    /// so a completed, panicked, or dropped/cancelled hand-off always clears. Surfaced by
    /// [`operations`](Self::operations), the `$/sessions` listing, and the server's SIGUSR2 dump.
    ///
    /// This is **not** called on the request/reply fast path — only for the rare mode-switch
    /// hand-offs — so the per-session lock it takes never touches normal dispatch.
    pub fn track_operation(
        self: &Arc<Self>,
        kind: OperationKind,
        label: Arc<str>,
    ) -> OperationGuard<S> {
        let mut reg = self
            .op_registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let id = reg.next_id;
        reg.next_id += 1;
        reg.live.push(OperationRecord {
            id,
            kind,
            label,
            started: Instant::now(),
        });
        drop(reg);
        OperationGuard {
            session: self.clone(),
            id,
        }
    }

    /// Remove an operation by id — called by [`OperationGuard`]'s drop.
    fn end_operation(&self, id: u64) {
        self.op_registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .live
            .retain(|o| o.id != id);
    }

    /// Snapshot the live operations on this session (oldest first) for the `$/sessions` listing and
    /// the admin dump. Normal method calls are not tracked, so this lists only in-flight raw-fd
    /// transfers / passthrough take-overs.
    pub fn operations(&self) -> Vec<OperationInfo> {
        self.op_registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .live
            .iter()
            .map(|o| OperationInfo {
                id: o.id,
                kind: o.kind,
                label: o.label.clone(),
                age: o.started.elapsed(),
            })
            .collect()
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

    #[test]
    fn track_operation_registers_and_guard_unregisters_on_drop() {
        let s: Arc<Session<()>> = Arc::new(Session::new(
            SessionId::nil(),
            "t".into(),
            Some(()),
            Arc::new(NullOutbound),
        ));
        assert!(s.operations().is_empty());

        let g0 = s.track_operation(OperationKind::Transfer, Arc::from("snapshot.receive"));
        let g1 = s.track_operation(OperationKind::Passthrough, Arc::from("$/sessionSetup"));
        let live = s.operations();
        assert_eq!(live.len(), 2);
        assert_eq!(live[0].id, 0);
        assert_eq!(live[0].kind, OperationKind::Transfer);
        assert_eq!(live[0].kind.as_str(), "transfer");
        assert_eq!(live[0].label.as_ref(), "snapshot.receive");
        assert!(live[0].age >= Duration::ZERO);
        assert_eq!(live[1].id, 1);
        assert_eq!(live[1].kind, OperationKind::Passthrough);
        assert_eq!(live[1].kind.as_str(), "passthrough");

        // Dropping the first guard unregisters exactly that operation; `retain` keeps order.
        drop(g0);
        let live = s.operations();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, 1);
        assert_eq!(live[0].kind, OperationKind::Passthrough);

        drop(g1);
        assert!(s.operations().is_empty());
    }
}
