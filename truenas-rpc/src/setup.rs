//! Session-setup outcomes that can **take over the connection** — the **Control-plane** session-setup
//! seam for passthrough **Authentication**, where the handshake is completed out-of-band by handing
//! the connection's fd to a broker (see `truenas-rpc-auth`'s passthrough mechanism).
//!
//! A normal `$/sessionSetup` handler finishes synchronously: it returns
//! [`SetupOutcome::Commit`] and the core commits the lifecycle + reply. A passthrough handler
//! cannot — it must hand the connection fd to the broker, which talks to the client directly — so
//! it returns [`SetupOutcome::Takeover`] carrying a [`SetupHandoff`]. The core then yields a
//! [`crate::Dispatched::Passthrough`] directive; the **server** gates the connection (pausing the
//! reader, holding the writer) and runs it with the connection's fd, and the core commits the
//! resulting lifecycle + audit inside the directive.

use serde_json::value::RawValue;

use crate::error::JsonRpcError;
use crate::transfer::FileTransfer;
use crate::types::SessionLifecycle;

/// What a `$/sessionSetup` handler produces. `R` is the synchronous reply type.
pub enum SetupOutcome<R> {
    /// Commit `lifecycle` and reply with `R` — the synchronous path (peer-cred, mTLS, SCRAM).
    Commit(SessionLifecycle, R),
    /// Take over the connection: the server hands the fd to the [`SetupHandoff`], which finishes
    /// authentication out-of-band (the passthrough broker) and yields the lifecycle + reply.
    Takeover(SetupHandoff),
}

/// The handler-provided half of a setup takeover: given the connection's [`FileTransfer`] (its raw
/// fd), finish authentication out-of-band and return the resulting lifecycle plus the
/// already-encoded reply. The core wraps this with the session-lifecycle commit and the audit
/// record, so the closure only does the hand-off and reports what happened.
pub struct SetupHandoff {
    pub(crate) fd_handoff: bool,
    #[allow(clippy::type_complexity)]
    pub(crate) complete:
        Box<dyn FnOnce(&dyn FileTransfer) -> Result<(SessionLifecycle, Box<RawValue>), JsonRpcError> + Send>,
}

impl SetupHandoff {
    /// Build a takeover. `fd_handoff` marks that the hand-off passes the connection's fd to an
    /// out-of-band authenticator (a broker), so the server applies its transport-posture policy and
    /// supplies the fd before running it. `complete` runs on the server's blocking worker once the
    /// connection is gated and the fd is available, and returns the lifecycle + encoded reply (or an
    /// error, which leaves the session unauthenticated).
    pub fn new<F>(fd_handoff: bool, complete: F) -> Self
    where
        F: FnOnce(&dyn FileTransfer) -> Result<(SessionLifecycle, Box<RawValue>), JsonRpcError> + Send + 'static,
    {
        Self { fd_handoff, complete: Box::new(complete) }
    }
}

/// The boxed, state-erased work that runs a setup takeover with the connection's fd.
pub(crate) type TakeoverRun = Box<dyn FnOnce(&dyn FileTransfer) + Send>;

/// The [`crate::Dispatched::Passthrough`] directive: a `$/sessionSetup` handler took over the
/// connection. The server gates the connection, applies its transport-posture policy
/// ([`hands_off_fd`]), puts the fd in blocking mode, and calls [`run`] with it. `run` performs the
/// hand-off and commits the session (lifecycle + audit) inside the core; the broker has already
/// replied to the client over the fd, so the server sends nothing further.
///
/// [`hands_off_fd`]: SetupTakeover::hands_off_fd
/// [`run`]: SetupTakeover::run
pub struct SetupTakeover {
    fd_handoff: bool,
    rid: Option<String>,
    run: TakeoverRun,
}

impl SetupTakeover {
    pub(crate) fn new(rid: Option<String>, fd_handoff: bool, run: TakeoverRun) -> Self {
        Self { fd_handoff, rid, run }
    }

    /// Whether the hand-off passes the connection's fd to an out-of-band authenticator — the server
    /// applies its transport-posture policy (and supplies the fd) before running it.
    pub fn hands_off_fd(&self) -> bool {
        self.fd_handoff
    }

    /// The request id of the `$/sessionSetup` that initiated the takeover.
    pub fn request_id(&self) -> Option<&str> {
        self.rid.as_deref()
    }

    /// Run the hand-off with the connection's `file_transfer` (its fd), committing the session
    /// inside the core. Consumes the directive — it finishes exactly one takeover.
    pub fn run(self, file_transfer: &dyn FileTransfer) {
        (self.run)(file_transfer)
    }
}

impl std::fmt::Debug for SetupTakeover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupTakeover").field("fd_handoff", &self.fd_handoff).field("rid", &self.rid).finish_non_exhaustive()
    }
}
