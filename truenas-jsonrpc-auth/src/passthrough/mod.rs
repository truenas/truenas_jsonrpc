//! Passthrough authentication (the `passthrough` feature): hand the client connection's fd to a
//! local AF_UNIX **broker**, which conducts the handshake on its dup of the fd and returns a
//! verdict — "authentication as a daemon". The server stays out of the credential path; the broker
//! (which speaks the same `$/sessionSetup` wire to the client) is the only holder of secrets.
//!
//! Two halves live here:
//! - the [`Passthrough`] [`Mechanism`] + the [`BrokerContext`] / [`BrokerVerdict`] it exchanges,
//!   used by a server that *delegates* to a broker;
//! - the [`BrokerServer`], used by a process that *is* a broker.
//!
//! **How it is wired.** [`Passthrough::step`] can't finish inline — the hand-off needs the
//! connection's plaintext fd with the reader **paused** (the broker reads/writes that fd), which is
//! a connection-takeover concern, exactly like the [`run_transfer`] the server already performs for
//! raw-fd transfers. So `step` returns [`Outcome::Passthrough`], the auth stack turns it into a
//! [`SetupOutcome::Takeover`](truenas_jsonrpc::SetupOutcome), and the server gates the connection and
//! runs [`takeover`] with the fd — which calls [`handoff`](Passthrough::handoff), hands the broker
//! the fd (`SCM_RIGHTS`), and commits the verdict (identity + `(uid, mechanism)` roles + credential).
//! The whole path — broker wire and the `$/sessionSetup` takeover trigger — is implemented and tested
//! end to end (`tests/passthrough.rs`, `tests/passthrough_server.rs`). Eligibility is by transport
//! **posture**: passthrough runs over any connection with a secure posture *and* a passable plaintext
//! fd — AF_UNIX (local or proxied) and kTLS — and is refused over WebSocket / userspace-TLS (no fd)
//! and plain TCP (no posture). The server enforces the fd requirement; the auth stack the posture.
//!
//! [`run_transfer`]: https://docs.rs/truenas-jsonrpc-server

mod broker;
mod context;
mod protocol;

use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use truenas_jsonrpc::{FileTransfer, JsonRpcError, Session, SessionId, SessionLifecycle, SetupHandoff};

use crate::channel::{Capability, Channel};
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Outcome, RejectKind};
use crate::stack::{AuthStack, AuthStackBuilder};
use crate::state::AuthSession;
use crate::wire::{AuthResponse, AuthResult};

pub use self::broker::BrokerServer;
pub use self::context::{BrokerContext, BrokerVerdict, PeerCred};

/// The wire tag clients use to select passthrough (`{ "mechanism": "PASSTHROUGH" }`).
pub const PASSTHROUGH_TAG: &str = "PASSTHROUGH";

/// The passthrough mechanism: forward a client connection to the broker listening at `broker` (an
/// AF_UNIX path). Register it with [`AuthStackBuilder::passthrough`].
pub struct Passthrough {
    broker: PathBuf,
}

impl Passthrough {
    /// Build the mechanism, forwarding to the broker at `broker`.
    pub fn new(broker: impl Into<PathBuf>) -> Self {
        Self { broker: broker.into() }
    }

    /// Perform the hand-off for a client connection whose plaintext fd is `client_fd`: connect the
    /// broker, send the fd (`SCM_RIGHTS`) + `ctx`, and map the broker's verdict to an [`Outcome`]
    /// plus the mechanism the broker reported using (`None` unless authenticated).
    ///
    /// **Blocking**, and it requires the connection's reader to be **paused** — the broker conducts
    /// the client handshake on the passed fd, so the server must not read it concurrently. The
    /// connection-takeover seam calls this (not [`step`](Mechanism::step)); any I/O failure (no
    /// broker, short read, bad frame) maps to `Reject(AuthErr)`.
    pub fn handoff(&self, client_fd: RawFd, ctx: &BrokerContext) -> (Outcome, Option<String>) {
        match handoff_io(&self.broker, client_fd, ctx) {
            Ok(verdict) => verdict.into_handoff(),
            Err(_) => (Outcome::Reject(RejectKind::AuthErr), None),
        }
    }
}

fn handoff_io(broker: &Path, client_fd: RawFd, ctx: &BrokerContext) -> std::io::Result<BrokerVerdict> {
    let stream = UnixStream::connect(broker)?;
    protocol::request(&stream, client_fd, ctx)
}

impl Mechanism for Passthrough {
    fn required(&self) -> &'static [Capability] {
        // No channel capability: passthrough is eligible on any connection with a secure transport
        // posture (the auth stack rejects a posture-less setup before any mechanism runs), and the
        // server enforces the passable-fd requirement when it runs the takeover. SCM_RIGHTS passes
        // the client fd over the broker's *local* socket, so the client transport need not be AF_UNIX.
        &[]
    }

    fn step(&self, _payload: &serde_json::Value, _channel: &Channel, _progress: Option<AuthProgress>) -> Outcome {
        // Passthrough can't finish inside `step` — it needs the connection's plaintext fd with the
        // reader *paused* (the broker reads/writes that fd). So signal a takeover: the auth stack
        // turns this into a `SetupOutcome::Takeover` the server runs once it has gated the
        // connection and can supply the fd (see [`takeover`]).
        Outcome::Passthrough(self.broker.clone())
    }
}

impl AuthStackBuilder {
    /// Enable passthrough under the [`PASSTHROUGH_TAG`] tag, forwarding to the broker at `broker`.
    #[must_use]
    pub fn passthrough(self, broker: impl Into<PathBuf>) -> Self {
        self.mechanism(PASSTHROUGH_TAG, Passthrough::new(broker))
    }
}

/// Build the [`SetupHandoff`] for a passthrough takeover. When the server gates the connection and
/// supplies the fd, this hands it (plus the channel-derived [`BrokerContext`]) to the broker at
/// `broker`, then commits the broker's verdict onto the session exactly as a synchronous mechanism
/// would — identity, the `(uid, mechanism)` role mask, and the credential. Called by the auth stack
/// when a mechanism returns [`Outcome::Passthrough`]; `stack` is the authorizing stack.
pub(crate) fn takeover(
    stack: Arc<AuthStack>,
    broker: PathBuf,
    channel: &Channel,
    session: Arc<Session<AuthSession>>,
    session_id: SessionId,
) -> SetupHandoff {
    let ctx = BrokerContext::from_channel(channel);
    SetupHandoff::new(true, move |ft: &dyn FileTransfer| {
        let (outcome, mechanism) = Passthrough::new(&broker).handoff(ft.as_raw_fd(), &ctx);
        // The broker reports the mechanism it actually used (SCRAM/GSSAPI/…): authorize
        // `(uid, mechanism)` → role mask + credential exactly as a synchronous mechanism would,
        // falling back to the outer PASSTHROUGH tag if the broker didn't report one.
        let mech = mechanism.as_deref().unwrap_or(PASSTHROUGH_TAG);
        let (granted, uid) = stack.authorize(&outcome, mech);
        let credential = crate::stack::credential_of(&outcome, mech, uid);
        let (lifecycle, result) = session.with_internal_mut(|slot| match slot.as_mut() {
            Some(auth) => crate::stack::commit(auth, outcome, session_id),
            None => (SessionLifecycle::None, AuthResult { response: AuthResponse::AuthErr }),
        });
        session.set_roles(granted);
        if let Some(cred) = credential {
            session.set_credential(cred);
        }
        let raw = serde_json::value::to_raw_value(&result)
            .map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
        Ok((lifecycle, raw))
    })
}
