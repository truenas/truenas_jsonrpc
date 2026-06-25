//! [`AuthStack`] — the enabled mechanisms + the peer-cred default — and [`install`], which wires
//! it onto a protocol's `$/sessionSetup` / `$/sessionSetupContinue`.

use std::collections::HashMap;
use std::sync::Arc;

use truenas_jsonrpc::{
    JsonRpcError, JsonRpcProtocolBuilder, MethodDef, RoleMask, Roles, Session, SessionId,
    SessionLifecycle, SetupOutcome,
};
use truenas_jsonrpc_server::Transport;

/// The conventional role name that grants every privilege (mapped to [`RoleMask::FULL_ADMIN`]).
pub const FULL_ADMIN: &str = "FULL_ADMIN";

use crate::channel::Channel;
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Identity, Outcome, RejectKind};
use crate::state::{AuthSession, AuthSessionState};
use crate::wire::{AuthResponse, AuthResult, ContinueArgs, SetupArgs};

/// An AF_UNIX peer-cred verifier: map the connecting process's credentials to an identity plus its
/// granted role names (e.g. `uid 0 → ["FULL_ADMIN"]`), or `None` to fall through (the connection
/// must then use an explicit mechanism).
type PeercredFn = Box<dyn Fn(&Channel) -> Option<(Identity, Vec<String>)> + Send + Sync>;

/// The configured authentication stack: the mechanisms enabled for this protocol (keyed by wire
/// tag) plus an optional AF_UNIX peer-cred default. Build it with [`AuthStack::builder`] and wire
/// it on with [`install`].
pub struct AuthStack {
    peercred: Option<PeercredFn>,
    mechanisms: HashMap<String, Box<dyn Mechanism>>,
    registry: Option<Roles>,
}

/// Builder for [`AuthStack`].
#[derive(Default)]
pub struct AuthStackBuilder {
    peercred: Option<PeercredFn>,
    mechanisms: HashMap<String, Box<dyn Mechanism>>,
    registry: Option<Roles>,
}

impl AuthStack {
    /// Start configuring an auth stack.
    pub fn builder() -> AuthStackBuilder {
        AuthStackBuilder::default()
    }

    /// Run the channel default for `$/sessionSetup` with no mechanism: AF_UNIX peer-cred, or a
    /// refusal on a network transport (which must declare a mechanism).
    fn peercred_default(&self, channel: &Channel) -> Outcome {
        if channel.transport != Transport::Unix {
            return Outcome::Reject(RejectKind::Denied);
        }
        match self.peercred.as_ref().and_then(|f| f(channel)) {
            Some((identity, roles)) => Outcome::authenticated_with_roles(identity, roles),
            None => Outcome::Reject(RejectKind::AuthErr),
        }
    }

    /// Convert granted role *names* to a [`RoleMask`] via the registry: [`FULL_ADMIN`] grants every
    /// role (all-ones), otherwise the union of each registered name's bit. Unknown names are
    /// ignored (a stale role in a credential doesn't fail the whole authentication).
    fn granted_mask(&self, names: &[String]) -> RoleMask {
        if names.iter().any(|n| n == FULL_ADMIN) {
            return RoleMask::FULL_ADMIN;
        }
        let Some(reg) = &self.registry else { return RoleMask::NONE };
        names.iter().fold(RoleMask::NONE, |acc, n| match reg.get(n) {
            Some(bit) => acc.union(bit),
            None => acc,
        })
    }

    /// The granted mask an [`Outcome`] confers (only [`Outcome::Authenticated`] grants roles).
    fn granted_mask_of(&self, outcome: &Outcome) -> RoleMask {
        match outcome {
            Outcome::Authenticated { roles, .. } => self.granted_mask(roles),
            _ => RoleMask::NONE,
        }
    }

    /// Route a mechanism request to its handler (tag lookup → capability gate → `step`).
    fn dispatch(
        &self,
        mech: &serde_json::Value,
        channel: &Channel,
        progress: Option<AuthProgress>,
    ) -> Outcome {
        let Some(tag) = mech_tag(mech) else {
            return Outcome::Reject(RejectKind::AuthErr);
        };
        let Some(handler) = self.mechanisms.get(tag) else {
            return Outcome::Reject(RejectKind::AuthErr); // unsupported / not enabled
        };
        if !channel.has_all(handler.required()) {
            return Outcome::Reject(RejectKind::Denied);
        }
        handler.step(mech, channel, progress)
    }

    /// `$/sessionSetup` handler (valid only at `None`, enforced by the core). Most mechanisms
    /// commit synchronously; passthrough instead returns a [`SetupOutcome::Takeover`] so the server
    /// can hand the connection fd to the broker.
    fn on_setup(
        &self,
        args: SetupArgs,
        session: &Arc<Session<AuthSession>>,
    ) -> Result<SetupOutcome<AuthResult>, JsonRpcError> {
        let session_id = session.id();
        // The channel is immutable; clone it out so the mechanism (and any takeover closure) can use
        // it without holding the session lock.
        let channel = session
            .with_internal(|slot| slot.map(|a| a.channel.clone()))
            .ok_or_else(missing_state)?;
        let outcome = match &args.mechanism {
            None => self.peercred_default(&channel),
            Some(mech) => self.dispatch(mech, &channel, None),
        };
        Ok(self.build_setup_outcome(outcome, session, session_id, &channel))
    }

    /// Map a mechanism [`Outcome`] onto the core's [`SetupOutcome`]: a passthrough becomes a
    /// connection takeover; everything else commits synchronously in place.
    fn build_setup_outcome(
        &self,
        outcome: Outcome,
        session: &Arc<Session<AuthSession>>,
        session_id: SessionId,
        channel: &Channel,
    ) -> SetupOutcome<AuthResult> {
        #[cfg(feature = "passthrough")]
        if let Outcome::Passthrough(broker) = outcome {
            return SetupOutcome::Takeover(crate::passthrough::takeover(
                broker,
                channel,
                session.clone(),
                session_id,
            ));
        }
        let _ = channel;
        // The granted roles (if any) become the session's role mask for the per-call gate.
        let granted = self.granted_mask_of(&outcome);
        let (lifecycle, result) = session.with_internal_mut(|slot| match slot.as_mut() {
            Some(auth) => commit(auth, outcome, session_id),
            None => (SessionLifecycle::None, AuthResult { response: AuthResponse::AuthErr }),
        });
        session.set_roles(granted);
        SetupOutcome::Commit(lifecycle, result)
    }

    /// `$/sessionSetupContinue` handler (valid only at `Init`, enforced by the core).
    fn on_continue(
        &self,
        args: ContinueArgs,
        session: &Session<AuthSession>,
    ) -> Result<(SessionLifecycle, AuthResult), JsonRpcError> {
        let session_id = session.id();
        type Committed = ((SessionLifecycle, AuthResult), RoleMask);
        let (committed, granted) = session.with_internal_mut(|slot| -> Result<Committed, JsonRpcError> {
            let auth = slot.as_mut().ok_or_else(missing_state)?;
            // Take the carried in-progress state; anything else is out of sequence.
            let progress = match std::mem::replace(&mut auth.state, AuthSessionState::Unauthenticated)
            {
                AuthSessionState::InProgress(p) => p,
                other => {
                    auth.state = other;
                    let reject = AuthResult { response: AuthResponse::AuthErr };
                    return Ok(((SessionLifecycle::None, reject), RoleMask::NONE));
                }
            };
            // A continue must stay on the in-progress mechanism.
            let outcome = if mech_tag(&args.mechanism) == Some(progress.tag) {
                self.dispatch(&args.mechanism, &auth.channel, Some(progress))
            } else {
                Outcome::Reject(RejectKind::AuthErr)
            };
            let granted = self.granted_mask_of(&outcome);
            Ok((commit(auth, outcome, session_id), granted))
        })?;
        session.set_roles(granted);
        Ok(committed)
    }
}

impl AuthStackBuilder {
    /// Set the AF_UNIX peer-cred default: a connection with no declared mechanism authenticates by
    /// its `SO_PEERCRED` credentials, returning the identity plus its granted role names (e.g.
    /// `uid 0 → ["FULL_ADMIN"]`). Return `None` from `f` to require an explicit mechanism.
    #[must_use]
    pub fn peercred(
        mut self,
        f: impl Fn(&Channel) -> Option<(Identity, Vec<String>)> + Send + Sync + 'static,
    ) -> Self {
        self.peercred = Some(Box::new(f));
        self
    }

    /// Set the role registry — the canonical role taxonomy. The stack interns the role names a
    /// mechanism grants into a [`RoleMask`] at `sessionSetup`. Use the **same** [`Roles`] you pass
    /// to the protocol builder's [`roles`](truenas_jsonrpc::JsonRpcProtocolBuilder::roles) so the
    /// granted and required masks share one numbering.
    #[must_use]
    pub fn roles(mut self, roles: Roles) -> Self {
        self.registry = Some(roles);
        self
    }

    /// Enable a mechanism under its wire `tag` (the `"mechanism"` value clients send).
    #[must_use]
    pub fn mechanism(mut self, tag: impl Into<String>, mechanism: impl Mechanism + 'static) -> Self {
        self.mechanisms.insert(tag.into(), Box::new(mechanism));
        self
    }

    /// Freeze into a shared [`AuthStack`].
    pub fn build(self) -> Arc<AuthStack> {
        Arc::new(AuthStack {
            peercred: self.peercred,
            mechanisms: self.mechanisms,
            registry: self.registry,
        })
    }
}

/// Wire `stack` onto `builder`'s `$/sessionSetup` / `$/sessionSetupContinue` (both always audited,
/// credentials redacted). Registering session setup also turns on the core's
/// session-established gate and the server's network-auth guard.
pub fn install(
    builder: JsonRpcProtocolBuilder<AuthSession>,
    stack: Arc<AuthStack>,
) -> JsonRpcProtocolBuilder<AuthSession> {
    let setup = stack.clone();
    let cont = stack;
    builder
        .session_setup_takeover(
            MethodDef::new("$/sessionSetup").secret_fields(["mechanism"]),
            move |args: SetupArgs, session: &Arc<Session<AuthSession>>| setup.on_setup(args, session),
        )
        .session_setup_continue(
            MethodDef::new("$/sessionSetupContinue").secret_fields(["mechanism"]),
            move |args: ContinueArgs, session: &Session<AuthSession>| cont.on_continue(args, session),
        )
}

/// The `"mechanism"` tag inside a mechanism request object.
fn mech_tag(mech: &serde_json::Value) -> Option<&str> {
    mech.get("mechanism").and_then(serde_json::Value::as_str)
}

fn missing_state() -> JsonRpcError {
    JsonRpcError::request_failed(
        "auth session state is missing — set .state_from_peer(AuthSession::from_peer) on the server",
    )
}

/// Map a mechanism [`Outcome`] onto the `(lifecycle, reply)` the core commits, advancing the
/// session's auth state in place. `session_id` is returned to the client on success. (Shared with
/// the passthrough takeover closure, which commits the broker's verdict the same way.)
pub(crate) fn commit(
    auth: &mut AuthSession,
    outcome: Outcome,
    session_id: SessionId,
) -> (SessionLifecycle, AuthResult) {
    match outcome {
        // `roles` were converted to the session's mask by the caller (`granted_mask_of`).
        Outcome::Authenticated { identity, roles: _, user_info, extra } => {
            auth.state = AuthSessionState::Authenticated(identity);
            let response =
                AuthResponse::Success { session_id: session_id.to_string(), user_info, extra };
            (SessionLifecycle::Established, AuthResult { response })
        }
        Outcome::Challenge { reply, next } => {
            auth.state = AuthSessionState::InProgress(next);
            (SessionLifecycle::Init, AuthResult { response: reply })
        }
        Outcome::Reject(kind) => {
            auth.state = AuthSessionState::Unauthenticated;
            (SessionLifecycle::None, AuthResult { response: kind.into() })
        }
        // Passthrough is intercepted before `commit` (it becomes a takeover, not a sync commit);
        // this arm only keeps the match exhaustive.
        #[cfg(feature = "passthrough")]
        Outcome::Passthrough(_) => {
            auth.state = AuthSessionState::Unauthenticated;
            (SessionLifecycle::None, AuthResult { response: AuthResponse::AuthErr })
        }
    }
}
