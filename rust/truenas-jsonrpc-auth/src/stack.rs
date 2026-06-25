//! [`AuthStack`] — the enabled mechanisms + the peer-cred default — and [`install`], which wires
//! it onto a protocol's `$/sessionSetup` / `$/sessionSetupContinue`.

use std::collections::HashMap;
use std::sync::Arc;

use truenas_jsonrpc::{
    JsonRpcError, JsonRpcProtocolBuilder, MethodDef, Session, SessionId, SessionLifecycle,
};
use truenas_jsonrpc_server::Transport;

use crate::channel::Channel;
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Identity, Outcome, RejectKind};
use crate::state::{AuthSession, AuthSessionState};
use crate::wire::{AuthResponse, AuthResult, ContinueArgs, SetupArgs};

/// An AF_UNIX peer-cred verifier: map the connecting process's credentials to an identity, or
/// `None` to fall through (the connection must then use an explicit mechanism).
type PeercredFn = Box<dyn Fn(&Channel) -> Option<Identity> + Send + Sync>;

/// The configured authentication stack: the mechanisms enabled for this protocol (keyed by wire
/// tag) plus an optional AF_UNIX peer-cred default. Build it with [`AuthStack::builder`] and wire
/// it on with [`install`].
pub struct AuthStack {
    peercred: Option<PeercredFn>,
    mechanisms: HashMap<String, Box<dyn Mechanism>>,
}

/// Builder for [`AuthStack`].
#[derive(Default)]
pub struct AuthStackBuilder {
    peercred: Option<PeercredFn>,
    mechanisms: HashMap<String, Box<dyn Mechanism>>,
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
            Some(identity) => Outcome::authenticated(identity),
            None => Outcome::Reject(RejectKind::AuthErr),
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

    /// `$/sessionSetup` handler (valid only at `None`, enforced by the core).
    fn on_setup(
        &self,
        args: SetupArgs,
        session: &Session<AuthSession>,
    ) -> Result<(SessionLifecycle, AuthResult), JsonRpcError> {
        let session_id = session.id();
        session.with_internal_mut(|slot| {
            let auth = slot.as_mut().ok_or_else(missing_state)?;
            let outcome = match &args.mechanism {
                None => self.peercred_default(&auth.channel),
                Some(mech) => self.dispatch(mech, &auth.channel, None),
            };
            Ok(commit(auth, outcome, session_id))
        })
    }

    /// `$/sessionSetupContinue` handler (valid only at `Init`, enforced by the core).
    fn on_continue(
        &self,
        args: ContinueArgs,
        session: &Session<AuthSession>,
    ) -> Result<(SessionLifecycle, AuthResult), JsonRpcError> {
        let session_id = session.id();
        session.with_internal_mut(|slot| {
            let auth = slot.as_mut().ok_or_else(missing_state)?;
            // Take the carried in-progress state; anything else is out of sequence.
            let progress = match std::mem::replace(&mut auth.state, AuthSessionState::Unauthenticated)
            {
                AuthSessionState::InProgress(p) => p,
                other => {
                    auth.state = other;
                    return Ok((SessionLifecycle::None, AuthResult { response: AuthResponse::AuthErr }));
                }
            };
            // A continue must stay on the in-progress mechanism.
            let outcome = if mech_tag(&args.mechanism) == Some(progress.tag) {
                self.dispatch(&args.mechanism, &auth.channel, Some(progress))
            } else {
                Outcome::Reject(RejectKind::AuthErr)
            };
            Ok(commit(auth, outcome, session_id))
        })
    }
}

impl AuthStackBuilder {
    /// Set the AF_UNIX peer-cred default: a connection with no declared mechanism authenticates by
    /// its `SO_PEERCRED` credentials. Return `None` from `f` to require an explicit mechanism.
    #[must_use]
    pub fn peercred(
        mut self,
        f: impl Fn(&Channel) -> Option<Identity> + Send + Sync + 'static,
    ) -> Self {
        self.peercred = Some(Box::new(f));
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
        Arc::new(AuthStack { peercred: self.peercred, mechanisms: self.mechanisms })
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
        .session_setup(
            MethodDef::new("$/sessionSetup").secret_fields(["mechanism"]),
            move |args: SetupArgs, session: &Session<AuthSession>| setup.on_setup(args, session),
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
/// session's auth state in place. `session_id` is returned to the client on success.
fn commit(
    auth: &mut AuthSession,
    outcome: Outcome,
    session_id: SessionId,
) -> (SessionLifecycle, AuthResult) {
    match outcome {
        Outcome::Authenticated { identity, user_info, extra } => {
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
    }
}
