//! [`AuthStack`] — the enabled mechanisms + the peer-cred default — and [`install`], which wires
//! it onto a protocol's `$/sessionSetup` / `$/sessionSetupContinue`.

use std::collections::HashMap;
use std::sync::Arc;

use truenas_rpc::{
    Credential, JsonRpcError, JsonRpcProtocolBuilder, MethodDef, RoleMask, Roles, Session,
    SessionId, SessionLifecycle, SetupOutcome,
};
use truenas_rpc_server::TransportPosture;

/// The conventional role name that grants every privilege (mapped to [`RoleMask::FULL_ADMIN`]).
pub const FULL_ADMIN: &str = "FULL_ADMIN";

use crate::channel::Channel;
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Identity, Outcome, Principal, RejectKind};
use crate::state::{AuthSession, AuthSessionState};
use crate::wire::{AuthResponse, AuthResult, ContinueArgs, SetupArgs};

/// An AF_UNIX peer-cred verifier: map the connecting process's credentials to an identity, or
/// `None` to fall through (the connection must then use an explicit mechanism). Authorization comes
/// from the peer's uid (`SO_PEERCRED`) via `server_roles`, not from this closure.
type PeercredFn = Box<dyn Fn(&Channel) -> Option<Identity> + Send + Sync>;

/// A username→uid resolver (e.g. `getpwnam`): the uid authorization keys off, or `None` if the
/// account is unknown / rejected. Used for [`Principal::User`] (SCRAM / mTLS).
type UserResolverFn = Box<dyn Fn(&str) -> Option<u32> + Send + Sync>;

/// A `(uid, mechanism)`→roles source (e.g. the `server_roles` keyring): the role names granted to a
/// uid that authenticated via a given mechanism. Authorization is **assurance/channel-based** — one
/// account may be granted different roles over different mechanisms (local socket vs SCRAM vs mTLS).
type RoleSourceFn = Box<dyn Fn(u32, &str) -> Vec<String> + Send + Sync>;

/// The configured authentication stack: the mechanisms enabled for this protocol (keyed by wire
/// tag) plus an optional AF_UNIX peer-cred default. Build it with [`AuthStack::builder`] and wire
/// it on with [`install`].
pub struct AuthStack {
    peercred: Option<PeercredFn>,
    mechanisms: HashMap<String, Box<dyn Mechanism>>,
    registry: Option<Roles>,
    user_resolver: Option<UserResolverFn>,
    role_source: Option<RoleSourceFn>,
}

/// Builder for [`AuthStack`].
#[derive(Default)]
pub struct AuthStackBuilder {
    peercred: Option<PeercredFn>,
    mechanisms: HashMap<String, Box<dyn Mechanism>>,
    registry: Option<Roles>,
    user_resolver: Option<UserResolverFn>,
    role_source: Option<RoleSourceFn>,
}

impl AuthStack {
    /// Start configuring an auth stack.
    pub fn builder() -> AuthStackBuilder {
        AuthStackBuilder::default()
    }

    /// Run the channel default for `$/sessionSetup` with no mechanism: AF_UNIX peer-cred, or a
    /// refusal on a network transport (which must declare a mechanism).
    fn peercred_default(&self, channel: &Channel) -> Outcome {
        // Peer-cred is trusted only on a genuinely-local socket. A proxied unix socket carries the
        // reverse proxy's uid (not the client's), and a network transport has none — both refuse.
        if channel.posture != Some(TransportPosture::TrustedLocalUnix) {
            return Outcome::Reject(RejectKind::Denied);
        }
        // Authorization keys off the peer's uid (`SO_PEERCRED`); without it we can't authorize.
        let Some(uid) = channel.ucred.map(|c| c.uid) else {
            return Outcome::Reject(RejectKind::AuthErr);
        };
        match self.peercred.as_ref().and_then(|f| f(channel)) {
            Some(identity) => Outcome::authenticated(identity, Principal::Uid(uid)),
            None => Outcome::Reject(RejectKind::AuthErr),
        }
    }

    /// Convert granted role *names* to a [`RoleMask`] via the registry: [`FULL_ADMIN`] grants every
    /// role (all-ones), otherwise the union of each registered name's bit. Unknown names are
    /// ignored (a stale role doesn't fail the whole authentication).
    fn granted_mask(&self, names: &[String]) -> RoleMask {
        if names.iter().any(|n| n == FULL_ADMIN) {
            return RoleMask::FULL_ADMIN;
        }
        let Some(reg) = &self.registry else {
            return RoleMask::NONE;
        };
        names
            .iter()
            .fold(RoleMask::NONE, |acc, n| match reg.get(n) {
                Some(bit) => acc.union(bit),
                None => acc,
            })
    }

    /// Resolve a [`Principal`] to the uid authorization (and the session credential) key off: a
    /// peer-cred uid directly, an account name via the username→uid resolver. [`Principal::None`],
    /// an unresolvable name, or no resolver configured yields `None`.
    fn principal_uid(&self, principal: &Principal) -> Option<u32> {
        match principal {
            Principal::Uid(uid) => Some(*uid),
            Principal::User(name) => self.user_resolver.as_ref().and_then(|f| f(name)),
            Principal::None => None,
        }
    }

    /// The role *names* granted to a resolved uid authenticating via `mechanism`: **uid 0 is always
    /// full admin** (an anti-lockout net — root over any mechanism, no record needed); any other uid
    /// reads its roles from the `(uid, mechanism)` source (nothing if none is configured); `None`
    /// grants nothing.
    fn roles_for(&self, uid: Option<u32>, mechanism: &str) -> Vec<String> {
        match uid {
            Some(0) => vec![FULL_ADMIN.to_string()],
            Some(uid) => self
                .role_source
                .as_ref()
                .map(|f| f(uid, mechanism))
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Authorize an [`Outcome`] (only [`Outcome::Authenticated`] grants anything) for a session that
    /// authenticated via `mechanism`: resolve the principal to a uid **once**, then to the granted
    /// [`RoleMask`] via the `(uid, mechanism)` role source + registry. Returns the uid alongside so
    /// the caller can record it in the session [`Credential`] without resolving the principal twice.
    pub(crate) fn authorize(&self, outcome: &Outcome, mechanism: &str) -> (RoleMask, Option<u32>) {
        match outcome {
            Outcome::Authenticated { principal, .. } => {
                let uid = self.principal_uid(principal);
                (self.granted_mask(&self.roles_for(uid, mechanism)), uid)
            }
            _ => (RoleMask::NONE, None),
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
        self: &Arc<Self>,
        args: SetupArgs,
        session: &Arc<Session<AuthSession>>,
    ) -> Result<SetupOutcome<AuthResult>, JsonRpcError> {
        let session_id = session.id();
        // The channel is immutable; clone it out so the mechanism (and any takeover closure) can use
        // it without holding the session lock.
        let channel = session
            .with_internal(|slot| slot.map(|a| a.channel.clone()))
            .ok_or_else(missing_state)?;
        // A connection with no declared secure posture (plain TCP / userspace-TLS) may not
        // authenticate — refuse every mechanism before it runs. Otherwise the credential's mechanism
        // label is `UNIX_SOCKET` for the peer-cred default, else the wire tag the client selected.
        let (outcome, label) = if channel.posture.is_none() {
            (Outcome::Reject(RejectKind::Denied), "NONE")
        } else {
            match &args.mechanism {
                None => (self.peercred_default(&channel), "UNIX_SOCKET"),
                Some(mech) => (
                    self.dispatch(mech, &channel, None),
                    mech_tag(mech).unwrap_or("UNKNOWN"),
                ),
            }
        };
        Ok(self.build_setup_outcome(outcome, label, session, session_id, &channel))
    }

    /// Map a mechanism [`Outcome`] onto the core's [`SetupOutcome`]: a passthrough becomes a
    /// connection takeover; everything else commits synchronously in place.
    fn build_setup_outcome(
        self: &Arc<Self>,
        outcome: Outcome,
        mech: &str,
        session: &Arc<Session<AuthSession>>,
        session_id: SessionId,
        channel: &Channel,
    ) -> SetupOutcome<AuthResult> {
        #[cfg(feature = "passthrough")]
        if let Outcome::Passthrough(broker) = outcome {
            return SetupOutcome::Takeover(crate::passthrough::takeover(
                self.clone(),
                broker,
                channel,
                session.clone(),
                session_id,
            ));
        }
        let _ = channel;
        // Resolve authorization once → the per-call gate mask + the account uid; derive the
        // credential summary before `commit` consumes the outcome.
        let (granted, uid) = self.authorize(&outcome, mech);
        let credential = credential_of(&outcome, mech, uid);
        let (lifecycle, result) = session.with_internal_mut(|slot| match slot.as_mut() {
            Some(auth) => commit(auth, outcome, session_id),
            None => (
                SessionLifecycle::None,
                AuthResult {
                    response: AuthResponse::AuthErr,
                },
            ),
        });
        session.set_roles(granted);
        if let Some(cred) = credential {
            session.set_credential(cred);
        }
        SetupOutcome::Commit(lifecycle, result)
    }

    /// `$/sessionSetupContinue` handler (valid only at `Init`, enforced by the core).
    fn on_continue(
        &self,
        args: ContinueArgs,
        session: &Session<AuthSession>,
    ) -> Result<(SessionLifecycle, AuthResult), JsonRpcError> {
        let session_id = session.id();
        type Committed = ((SessionLifecycle, AuthResult), RoleMask, Option<Credential>);
        let (committed, granted, credential) =
            session.with_internal_mut(|slot| -> Result<Committed, JsonRpcError> {
                let auth = slot.as_mut().ok_or_else(missing_state)?;
                // Take the carried in-progress state; anything else is out of sequence.
                let progress =
                    match std::mem::replace(&mut auth.state, AuthSessionState::Unauthenticated) {
                        AuthSessionState::InProgress(p) => p,
                        other => {
                            auth.state = other;
                            let reject = AuthResult {
                                response: AuthResponse::AuthErr,
                            };
                            return Ok(((SessionLifecycle::None, reject), RoleMask::NONE, None));
                        }
                    };
                // A continue must stay on the in-progress mechanism.
                let outcome = if mech_tag(&args.mechanism) == Some(progress.tag) {
                    self.dispatch(&args.mechanism, &auth.channel, Some(progress))
                } else {
                    Outcome::Reject(RejectKind::AuthErr)
                };
                let mech = mech_tag(&args.mechanism).unwrap_or("UNKNOWN");
                let (granted, uid) = self.authorize(&outcome, mech);
                let credential = credential_of(&outcome, mech, uid);
                Ok((commit(auth, outcome, session_id), granted, credential))
            })?;
        session.set_roles(granted);
        if let Some(cred) = credential {
            session.set_credential(cred);
        }
        Ok(committed)
    }
}

impl AuthStackBuilder {
    /// Set the AF_UNIX peer-cred default: a connection with no declared mechanism authenticates by
    /// its `SO_PEERCRED` credentials, mapping them to an identity. Return `None` from `f` to require
    /// an explicit mechanism. Authorization comes from the peer's **uid** via the
    /// [`role_source`](Self::role_source) (uid 0 ⇒ full admin), not from this closure.
    #[must_use]
    pub fn peercred(
        mut self,
        f: impl Fn(&Channel) -> Option<Identity> + Send + Sync + 'static,
    ) -> Self {
        self.peercred = Some(Box::new(f));
        self
    }

    /// Set the role registry — the canonical role taxonomy. The stack interns the role names a
    /// principal is granted into a [`RoleMask`] at `sessionSetup`. Use the **same** [`Roles`] you
    /// pass to the protocol builder's [`roles`](truenas_rpc::JsonRpcProtocolBuilder::roles) so
    /// the granted and required masks share one numbering.
    #[must_use]
    pub fn roles(mut self, roles: Roles) -> Self {
        self.registry = Some(roles);
        self
    }

    /// Set the username→uid resolver used for a [`Principal::User`] (SCRAM / mTLS): it maps an
    /// authenticated account name to the uid authorization keys off, or `None` to grant no roles.
    /// With the `nss` feature, [`resolve_users_via_nss`](Self::resolve_users_via_nss) wires
    /// `getpwnam` here.
    #[must_use]
    pub fn user_resolver(
        mut self,
        f: impl Fn(&str) -> Option<u32> + Send + Sync + 'static,
    ) -> Self {
        self.user_resolver = Some(Box::new(f));
        self
    }

    /// Set the `(uid, mechanism)`→roles source: it returns the role names granted to a uid that
    /// authenticated via the given mechanism (`"UNIX_SOCKET"` / `"SCRAM"` / `"CLIENT_CERTIFICATE"` /
    /// …) — assurance/channel-based authorization. **uid 0 is always full admin** regardless (an
    /// anti-lockout net), so the source is consulted only for non-root uids. With the `keyring`
    /// feature, [`roles_from_keyring`](Self::roles_from_keyring) wires the `server_roles` ring here.
    #[must_use]
    pub fn role_source(
        mut self,
        f: impl Fn(u32, &str) -> Vec<String> + Send + Sync + 'static,
    ) -> Self {
        self.role_source = Some(Box::new(f));
        self
    }

    /// Resolve a [`Principal::User`]'s uid via the system passwd database (`getpwnam`, through
    /// `nix::unistd::User`) — the built-in [`user_resolver`](Self::user_resolver) for accounts that
    /// live in NSS.
    #[cfg(feature = "nss")]
    #[must_use]
    pub fn resolve_users_via_nss(self) -> Self {
        self.user_resolver(|name| {
            nix::unistd::User::from_name(name)
                .ok()
                .flatten()
                .map(|u| u.uid.as_raw())
        })
    }

    /// Read a `(uid, mechanism)`'s roles from a keyring
    /// [`server_roles`](truenas_keyring::SERVER_ROLES) ring — the built-in
    /// [`role_source`](Self::role_source). Records are keyed `"<uid>_<mechanism>"` (e.g.
    /// `"0_UNIX_SOCKET"`, `"1000_SCRAM"`); a pair with no record (or an unreadable one) grants no
    /// roles.
    #[cfg(feature = "keyring")]
    #[must_use]
    pub fn roles_from_keyring(self, store: Arc<truenas_keyring::KeyringStore>) -> Self {
        self.role_source(move |uid, mechanism| {
            store
                .server_roles()
                .get_record::<truenas_keyring::RoleRecord>(&format!("{uid}_{mechanism}"))
                .ok()
                .flatten()
                .map(|r| r.roles)
                .unwrap_or_default()
        })
    }

    /// Enable a mechanism under its wire `tag` (the `"mechanism"` value clients send).
    #[must_use]
    pub fn mechanism(
        mut self,
        tag: impl Into<String>,
        mechanism: impl Mechanism + 'static,
    ) -> Self {
        self.mechanisms.insert(tag.into(), Box::new(mechanism));
        self
    }

    /// Freeze into a shared [`AuthStack`].
    pub fn build(self) -> Arc<AuthStack> {
        Arc::new(AuthStack {
            peercred: self.peercred,
            mechanisms: self.mechanisms,
            registry: self.registry,
            user_resolver: self.user_resolver,
            role_source: self.role_source,
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
            move |args: SetupArgs, session: &Arc<Session<AuthSession>>| {
                setup.on_setup(args, session)
            },
        )
        .session_setup_continue(
            MethodDef::new("$/sessionSetupContinue").secret_fields(["mechanism"]),
            move |args: ContinueArgs, session: &Session<AuthSession>| {
                cont.on_continue(args, session)
            },
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

/// Build the standardized [`Credential`] summary the `$/sessions` listing surfaces — present only
/// for an authenticated outcome. `mech` is the mechanism label (`"UNIX_SOCKET"` for the peer-cred
/// default, else the wire tag: `"SCRAM"`, `"CLIENT_CERTIFICATE"`, `"PASSTHROUGH"`, …); `uid` is the
/// account uid [`AuthStack::authorize`] already resolved (so the principal isn't resolved twice).
pub(crate) fn credential_of(outcome: &Outcome, mech: &str, uid: Option<u32>) -> Option<Credential> {
    let Outcome::Authenticated { principal, .. } = outcome else {
        return None;
    };
    let who = match principal {
        Principal::Uid(u) => format!(" uid={u}"),
        Principal::User(name) => format!(" user={name}"),
        Principal::None => String::new(),
    };
    Some(Credential {
        description: format!("{mech}{who}"),
        uid,
    })
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
        // The `principal` was resolved to the session's role mask + uid by the caller (`authorize`).
        Outcome::Authenticated {
            identity,
            principal: _,
            user_info,
            extra,
        } => {
            auth.state = AuthSessionState::Authenticated(identity);
            let response = AuthResponse::Success {
                session_id: session_id.to_string(),
                user_info,
                extra,
            };
            (SessionLifecycle::Established, AuthResult { response })
        }
        Outcome::Challenge { reply, next } => {
            auth.state = AuthSessionState::InProgress(next);
            (SessionLifecycle::Init, AuthResult { response: reply })
        }
        Outcome::Reject(kind) => {
            auth.state = AuthSessionState::Unauthenticated;
            (
                SessionLifecycle::None,
                AuthResult {
                    response: kind.into(),
                },
            )
        }
        // Passthrough is intercepted before `commit` (it becomes a takeover, not a sync commit);
        // this arm only keeps the match exhaustive.
        #[cfg(feature = "passthrough")]
        Outcome::Passthrough(_) => {
            auth.state = AuthSessionState::Unauthenticated;
            (
                SessionLifecycle::None,
                AuthResult {
                    response: AuthResponse::AuthErr,
                },
            )
        }
    }
}
