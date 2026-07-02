//! The result a [`Mechanism`](crate::Mechanism) returns, plus the opaque carried state for a
//! multi-round mechanism.

use std::any::Any;

use serde::{Deserialize, Serialize};

use crate::wire::AuthResponse;

/// An authenticated identity — opaque to the framework (the application decides its shape).
/// Conventionally a JSON object such as `{ "username": …, "uid": …, "api_key_id": … }`.
pub type Identity = serde_json::Value;

/// What a mechanism produced this round.
pub enum Outcome {
    /// Done — the connection is authenticated as `identity`. `user_info` (if any) is echoed to the
    /// client, and `extra` carries any mechanism-specific final payload (e.g. SCRAM's server-final
    /// `v=` for the client's mutual-auth check) in the `SUCCESS` reply.
    Authenticated {
        /// The server-internal identity stored on the session.
        identity: Identity,
        /// Who was authenticated, as the auth stack resolves authorization: a uid (AF_UNIX
        /// peer-cred), an account name (SCRAM / mTLS — resolved to a uid via the configured
        /// username→uid resolver), or [`Principal::None`]. The stack maps it to a uid, looks the
        /// uid's roles up in `server_roles` keyed on `(uid, mechanism)`, interns them via its
        /// [`Roles`](truenas_rpc::Roles) registry, and stores the [`RoleMask`](truenas_rpc::RoleMask)
        /// on the session for the per-call gate.
        principal: Principal,
        /// Optional client-facing info attached to the success reply.
        user_info: Option<serde_json::Value>,
        /// Optional mechanism-specific data attached to the success reply.
        extra: Option<serde_json::Value>,
    },
    /// Another round is needed: send `reply` to the client (the session moves to `Init`) and carry
    /// `next` until `$/sessionSetupContinue`. This is every "not done yet" case, including a second
    /// factor: a primary mechanism prompts for an OTP by returning a `Challenge` whose `reply` is
    /// [`AuthResponse::OtpRequired`](crate::AuthResponse::OtpRequired) and whose `next` is tagged
    /// for the OTP mechanism — so the continue routes *there* (not back to the primary), and the
    /// primary is still free to send its own final message (e.g. a SCRAM server-final) in `reply`.
    Challenge {
        /// The challenge to send the client.
        reply: AuthResponse,
        /// The mechanism's in-progress state, threaded to the round that handles `reply`'s answer
        /// (its [`tag`](AuthProgress::tag) selects which mechanism that is).
        next: AuthProgress,
    },
    /// Authentication failed.
    Reject(RejectKind),
    /// Take over the connection: hand the client fd to the passthrough broker at this AF_UNIX path,
    /// which conducts the handshake and returns the verdict. The auth stack turns this into a
    /// connection takeover ([`SetupOutcome::Takeover`](truenas_rpc::SetupOutcome)) rather than a
    /// synchronous commit. Produced only by the passthrough mechanism.
    #[cfg(feature = "passthrough")]
    Passthrough(std::path::PathBuf),
}

impl Outcome {
    /// Authenticated as `identity`, authorized as `principal` (the uid/account the stack resolves
    /// roles from), with no client-facing info or mechanism extras.
    pub fn authenticated(identity: Identity, principal: Principal) -> Outcome {
        Outcome::Authenticated {
            identity,
            principal,
            user_info: None,
            extra: None,
        }
    }
}

/// Who was authenticated, for the auth stack to resolve authorization from. Authorization keys off
/// the **uid**: an AF_UNIX peer arrives as a [`Uid`](Principal::Uid) directly, a SCRAM/mTLS account
/// as a [`User`](Principal::User) name the stack resolves to a uid (via the configured
/// username→uid resolver, e.g. `getpwnam`). [`None`](Principal::None) grants no roles.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Principal {
    /// A Unix user id — roles come from `server_roles` keyed on `(uid, mechanism)` (uid 0 ⇒ full admin).
    Uid(u32),
    /// An account name — resolved to a uid (then `server_roles[(uid, mechanism)]`) by the resolver.
    User(String),
    /// No authorization principal: the session is authenticated but granted no roles.
    #[default]
    None,
}

/// Why authentication was refused — maps onto the `AUTH_ERR` / `DENIED` / `EXPIRED` wire responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectKind {
    /// Generic failure (bad credential, unsupported mechanism, protocol error).
    AuthErr,
    /// The channel doesn't meet the mechanism's requirements (e.g. mTLS with no client cert).
    Denied,
    /// The credential is expired/revoked.
    Expired,
}

/// A mechanism's in-progress state, carried across the `$/sessionSetupContinue` round. The state
/// itself is opaque (`Box<dyn Any>`) so the core needn't enumerate every mechanism's type; the
/// `tag` records which mechanism owns it, so a continue can't switch mechanisms and the owner can
/// downcast its own state.
pub struct AuthProgress {
    /// The wire tag of the mechanism that owns this state (e.g. `"SCRAM"`).
    pub tag: &'static str,
    /// The mechanism-specific carried state, downcast by its owner on the next round.
    pub state: Box<dyn Any + Send + Sync>,
}

impl AuthProgress {
    /// Carry `state` for the mechanism identified by `tag`.
    pub fn new(tag: &'static str, state: impl Any + Send + Sync) -> Self {
        Self {
            tag,
            state: Box::new(state),
        }
    }
}
