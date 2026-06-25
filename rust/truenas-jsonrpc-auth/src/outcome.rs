//! The result a [`Mechanism`](crate::Mechanism) returns, plus the opaque carried state for a
//! multi-round mechanism.

use std::any::Any;

use crate::wire::AuthResponse;

/// An authenticated identity — opaque to the framework (the application decides its shape, as in
/// the Python layer where `server_state_internal` is untyped). Conventionally a JSON object such
/// as `{ "username": …, "uid": …, "api_key_id": … }`.
pub type Identity = serde_json::Value;

/// What a mechanism produced this round.
pub enum Outcome {
    /// Done — the connection is authenticated as `identity`. `user_info` (if any) is echoed to the
    /// client, and `extra` carries any mechanism-specific final payload (e.g. SCRAM's server-final
    /// `v=` for the client's mutual-auth check) in the `SUCCESS` reply.
    Authenticated {
        /// The server-internal identity stored on the session.
        identity: Identity,
        /// The role *names* this identity was granted. The auth stack converts them to a
        /// [`RoleMask`](truenas_jsonrpc::RoleMask) via its registry (`FULL_ADMIN` / hierarchy
        /// expanded) and stores it on the session for the per-call authorization gate.
        roles: Vec<String>,
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
    /// connection takeover ([`SetupOutcome::Takeover`](truenas_jsonrpc::SetupOutcome)) rather than a
    /// synchronous commit. Produced only by the passthrough mechanism.
    #[cfg(feature = "passthrough")]
    Passthrough(std::path::PathBuf),
}

impl Outcome {
    /// Authenticated as `identity` with the granted `roles` (role names) and no client-facing info
    /// or mechanism extras.
    pub fn authenticated_with_roles(identity: Identity, roles: Vec<String>) -> Outcome {
        Outcome::Authenticated { identity, roles, user_info: None, extra: None }
    }

    /// Authenticated as `identity` with **no** granted roles (only methods that require no role are
    /// callable) — the common single-shot case where the mechanism grants no roles.
    pub fn authenticated(identity: Identity) -> Outcome {
        Outcome::authenticated_with_roles(identity, Vec::new())
    }
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
        Self { tag, state: Box::new(state) }
    }
}
