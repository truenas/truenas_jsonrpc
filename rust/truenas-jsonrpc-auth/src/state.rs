//! [`AuthSession`] — the per-connection server-internal state (`S`) the auth layer owns.

use truenas_jsonrpc_server::Peer;

use crate::channel::Channel;
use crate::outcome::{AuthProgress, Identity};

/// The protocol/server's per-connection state when the auth layer is installed. It carries the
/// immutable [`Channel`] (what the transport offers) and the evolving auth [`AuthSessionState`].
///
/// Seed it on the server with `.state_from_peer(AuthSession::from_peer)`; the setup handlers
/// advance `state` in place across rounds (via the session's `with_internal_mut`), and downstream
/// method handlers read [`identity`](Self::identity).
pub struct AuthSession {
    /// Immutable channel context (transport, peer-cred, TLS cert/binding).
    pub channel: Channel,
    /// The evolving authentication state.
    pub state: AuthSessionState,
}

/// Where a connection is in authentication.
pub enum AuthSessionState {
    /// No mechanism has succeeded yet.
    Unauthenticated,
    /// A multi-round mechanism is mid-exchange (carrying its opaque state).
    InProgress(AuthProgress),
    /// Authenticated as this identity.
    Authenticated(Identity),
}

impl AuthSession {
    /// Build the per-connection state from the connected [`Peer`] — the `state_from_peer` hook.
    /// Always `Some` (an unauthenticated session over whatever channel the peer arrived on).
    pub fn from_peer(peer: &Peer) -> Option<Self> {
        Some(Self { channel: Channel::from_peer(peer), state: AuthSessionState::Unauthenticated })
    }

    /// The authenticated identity, or `None` if not yet `Established`.
    pub fn identity(&self) -> Option<&Identity> {
        match &self.state {
            AuthSessionState::Authenticated(id) => Some(id),
            _ => None,
        }
    }

    /// Whether the connection has completed authentication.
    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, AuthSessionState::Authenticated(_))
    }
}
