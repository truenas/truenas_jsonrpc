//! [`render_auth_session`] — a ready-made [`SessionInfo`](truenas_rpc::SessionInfo) renderer for
//! [`AuthSession`]. Install it with `JsonRpcProtocolBuilder::session_info(render_auth_session)` so the
//! FULL_ADMIN `$/sessions` listing also surfaces the authenticated identity. The core base entry
//! already carries `session_id` / age / `created_at` / lifecycle / `origin` / `secure_transport` /
//! `internal` / `credential` / `current`; the [`SessionInfo`] seam *augments* it, so this renderer
//! returns only the auth-specific extras (`authenticated` + the full `identity`) for the core to
//! merge on top. Sibling to the audit identity renderer.

use serde_json::{json, Map, Value};
use truenas_rpc::Session;

use crate::state::AuthSession;

/// Render the auth-specific **extras** for one [`AuthSession`] in the `$/sessions` listing: whether
/// the connection is `authenticated` and, once it is, the full `identity` value. Returned as a JSON
/// object the core merges onto its base entry — origin / credential / age / … are the core's job now.
pub fn render_auth_session(session: &Session<AuthSession>) -> Value {
    let mut extra = Map::new();
    session.with_internal(|st| {
        if let Some(auth) = st {
            extra.insert("authenticated".to_string(), json!(auth.is_authenticated()));
            if let Some(identity) = auth.identity() {
                extra.insert("identity".to_string(), identity.clone());
            }
        }
    });
    Value::Object(extra)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use truenas_rpc::{JsonRpcProtocol, NullOutbound};
    use truenas_rpc_server::{Peer, Ucred};

    use super::*;
    use crate::channel::Channel;
    use crate::state::AuthSessionState;

    #[test]
    fn renders_only_authenticated_extras() {
        let proto = JsonRpcProtocol::<AuthSession>::builder("api", "1").build();
        let peer = Peer::unix(Some(Ucred { pid: 1, uid: 1000, gid: 1000 }));

        // Unauthenticated: just the `authenticated` flag, no identity. The core base entry owns
        // session_id / origin / age / … now — the renderer no longer emits them.
        let s = proto.new_session(AuthSession::from_peer(&peer), Arc::new(NullOutbound));
        let v = render_auth_session(&s);
        assert_eq!(v["authenticated"], false);
        assert!(v.get("identity").is_none());
        assert!(v.get("session_id").is_none());
        assert!(v.get("origin").is_none());

        // Authenticated: the identity is surfaced.
        let auth = AuthSession {
            channel: Channel::from_peer(&peer),
            state: AuthSessionState::Authenticated(json!({"username": "alice", "uid": 1000})),
        };
        let s2 = proto.new_session(Some(auth), Arc::new(NullOutbound));
        let v = render_auth_session(&s2);
        assert_eq!(v["authenticated"], true);
        assert_eq!(v["identity"]["username"], "alice");
    }
}
