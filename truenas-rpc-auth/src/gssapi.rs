//! The native GSSAPI/Kerberos `GSSAPI` [`Mechanism`] (the `gssapi` feature): an in-process,
//! multi-round token exchange for native/CLI/service clients that already hold a Kerberos ticket
//! (`kinit` / a keytab). Structurally identical to SCRAM — each round feeds the client's base64
//! token to `gss_accept_sec_context`; while the context needs more rounds it returns a `Challenge`
//! carrying the server's reply token, and on completion it resolves the initiator's principal to an
//! account. (Browsers don't use this — they present a `GSSAPI_BEARER_TOKEN` minted by an external
//! SPNEGO edge; see [`crate::bearer`].)
//!
//! The acceptor uses the host keytab (`KRB5_KTNAME` / the default). The half-built [`ServerCtx`] is
//! `Send` but not `Sync`, so it rides across rounds inside a [`Mutex`] (which is `Send + Sync` over a
//! `Send` value) — no `unsafe` in this crate. Gated on [`Capability::Encrypted`]; no second factor
//! (the KDC enforces MFA via preauth/PKINIT/FAST).

use std::sync::Mutex;

use openssl::base64::{decode_block, encode_block};
use serde_json::{json, Value};
use truenas_gssapi::ServerCtx;

use crate::channel::{Capability, Channel};
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Identity, Outcome, Principal, RejectKind};
use crate::stack::AuthStackBuilder;

/// The wire tag clients use (`{ "mechanism": "GSSAPI", "token": "<base64 GSS token>" }`).
pub const GSSAPI_TAG: &str = "GSSAPI";

/// Maps a completed Kerberos principal (`user@REALM`) to a session [`Identity`] + the authorization
/// [`Principal`]. Return `None` to reject (e.g. a service principal). The
/// [default](default_principal_map) strips the realm and refuses service principals.
type PrincipalMap = Box<dyn Fn(&str) -> Option<(Identity, Principal)> + Send + Sync>;

/// The native GSSAPI mechanism: a host-keytab acceptor with a principal→account mapping.
pub struct Gssapi {
    principal_map: PrincipalMap,
    bind_channel: bool,
}

impl Default for Gssapi {
    fn default() -> Self {
        Self::new()
    }
}

impl Gssapi {
    /// A GSSAPI acceptor over the host keytab, mapping principals with [`default_principal_map`]
    /// (strip the realm, reject service principals) and **not** enforcing channel binding.
    pub fn new() -> Self {
        Self { principal_map: Box::new(default_principal_map), bind_channel: false }
    }

    /// Override the principal→`(identity, authorization principal)` mapping (e.g. for cross-realm or
    /// enterprise-name handling). Return `None` to reject a principal.
    #[must_use]
    pub fn principal_map(
        mut self,
        f: impl Fn(&str) -> Option<(Identity, Principal)> + Send + Sync + 'static,
    ) -> Self {
        self.principal_map = Box::new(f);
        self
    }

    /// Enforce GSS channel binding to the connection's `tls-server-end-point` value (defeats token
    /// relay across TLS channels). Off by default — the client must bind to the same value, so only
    /// enable it when clients cooperate.
    #[must_use]
    pub fn bind_channel(mut self, enabled: bool) -> Self {
        self.bind_channel = enabled;
        self
    }
}

/// The half-built acceptor context carried across `$/sessionSetupContinue` rounds. Wrapped in a
/// [`Mutex`] only to satisfy `AuthProgress`'s `Send + Sync` (the context is `Send`, not `Sync`); it
/// is never actually contended (one connection's setup is serialized).
struct GssPending {
    ctx: Mutex<ServerCtx>,
}

impl Mechanism for Gssapi {
    fn required(&self) -> &'static [Capability] {
        &[Capability::Encrypted]
    }

    fn step(&self, payload: &Value, channel: &Channel, progress: Option<AuthProgress>) -> Outcome {
        let Some(token_b64) = payload.get("token").and_then(Value::as_str) else {
            return Outcome::Reject(RejectKind::AuthErr);
        };
        let Ok(token) = decode_block(token_b64) else {
            return Outcome::Reject(RejectKind::AuthErr);
        };

        // Round 1 creates a fresh acceptor over the host keytab; later rounds recover the carried
        // context (taking it back out of its Mutex).
        let mut ctx = match progress {
            None => ServerCtx::new(),
            Some(p) => {
                let Ok(pending) = p.state.downcast::<GssPending>() else {
                    return Outcome::Reject(RejectKind::AuthErr);
                };
                match pending.ctx.into_inner() {
                    Ok(ctx) => ctx,
                    Err(_) => return Outcome::Reject(RejectKind::AuthErr), // poisoned
                }
            }
        };

        let binding = if self.bind_channel { channel.channel_binding.as_deref() } else { None };
        let out = match ctx.step(&token, binding) {
            Ok(out) => out,
            Err(_) => return Outcome::Reject(RejectKind::AuthErr), // bad/forged/expired token
        };

        if ctx.is_complete() {
            let name = match ctx.source_name() {
                Ok(name) => name,
                Err(_) => return Outcome::Reject(RejectKind::AuthErr),
            };
            let Some((identity, principal)) = (self.principal_map)(&name) else {
                return Outcome::Reject(RejectKind::AuthErr); // mapped to no account
            };
            // A final (non-empty) token is the mutual-auth reply the client verifies.
            let extra = (!out.is_empty()).then(|| json!({ "token": encode_block(&out) }));
            Outcome::Authenticated { identity, principal, user_info: None, extra }
        } else {
            // Another round: hand the server's output token back as the challenge (empty → "").
            Outcome::Challenge {
                reply: crate::wire::AuthResponse::Challenge {
                    mechanism: GSSAPI_TAG.to_string(),
                    data: json!({ "token": encode_block(&out) }),
                },
                next: AuthProgress::new(GSSAPI_TAG, GssPending { ctx: Mutex::new(ctx) }),
            }
        }
    }
}

/// The default principal→account mapping: reject a **service** principal (one containing `/`, e.g.
/// `host/...`, `nfs/...`), else strip the realm (`alice@REALM` → `alice`) and authorize as that user
/// (resolved to a uid by the stack's username→uid resolver, then roles via `(uid, "GSSAPI")`).
pub fn default_principal_map(principal: &str) -> Option<(Identity, Principal)> {
    if principal.contains('/') {
        return None;
    }
    let user = principal.split('@').next().unwrap_or(principal);
    if user.is_empty() {
        return None;
    }
    Some((json!({ "username": user, "principal": principal }), Principal::User(user.to_string())))
}

impl AuthStackBuilder {
    /// Enable the [`GSSAPI_TAG`] mechanism with a default host-keytab acceptor.
    #[must_use]
    pub fn gssapi(self) -> Self {
        self.mechanism(GSSAPI_TAG, Gssapi::new())
    }

    /// Enable the [`GSSAPI_TAG`] mechanism with a configured [`Gssapi`] (custom principal mapping /
    /// channel binding).
    #[must_use]
    pub fn gssapi_with(self, mechanism: Gssapi) -> Self {
        self.mechanism(GSSAPI_TAG, mechanism)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_map_strips_realm() {
        let (identity, principal) = default_principal_map("alice@EXAMPLE.COM").unwrap();
        assert_eq!(principal, Principal::User("alice".into()));
        assert_eq!(identity["username"], "alice");
        assert_eq!(identity["principal"], "alice@EXAMPLE.COM");
    }

    #[test]
    fn default_map_rejects_service_principals_and_empties() {
        assert!(default_principal_map("host/server.example.com@EXAMPLE.COM").is_none());
        assert!(default_principal_map("nfs/server@EXAMPLE.COM").is_none());
        assert!(default_principal_map("@EXAMPLE.COM").is_none());
    }

    #[test]
    fn default_map_passes_a_bare_name() {
        let (_id, principal) = default_principal_map("bob").unwrap();
        assert_eq!(principal, Principal::User("bob".into()));
    }
}
