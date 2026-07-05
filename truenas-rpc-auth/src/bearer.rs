//! The `GSSAPI_BEARER_TOKEN` [`Mechanism`]: a single-use bearer token, minted **outside** this app
//! (by an HTTP SPNEGO edge that performed the Kerberos accept) and inserted into the keyring this
//! server reads, presented by the browser at `$/sessionSetup`. The server only does a keyring
//! lookup + single-use consume — no krb5 runs in-process. The token authenticates the principal the
//! edge bound to it; authorization then resolves `(uid, "GSSAPI_BEARER_TOKEN")` → roles like every
//! other mechanism.
//!
//! Single-shot, gated on [`Capability::Encrypted`] (the token is a bearer secret, so it may only
//! cross a confidential channel). **Replay-safe by construction:** a valid token is consumed
//! (removed) on first use, so a second presentation of the same token fails.

use serde_json::Value;

use crate::channel::{Capability, Channel};
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Identity, Outcome, Principal, RejectKind};
use crate::stack::AuthStackBuilder;

/// The wire tag clients use (`{ "mechanism": "GSSAPI_BEARER_TOKEN", "token": "<opaque>" }`).
pub const GSSAPI_BEARER_TOKEN_TAG: &str = "GSSAPI_BEARER_TOKEN";

/// The credential a validated, consumed token resolves to.
pub struct BearerCredential {
    /// The server-internal identity stored on the session (e.g. `{ "username": "alice" }`).
    pub identity: Identity,
    /// The authorization principal — typically [`Principal::User`] of the realm-stripped Kerberos
    /// principal the edge authenticated, which the stack resolves to a uid (then roles).
    pub principal: Principal,
}

/// The verdict of consuming a presented token.
pub enum BearerVerdict {
    /// Valid and now consumed (single-use): authenticate as this credential.
    Valid(BearerCredential),
    /// The token existed but is past its expiry / revoked.
    Expired,
    /// No such token — unknown, or already consumed (a replay).
    Unknown,
}

/// The seam the bearer-token mechanism validates through: look the presented token up and, if
/// valid, **consume it** so a replay fails. Implemented by `KeyringBearerTokens` (the keyring the
/// external minter writes into) — or by an embedder's own store (in-memory, an RPC to middleware).
pub trait BearerTokenSource: Send + Sync {
    /// Validate and CONSUME the token (single-use). Implementations MUST remove a valid token
    /// **before** returning [`BearerVerdict::Valid`], so the same token can't authenticate twice.
    fn consume(&self, token: &str) -> BearerVerdict;
}

/// The `GSSAPI_BEARER_TOKEN` mechanism over a [`BearerTokenSource`].
pub struct GssapiBearerToken<S> {
    source: S,
}

impl<S> GssapiBearerToken<S> {
    /// Build the mechanism over a token source.
    pub fn new(source: S) -> Self {
        Self { source }
    }
}

impl<S: BearerTokenSource> Mechanism for GssapiBearerToken<S> {
    fn required(&self) -> &'static [Capability] {
        // The token is a bearer secret — only over a confidential channel.
        &[Capability::Encrypted]
    }

    fn step(
        &self,
        payload: &Value,
        _channel: &Channel,
        _progress: Option<AuthProgress>,
    ) -> Outcome {
        let Some(token) = payload.get("token").and_then(Value::as_str) else {
            return Outcome::Reject(RejectKind::AuthErr);
        };
        match self.source.consume(token) {
            BearerVerdict::Valid(cred) => Outcome::Authenticated {
                identity: cred.identity,
                principal: cred.principal,
                user_info: None,
                extra: None,
            },
            BearerVerdict::Expired => Outcome::Reject(RejectKind::Expired),
            BearerVerdict::Unknown => Outcome::Reject(RejectKind::AuthErr),
        }
    }
}

impl AuthStackBuilder {
    /// Enable the [`GSSAPI_BEARER_TOKEN_TAG`] mechanism: validate a single-use bearer token (minted
    /// by an external SPNEGO edge and inserted into the keyring) via `source`.
    #[must_use]
    pub fn gssapi_bearer_token(self, source: impl BearerTokenSource + 'static) -> Self {
        self.mechanism(GSSAPI_BEARER_TOKEN_TAG, GssapiBearerToken::new(source))
    }
}

// --- the keyring-backed source (the `keyring` feature): the ring the external minter writes ------

/// A bearer-token record the external SPNEGO edge writes into the keyring, keyed by the **hex
/// SHA-256 of the token** (so the raw token is never a key name). Binds the token to the principal
/// the edge authenticated, with an expiry.
#[cfg(feature = "keyring")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BearerTokenRecord {
    /// The authenticated account (realm-stripped Kerberos principal); resolved to a uid via the
    /// stack's username→uid resolver, then to roles via `(uid, "GSSAPI_BEARER_TOKEN")`.
    pub username: String,
    /// Expiry: `-1` revoked, `0` never, `> 0` a Unix timestamp after which the token is invalid.
    #[serde(default)]
    pub expiry: i64,
}

/// A [`BearerTokenSource`] backed by a kernel-keyring sub-keyring the external minter writes. Tokens
/// are looked up by `hex(SHA-256(token))` and **removed on use** (single-use); the raw token is
/// never stored, only its hash is a key name.
#[cfg(feature = "keyring")]
pub struct KeyringBearerTokens {
    ring: truenas_rpc_utils_unsafe::keyring::KeyRing,
}

#[cfg(feature = "keyring")]
impl KeyringBearerTokens {
    /// Validate/consume tokens against `ring` — the sub-keyring the edge inserts [`BearerTokenRecord`]s
    /// into (e.g. a config-extra ring from [`KeyringStore`](truenas_rpc_utils_unsafe::keyring::KeyringStore)).
    pub fn new(ring: truenas_rpc_utils_unsafe::keyring::KeyRing) -> Self {
        Self { ring }
    }
}

#[cfg(feature = "keyring")]
impl BearerTokenSource for KeyringBearerTokens {
    fn consume(&self, token: &str) -> BearerVerdict {
        let key = token_key(token);
        let record: BearerTokenRecord = match self.ring.get_record(&key) {
            Ok(Some(r)) => r,
            _ => return BearerVerdict::Unknown, // absent / unreadable
        };
        if record.expiry < 0 || is_expired(record.expiry) {
            let _ = self.ring.remove_record(&key); // best-effort cleanup of a dead token
            return BearerVerdict::Expired;
        }
        // Single-use: the remove is the serialization point. Only the caller whose remove returns
        // `true` may authenticate; a concurrent replay loses the race and gets `false` → Unknown.
        match self.ring.remove_record(&key) {
            Ok(true) => BearerVerdict::Valid(BearerCredential {
                identity: serde_json::json!({ "username": record.username }),
                principal: Principal::User(record.username),
            }),
            _ => BearerVerdict::Unknown,
        }
    }
}

/// `hex(SHA-256(token))` — the keyring key name for a token (so the raw secret is never a name).
#[cfg(feature = "keyring")]
fn token_key(token: &str) -> String {
    use std::fmt::Write;
    let digest = openssl::sha::sha256(token.as_bytes());
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Whether a `> 0` expiry timestamp is already in the past (`<= 0` is never/revoked-handled-elsewhere).
#[cfg(feature = "keyring")]
fn is_expired(expiry: i64) -> bool {
    if expiry <= 0 {
        return false;
    }
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(now) => now.as_secs() as i64 >= expiry,
        Err(_) => false,
    }
}
