//! The OAuth/OIDC `OAUTH` [`Mechanism`] (the `oauth` feature): validate a presented OIDC **ID
//! token** *offline*. The browser does the interactive authorization-code+PKCE dance with the IdP
//! out-of-band, then presents the resulting ID token over the WebSocket at `$/sessionSetup`; this
//! server is a pure OIDC **resource server** — it verifies the JWT's signature against the IdP's
//! published keys and checks the standard claims. No HTTP client lives here: the JWKS is supplied
//! by a [`JwksProvider`] the embedder fetches/caches however it likes (a background refresh, an RPC
//! to middleware), mirroring how SCRAM takes a `CredentialSource`.
//!
//! Anti-spoofing is the **signature** (forging a token needs the IdP's private key); cross-app
//! substitution is stopped by the `aud` check; the algorithm is **pinned** (an unexpected `alg` —
//! including `none` or an RS↔HS confusion — is refused *before* verification). Single-shot, gated on
//! [`Capability::Encrypted`]. Revocation freshness is bounded by the token's TTL (offline validation
//! can't see an IdP-side revocation), so pair it with short-lived tokens.

use jsonwebtoken::{decode, decode_header, Validation};
use serde_json::Value;

use crate::channel::{Capability, Channel};
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Outcome, Principal, RejectKind};
use crate::stack::AuthStackBuilder;

pub use jsonwebtoken::{Algorithm, DecodingKey};

/// The wire tag clients use (`{ "mechanism": "OAUTH", "token": "<id-token JWT>" }`).
pub const OAUTH_TAG: &str = "OAUTH";

/// Supplies the IdP's signing keys (its JWKS), selected by the token's `kid`. The embedder owns how
/// the JWKS is fetched + cached (this crate pulls no HTTP client); a production provider refreshes
/// it in the background and returns a [`DecodingKey`] per `kid`.
pub trait JwksProvider: Send + Sync {
    /// The decoding key for the token's `kid` (a JWKS may rotate / hold several keys), or `None` if
    /// no key matches (→ the token is refused).
    fn decoding_key(&self, kid: Option<&str>) -> Option<DecodingKey>;
}

/// What an OIDC provider's tokens must satisfy to authenticate: the expected `iss`/`aud`, the
/// allowed signature algorithms (**pinned** — asymmetric only), and which claim names the account.
pub struct OauthConfig {
    issuer: String,
    audience: String,
    algorithms: Vec<Algorithm>,
    username_claim: String,
}

impl OauthConfig {
    /// A config for `issuer` (the expected `iss`) and `audience` (our client_id — the expected
    /// `aud`), defaulting to the asymmetric algorithms `RS256`/`ES256`/`EdDSA` and the
    /// `preferred_username` claim for the account name.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: vec![Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA],
            username_claim: "preferred_username".into(),
        }
    }

    /// Pin the allowed signature algorithms (asymmetric only — never `HS*`, to avoid the
    /// public-key-as-HMAC-secret confusion attack).
    #[must_use]
    pub fn algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Set the claim whose value names the account (resolved to a uid by the stack's username→uid
    /// resolver, then to roles via `(uid, "OAUTH")`). Defaults to `preferred_username`.
    #[must_use]
    pub fn username_claim(mut self, claim: impl Into<String>) -> Self {
        self.username_claim = claim.into();
        self
    }
}

/// The OAuth/OIDC mechanism over a [`JwksProvider`] and an [`OauthConfig`].
pub struct Oauth<P> {
    config: OauthConfig,
    provider: P,
}

impl<P> Oauth<P> {
    /// Build the mechanism from the provider config + the JWKS source.
    pub fn new(config: OauthConfig, provider: P) -> Self {
        Self { config, provider }
    }
}

impl<P: JwksProvider> Mechanism for Oauth<P> {
    fn required(&self) -> &'static [Capability] {
        // The token is a bearer credential — only over a confidential channel.
        &[Capability::Encrypted]
    }

    fn step(&self, payload: &Value, _channel: &Channel, _progress: Option<AuthProgress>) -> Outcome {
        let Some(token) = payload.get("token").and_then(Value::as_str) else {
            return Outcome::Reject(RejectKind::AuthErr);
        };
        // Read the unverified header to select the key and **pin the algorithm** before verifying —
        // an `alg` we didn't expect (`none`, or RS↔HS confusion) is refused with no verification.
        let Ok(header) = decode_header(token) else {
            return Outcome::Reject(RejectKind::AuthErr);
        };
        if !self.config.algorithms.contains(&header.alg) {
            return Outcome::Reject(RejectKind::AuthErr);
        }
        let Some(key) = self.provider.decoding_key(header.kid.as_deref()) else {
            return Outcome::Reject(RejectKind::AuthErr);
        };

        // `header.alg` already passed the policy allowlist above, so verify with exactly that
        // algorithm. (A multi-family `algorithms` list trips jsonwebtoken's key-family check; the
        // explicit pre-check is what enforces the allowlist / defeats the `none`/HS-confusion attack.)
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        // `exp` is required + validated by default; `nbf` (rare on ID tokens) is checked only when
        // present (jsonwebtoken's default), so a token without one isn't spuriously rejected.

        let Ok(data) = decode::<Value>(token, &key, &validation) else {
            return Outcome::Reject(RejectKind::AuthErr); // bad signature / iss / aud / expiry
        };
        let claims = data.claims;
        let username = match claims.get(&self.config.username_claim).and_then(Value::as_str) {
            Some(u) => u.to_string(),
            None => return Outcome::Reject(RejectKind::AuthErr), // no account claim
        };
        Outcome::Authenticated {
            identity: claims,
            principal: Principal::User(username),
            user_info: None,
            extra: None,
        }
    }
}

impl AuthStackBuilder {
    /// Enable the [`OAUTH_TAG`] mechanism: validate a presented OIDC ID token offline against
    /// `config` using keys from `provider`.
    #[must_use]
    pub fn oauth(self, config: OauthConfig, provider: impl JwksProvider + 'static) -> Self {
        self.mechanism(OAUTH_TAG, Oauth::new(config, provider))
    }
}
