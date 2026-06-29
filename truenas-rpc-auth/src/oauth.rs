//! The OAuth/OIDC `OAUTH` [`Mechanism`] (the `oauth` feature): validate a presented OIDC **ID
//! token** *offline*. The browser does the interactive authorization-code+PKCE dance with the IdP
//! out-of-band, then presents the resulting ID token over the WebSocket at `$/sessionSetup`; this
//! server is a pure OIDC **resource server** — it verifies the JWT's signature against the IdP's
//! published keys and checks the standard claims. No HTTP client lives here: the JWKS is supplied
//! by a [`JwksProvider`] the embedder fetches/caches however it likes (a background refresh, an RPC
//! to middleware), mirroring how SCRAM takes a `CredentialSource`.
//!
//! Verification is over the **system OpenSSL** the crate already links for SCRAM — no separate JWT /
//! crypto crate. Anti-spoofing is the **signature** (forging a token needs the IdP's private key);
//! cross-app substitution is stopped by the `aud` check; the algorithm is **pinned** (an unexpected
//! `alg` — including `none` or an RS↔HS confusion — is refused *before* verification). Single-shot,
//! gated on [`Capability::Encrypted`]. Revocation freshness is bounded by the token's TTL (offline
//! validation can't see an IdP-side revocation), so pair it with short-lived tokens.

use std::time::{SystemTime, UNIX_EPOCH};

use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::sha::{sha256, sha384};
use openssl::sign::Verifier;
use serde_json::Value;

use crate::channel::{Capability, Channel};
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Outcome, Principal, RejectKind};
use crate::stack::AuthStackBuilder;

/// The wire tag clients use (`{ "mechanism": "OAUTH", "token": "<id-token JWT>" }`).
pub const OAUTH_TAG: &str = "OAUTH";

/// Clock-skew leeway (seconds) for the `exp`/`nbf` checks — matches jsonwebtoken's default.
const LEEWAY: i64 = 60;

/// A JWS signature algorithm we accept (asymmetric only — never `HS*`, to avoid the
/// public-key-as-HMAC-secret confusion attack; `none` is rejected because it doesn't parse here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 + SHA-256/384/512.
    RS256,
    /// RSASSA-PKCS1-v1_5 + SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 + SHA-512.
    RS512,
    /// ECDSA P-256 + SHA-256.
    ES256,
    /// ECDSA P-384 + SHA-384.
    ES384,
    /// EdDSA (Ed25519).
    EdDSA,
}

impl Algorithm {
    /// Parse a JWS `alg` header value, or `None` for an unsupported / disallowed algorithm (`none`,
    /// `HS*`, …) — which the caller turns into a rejection.
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "RS256" => Self::RS256,
            "RS384" => Self::RS384,
            "RS512" => Self::RS512,
            "ES256" => Self::ES256,
            "ES384" => Self::ES384,
            "EdDSA" => Self::EdDSA,
            _ => return None,
        })
    }
}

/// Supplies the IdP's signing keys (its JWKS), selected by the token's `kid`. The embedder owns how
/// the JWKS is fetched + cached (this crate pulls no HTTP client); a production provider refreshes
/// it in the background and returns the public key per `kid`. An IdP JWK converts to a `PKey` via
/// `openssl` (RSA `{n,e}` → `Rsa::from_public_components`; EC `{x,y}` →
/// `EcKey::from_public_key_affine_coordinates`; OKP `x` → `PKey::public_key_from_raw_bytes`).
pub trait JwksProvider: Send + Sync {
    /// The public verifying key for the token's `kid` (a JWKS may rotate / hold several keys), or
    /// `None` if no key matches (→ the token is refused).
    fn verifying_key(&self, kid: Option<&str>) -> Option<PKey<Public>>;
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

    /// Pin the allowed signature algorithms (asymmetric only — never `HS*`).
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
        match self.verify(payload) {
            Some((claims, username)) => Outcome::Authenticated {
                identity: claims,
                principal: Principal::User(username),
                user_info: None,
                extra: None,
            },
            None => Outcome::Reject(RejectKind::AuthErr),
        }
    }
}

impl<P: JwksProvider> Oauth<P> {
    /// Verify a presented JWT and return `(claims, username)` on success, or `None` on any failure
    /// (malformed / bad alg / no key / bad signature / iss / aud / expiry / missing account claim).
    fn verify(&self, payload: &Value) -> Option<(Value, String)> {
        let token = payload.get("token").and_then(Value::as_str)?;

        // A compact JWT is exactly three base64url segments.
        let parts: Vec<&str> = token.splitn(4, '.').collect();
        let [header_b64, payload_b64, sig_b64] = parts[..] else {
            return None;
        };
        // The signing input is the original `header.payload` ASCII (not re-encoded).
        let signing_input = &token.as_bytes()[..header_b64.len() + 1 + payload_b64.len()];

        // Header → pin the algorithm BEFORE verifying (an unexpected `alg` — `none`/`HS*` — never
        // parses or isn't in the allowlist, so it's refused with no verification).
        let header: Value = serde_json::from_slice(&b64url_decode(header_b64)?).ok()?;
        let alg = Algorithm::parse(header.get("alg").and_then(Value::as_str)?)?;
        if !self.config.algorithms.contains(&alg) {
            return None;
        }
        let kid = header.get("kid").and_then(Value::as_str);
        let key = self.provider.verifying_key(kid)?;

        // Signature.
        let sig = b64url_decode(sig_b64)?;
        if !verify_signature(alg, &key, signing_input, &sig) {
            return None;
        }

        // Claims.
        let claims: Value = serde_json::from_slice(&b64url_decode(payload_b64)?).ok()?;
        let now = unix_now();
        // `exp` required + not past (with leeway).
        let exp = claims.get("exp").and_then(Value::as_i64)?;
        if now >= exp + LEEWAY {
            return None;
        }
        // `nbf` optional — only checked when present.
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) {
            if now + LEEWAY < nbf {
                return None;
            }
        }
        // `iss` must match.
        if claims.get("iss").and_then(Value::as_str) != Some(self.config.issuer.as_str()) {
            return None;
        }
        // `aud` (a string or an array per RFC 7519) must contain our audience.
        if !aud_contains(claims.get("aud"), &self.config.audience) {
            return None;
        }

        let username = claims.get(&self.config.username_claim).and_then(Value::as_str)?.to_string();
        Some((claims, username))
    }
}

/// Verify `sig` over `signing_input` with `key` under `alg`, entirely via OpenSSL. Returns `false`
/// on any error or mismatch.
fn verify_signature(alg: Algorithm, key: &PKey<Public>, signing_input: &[u8], sig: &[u8]) -> bool {
    match alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let md = match alg {
                Algorithm::RS256 => MessageDigest::sha256(),
                Algorithm::RS384 => MessageDigest::sha384(),
                _ => MessageDigest::sha512(),
            };
            // RSASSA-PKCS1-v1_5 is OpenSSL's default RSA padding — exactly JWS `RS*`.
            let Ok(mut v) = Verifier::new(md, key) else { return false };
            v.update(signing_input).is_ok() && v.verify(sig).unwrap_or(false)
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            // JWS ECDSA signatures are the raw fixed-width `r || s`, not ASN.1 DER — rebuild the
            // EcdsaSig from the two halves and verify against the message hash.
            let (hash, half) = match alg {
                Algorithm::ES256 => (sha256(signing_input).to_vec(), 32),
                _ => (sha384(signing_input).to_vec(), 48),
            };
            if sig.len() != half * 2 {
                return false;
            }
            let Ok(ec_key) = key.ec_key() else { return false };
            let (Ok(r), Ok(s)) = (BigNum::from_slice(&sig[..half]), BigNum::from_slice(&sig[half..]))
            else {
                return false;
            };
            let Ok(ecdsa) = EcdsaSig::from_private_components(r, s) else { return false };
            ecdsa.verify(&hash, &ec_key).unwrap_or(false)
        }
        Algorithm::EdDSA => {
            // PureEdDSA: no pre-hash, no streaming — the one-shot verify.
            let Ok(mut v) = Verifier::new_without_digest(key) else { return false };
            v.verify_oneshot(sig, signing_input).unwrap_or(false)
        }
    }
}

/// Whether the `aud` claim (a JSON string or array of strings, per RFC 7519) contains `expected`.
fn aud_contains(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Strict base64url (unpadded) decode — rejects any character outside the URL-safe alphabet and any
/// non-zero trailing bits. JWT segments are base64url with no padding.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in s.as_bytes() {
        acc = (acc << 6) | u32::from(sextet(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // A valid unpadded tail leaves 0/2/4 leftover bits, all zero; 6 leftover bits (a lone trailing
    // char) or any non-zero leftover is malformed.
    if bits >= 6 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

impl AuthStackBuilder {
    /// Enable the [`OAUTH_TAG`] mechanism: validate a presented OIDC ID token offline against
    /// `config` using keys from `provider`.
    #[must_use]
    pub fn oauth(self, config: OauthConfig, provider: impl JwksProvider + 'static) -> Self {
        self.mechanism(OAUTH_TAG, Oauth::new(config, provider))
    }
}
