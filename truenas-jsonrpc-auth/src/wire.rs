//! The greenfield `$/sessionSetup` / `$/sessionSetupContinue` wire schema.
//!
//! A setup/continue request carries a `mechanism` object whose own `"mechanism"` tag selects the
//! [`Mechanism`](crate::Mechanism); the rest of the object is that mechanism's payload (kept as a
//! `serde_json::Value` so each mechanism owns its shape). Every reply is an [`AuthResult`] wrapping
//! a tagged [`AuthResponse`]. This is intentionally *not* a copy of the Python message structs.

use serde::{Deserialize, Serialize};

use crate::outcome::RejectKind;

/// `$/sessionSetup` params. `mechanism` is `None` to request the channel default (AF_UNIX
/// peer-cred); otherwise it is the chosen mechanism's request object (a `"mechanism"`-tagged map).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SetupArgs {
    /// The chosen login mechanism's request object, or `None` for the channel default.
    #[serde(default)]
    pub mechanism: Option<serde_json::Value>,
}

/// `$/sessionSetupContinue` params — the next message of a multi-round mechanism. Its `"mechanism"`
/// tag must match the in-progress mechanism.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContinueArgs {
    /// The continuing mechanism's request object (a `"mechanism"`-tagged map).
    pub mechanism: serde_json::Value,
}

/// The reply to a setup/continue call.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthResult {
    /// The tagged response.
    pub response: AuthResponse,
}

/// A setup/continue response, discriminated by `response_type`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "response_type")]
pub enum AuthResponse {
    /// Authentication completed; the session is `Established`.
    #[serde(rename = "SUCCESS")]
    Success {
        /// The established session's id (the connection's server-generated UUID), returned so the
        /// client has a handle to its authenticated session.
        session_id: String,
        /// Optional client-facing identity info.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_info: Option<serde_json::Value>,
        /// Optional mechanism-specific final payload (e.g. SCRAM's `{ "scram": "v=…" }`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extra: Option<serde_json::Value>,
    },
    /// A mechanism challenge; the client answers with `$/sessionSetupContinue`. `data` is the
    /// mechanism-specific challenge body (flattened alongside `mechanism`).
    #[serde(rename = "CHALLENGE")]
    Challenge {
        /// The mechanism this challenge belongs to (its wire tag).
        mechanism: String,
        /// The mechanism-specific challenge body.
        #[serde(flatten)]
        data: serde_json::Value,
    },
    /// The primary factor succeeded; a one-time second factor is required next.
    #[serde(rename = "OTP_REQUIRED")]
    OtpRequired {
        /// The username to prompt the second factor for.
        username: String,
    },
    /// Refused: the channel doesn't meet the mechanism's requirements.
    #[serde(rename = "DENIED")]
    Denied,
    /// Refused: a generic authentication failure.
    #[serde(rename = "AUTH_ERR")]
    AuthErr,
    /// Refused: the credential is expired/revoked.
    #[serde(rename = "EXPIRED")]
    Expired,
}

impl From<RejectKind> for AuthResponse {
    fn from(k: RejectKind) -> Self {
        match k {
            RejectKind::AuthErr => AuthResponse::AuthErr,
            RejectKind::Denied => AuthResponse::Denied,
            RejectKind::Expired => AuthResponse::Expired,
        }
    }
}
