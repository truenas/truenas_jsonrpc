//! Client-side session authentication: a **mechanism-agnostic driver** over `$/sessionSetup` /
//! `$/sessionSetupContinue`, plus a [`Mechanism`] seam each auth method plugs into (SCRAM under the
//! `scram` feature; more mechanisms follow). The driver sends the mechanism's first message, answers
//! each server `CHALLENGE`, and on `SUCCESS` lets the mechanism verify the server's final payload
//! (mutual auth). The auth **wire types are mirrored here** (deserialize-only) rather than depending
//! on `truenas-rpc-auth`, which pulls the server crate.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::engine::{Authenticates, Client};
use crate::error::ClientError;

/// The result of an authentication attempt: the session is established, or the server refused (a
/// one-time second factor may be required first). A **client-side** mechanism failure (a bad server
/// signature, a malformed challenge) is a [`ClientError::Auth`] instead.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// Authenticated; the connection's session is established.
    Established {
        /// The server-generated session id.
        session_id: String,
        /// Optional client-facing identity info.
        user_info: Option<Value>,
    },
    /// The primary factor succeeded; a one-time second factor is required for `username`.
    OtpRequired {
        /// The account to prompt the second factor for.
        username: String,
    },
    /// Refused: the channel doesn't meet the mechanism's requirements.
    Denied,
    /// Refused: a generic authentication failure.
    AuthErr,
    /// Refused: the credential is expired/revoked.
    Expired,
}

/// A client auth mechanism plugged into [`Client::authenticate_with`]. `first` produces the initial
/// `$/sessionSetup` mechanism object; `respond` answers each server challenge (for
/// `$/sessionSetupContinue`); `verify` checks the server's final payload on success (mutual auth).
pub trait Mechanism {
    /// The initial mechanism object (e.g. `{"mechanism":"SCRAM","message":"<client-first>"}`).
    fn first(&mut self) -> Result<Value, ClientError>;
    /// Answer a server `CHALLENGE` (`data` is its body) with the next mechanism object.
    fn respond(&mut self, data: &Value) -> Result<Value, ClientError>;
    /// Verify the server's `SUCCESS` `extra` payload (mutual auth). Default: accept.
    fn verify(&mut self, _extra: Option<&Value>) -> Result<(), ClientError> {
        Ok(())
    }
}

// --- the auth wire (a permissive, deserialize-only mirror of `truenas-rpc-auth`'s) ----------------

#[derive(Deserialize)]
struct AuthResult {
    response: AuthResponse,
}

#[derive(Deserialize)]
#[serde(tag = "response_type")]
enum AuthResponse {
    #[serde(rename = "SUCCESS")]
    Success {
        session_id: String,
        #[serde(default)]
        user_info: Option<Value>,
        #[serde(default)]
        extra: Option<Value>,
    },
    #[serde(rename = "CHALLENGE")]
    Challenge {
        #[serde(flatten)]
        data: Value,
    },
    #[serde(rename = "OTP_REQUIRED")]
    OtpRequired { username: String },
    #[serde(rename = "DENIED")]
    Denied,
    #[serde(rename = "AUTH_ERR")]
    AuthErr,
    #[serde(rename = "EXPIRED")]
    Expired,
}

/// One parsed setup/continue step: the driver either finishes (established or refused) or must answer
/// a challenge.
enum Step {
    Established {
        session_id: String,
        user_info: Option<Value>,
        extra: Option<Value>,
    },
    Challenge(Value),
    Refused(AuthOutcome),
}

fn interpret(result: &[u8]) -> Result<Step, ClientError> {
    let parsed: AuthResult = serde_json::from_slice(result)
        .map_err(|e| ClientError::Decode(format!("$/sessionSetup result: {e}")))?;
    Ok(match parsed.response {
        AuthResponse::Success {
            session_id,
            user_info,
            extra,
        } => Step::Established {
            session_id,
            user_info,
            extra,
        },
        AuthResponse::Challenge { data } => Step::Challenge(data),
        AuthResponse::OtpRequired { username } => {
            Step::Refused(AuthOutcome::OtpRequired { username })
        }
        AuthResponse::Denied => Step::Refused(AuthOutcome::Denied),
        AuthResponse::AuthErr => Step::Refused(AuthOutcome::AuthErr),
        AuthResponse::Expired => Step::Refused(AuthOutcome::Expired),
    })
}

/// Interpret a **single-shot** setup/continue result (no challenge is expected).
fn single(result: &[u8]) -> Result<AuthOutcome, ClientError> {
    match interpret(result)? {
        Step::Established {
            session_id,
            user_info,
            ..
        } => Ok(AuthOutcome::Established {
            session_id,
            user_info,
        }),
        Step::Refused(outcome) => Ok(outcome),
        Step::Challenge(_) => Err(ClientError::Auth(
            "unexpected challenge for a single-shot mechanism".into(),
        )),
    }
}

impl<P: Authenticates> Client<P> {
    /// Drive `mechanism` to completion over `$/sessionSetup` (+ `$/sessionSetupContinue`): send its
    /// first message, answer each `CHALLENGE`, and on `SUCCESS` verify the server's final payload
    /// (mutual auth). Returns the [`AuthOutcome`]; a client-side mechanism failure is a
    /// [`ClientError::Auth`].
    pub async fn authenticate_with(
        &self,
        mut mechanism: impl Mechanism,
    ) -> Result<AuthOutcome, ClientError> {
        let first = mechanism.first()?;
        let params = to_raw(&json!({ "mechanism": first }))?;
        let mut result = self.authenticate(Some(&*params)).await?;
        loop {
            match interpret(&result)? {
                Step::Established {
                    session_id,
                    user_info,
                    extra,
                } => {
                    mechanism.verify(extra.as_ref())?;
                    return Ok(AuthOutcome::Established {
                        session_id,
                        user_info,
                    });
                }
                Step::Challenge(data) => {
                    let next = mechanism.respond(&data)?;
                    let params = to_raw(&json!({ "mechanism": next }))?;
                    result = self.authenticate_continue(Some(&*params)).await?;
                }
                Step::Refused(outcome) => return Ok(outcome),
            }
        }
    }

    /// AF_UNIX **peer-cred**: an empty `$/sessionSetup` (no mechanism); the server authenticates from
    /// the connecting process's uid. Single-shot.
    pub async fn authenticate_peercred(&self) -> Result<AuthOutcome, ClientError> {
        let params = to_raw(&json!({}))?;
        single(&self.authenticate(Some(&*params)).await?)
    }

    /// **mTLS**: use the client certificate presented in the TLS handshake as the identity.
    pub async fn authenticate_mtls(&self) -> Result<AuthOutcome, ClientError> {
        self.authenticate_with(Single(json!({ "mechanism": "CLIENT_CERTIFICATE" })))
            .await
    }

    /// **OAuth/OIDC**: present a validated ID token (a JWT); the server verifies it offline.
    pub async fn authenticate_oauth(&self, id_token: &str) -> Result<AuthOutcome, ClientError> {
        self.authenticate_with(Single(json!({ "mechanism": "OAUTH", "token": id_token })))
            .await
    }

    /// A single-use **bearer token** minted by an external SPNEGO edge.
    pub async fn authenticate_bearer(&self, token: &str) -> Result<AuthOutcome, ClientError> {
        self.authenticate_with(Single(
            json!({ "mechanism": "GSSAPI_BEARER_TOKEN", "token": token }),
        ))
        .await
    }

    /// Continue with a one-time **second factor** after a primary factor returned
    /// [`AuthOutcome::OtpRequired`] (a `$/sessionSetupContinue`).
    pub async fn authenticate_otp(&self, otp_token: &str) -> Result<AuthOutcome, ClientError> {
        let params =
            to_raw(&json!({ "mechanism": { "mechanism": "OTP_TOKEN", "otp_token": otp_token } }))?;
        single(&self.authenticate_continue(Some(&*params)).await?)
    }
}

/// A single-shot mechanism: send `obj` once; a server challenge is a protocol error.
struct Single(Value);
impl Mechanism for Single {
    fn first(&mut self) -> Result<Value, ClientError> {
        Ok(self.0.clone())
    }
    fn respond(&mut self, _data: &Value) -> Result<Value, ClientError> {
        Err(ClientError::Auth(
            "this mechanism does not support a challenge".into(),
        ))
    }
}

/// Serialize a control-path params value to a `RawValue` (the shape `authenticate` takes).
fn to_raw(v: &Value) -> Result<Box<serde_json::value::RawValue>, ClientError> {
    serde_json::value::to_raw_value(v).map_err(|e| ClientError::Auth(e.to_string()))
}
