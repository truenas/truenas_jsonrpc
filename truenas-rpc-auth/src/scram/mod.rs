//! SCRAM-SHA-512-**PLUS** authentication (the `scram` feature), channel binding enforced.
//!
//! Two rounds over `$/sessionSetup` / `$/sessionSetupContinue`: client-first → server-first
//! (challenge), client-final → server-final (success). The mechanism payload carries the raw RFC
//! SCRAM string in a `"message"` field. Channel binding is **required**: the GS2 flag must be
//! `p=tls-server-end-point` and the client's `c=` must echo the server's binding value (so the
//! exchange is bound to this TLS channel); `n`/`y` are rejected. Verification recovers
//! `ClientKey = ClientProof XOR HMAC(StoredKey, AuthMessage)` and checks `H(ClientKey) == StoredKey`
//! constant-time, then returns the server-final `v=` for the client's mutual-auth check.

mod crypto;
mod message;

use std::any::Any;

use openssl::base64::{decode_block, encode_block};
use serde_json::{json, Value};

use crate::channel::{Capability, Channel};
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Identity, Outcome, Principal, RejectKind};
use crate::stack::AuthStackBuilder;

use self::crypto::KEY_LEN;
use self::message::{Cbind, ClientFirst};

pub use self::crypto::derive_verifier;

/// The wire tag clients use to select SCRAM (`{ "mechanism": "SCRAM", "message": "<rfc>" }`).
pub const SCRAM_TAG: &str = "SCRAM";

/// The stored verifier for one credential — no plaintext key, only the RFC-5802 server-side keys.
/// What [`CredentialSource`] hands the mechanism, and what (e.g.) a keyring-backed `ScramRecord`
/// decodes to.
#[derive(Clone)]
pub struct ScramCredentials {
    /// The PBKDF2 salt (raw bytes).
    pub salt: Vec<u8>,
    /// The PBKDF2 iteration count.
    pub iterations: u32,
    /// `StoredKey = H(ClientKey)` (raw, 64 bytes).
    pub stored_key: Vec<u8>,
    /// `ServerKey = HMAC(SaltedPassword, "Server Key")` (raw, 64 bytes).
    pub server_key: Vec<u8>,
    /// The identity to authenticate as on success (opaque to the mechanism).
    pub identity: Identity,
}

impl ScramCredentials {
    /// Mint a verifier from raw key material (PBKDF2-HMAC-SHA512 → StoredKey/ServerKey). Roles are
    /// not part of the verifier — authorization is resolved from the account's uid at `sessionSetup`.
    pub fn mint(
        key: &[u8],
        salt: Vec<u8>,
        iterations: u32,
        identity: Identity,
    ) -> ScramCredentials {
        let (stored_key, server_key) = derive_verifier(key, &salt, iterations);
        ScramCredentials {
            salt,
            iterations,
            stored_key: stored_key.into(),
            server_key: server_key.into(),
            identity,
        }
    }
}

/// The seam the SCRAM mechanism looks credentials up through (a username → verifier). Implemented
/// by a keyring-backed source, an in-memory map, an RPC to middleware, etc.
pub trait CredentialSource: Send + Sync {
    /// The stored verifier for `username`, or `None` if unknown.
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials>;
}

/// The SCRAM-SHA-512-PLUS mechanism over a [`CredentialSource`].
pub struct Scram<C> {
    source: C,
}

impl<C> Scram<C> {
    /// Build the mechanism over a credential source.
    pub fn new(source: C) -> Self {
        Self { source }
    }
}

/// In-progress server state carried from client-first to client-final.
struct ScramPending {
    server_first: String,
    combined_nonce_b64: String,
    client_first_bare: String,
    gs2_header: String,
    channel_binding: Vec<u8>,
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
    identity: Identity,
    username: String,
}

fn reject(kind: RejectKind) -> Outcome {
    Outcome::Reject(kind)
}

fn message_of(payload: &Value) -> Option<&str> {
    payload.get("message").and_then(Value::as_str)
}

impl<C: CredentialSource> Mechanism for Scram<C> {
    fn required(&self) -> &'static [Capability] {
        // SCRAM-PLUS binds to the TLS server cert, so it is only offered on an encrypted channel;
        // the channel-binding value itself is checked in `step`.
        &[Capability::Encrypted]
    }

    fn step(&self, payload: &Value, channel: &Channel, progress: Option<AuthProgress>) -> Outcome {
        match progress {
            None => self.client_first(payload, channel),
            Some(p) => self.client_final(payload, p),
        }
    }
}

impl<C: CredentialSource> Scram<C> {
    fn client_first(&self, payload: &Value, channel: &Channel) -> Outcome {
        let Some(msg) = message_of(payload) else {
            return reject(RejectKind::AuthErr);
        };
        let Some(cf) = message::parse_client_first(msg) else {
            return reject(RejectKind::AuthErr);
        };

        // Enforce SCRAM-PLUS: the client must request tls-server-end-point binding, and the channel
        // must actually carry a binding value (i.e. it's a TLS connection).
        if cf.cbind != Cbind::TlsServerEndPoint {
            return reject(RejectKind::AuthErr); // n / y — no-binding or downgrade
        }
        let Some(binding) = channel.channel_binding.clone() else {
            return reject(RejectKind::Denied); // SCRAM-PLUS requires a TLS channel binding
        };

        let username = message::unescape_username(&cf.username_raw);
        let Some(creds) = self.source.scram_credentials(&username) else {
            return reject(RejectKind::AuthErr); // unknown user
        };

        let server_nonce = crypto::random_nonce();
        let Some((server_first, combined_nonce_b64)) = message::server_first(
            &cf.client_nonce_b64,
            &server_nonce,
            &creds.salt,
            creds.iterations,
        ) else {
            return reject(RejectKind::AuthErr);
        };

        let ClientFirst {
            gs2_header, bare, ..
        } = cf;
        let pending = ScramPending {
            server_first: server_first.clone(),
            combined_nonce_b64,
            client_first_bare: bare,
            gs2_header,
            channel_binding: binding,
            stored_key: creds.stored_key,
            server_key: creds.server_key,
            identity: creds.identity,
            username,
        };
        Outcome::Challenge {
            reply: crate::wire::AuthResponse::Challenge {
                mechanism: SCRAM_TAG.to_string(),
                data: json!({ "message": server_first }),
            },
            next: AuthProgress::new(SCRAM_TAG, pending),
        }
    }

    fn client_final(&self, payload: &Value, progress: AuthProgress) -> Outcome {
        let pending = match progress.state.downcast::<ScramPending>() {
            Ok(p) => *p,
            Err(_) => return reject(RejectKind::AuthErr),
        };
        let Some(msg) = message_of(payload) else {
            return reject(RejectKind::AuthErr);
        };
        let Some(cf) = message::parse_client_final(msg) else {
            return reject(RejectKind::AuthErr);
        };

        // The echoed nonce must match (public values — plain compare).
        if cf.nonce_b64 != pending.combined_nonce_b64 {
            return reject(RejectKind::AuthErr);
        }
        // Channel binding: c= must decode to the gs2 header followed by the server's binding value.
        // A mismatch means a relay/MITM is sitting on a different TLS channel.
        let Ok(cbind) = decode_block(&cf.cbind_b64) else {
            return reject(RejectKind::AuthErr);
        };
        let mut expected = pending.gs2_header.into_bytes();
        expected.extend_from_slice(&pending.channel_binding);
        if cbind != expected {
            return reject(RejectKind::AuthErr);
        }

        let auth_message = message::auth_message(
            &pending.client_first_bare,
            &pending.server_first,
            &cf.without_proof,
        );

        // Recover ClientKey = ClientProof XOR HMAC(StoredKey, AuthMessage) and verify
        // H(ClientKey) == StoredKey, constant-time.
        let Ok(proof) = decode_block(&cf.proof_b64) else {
            return reject(RejectKind::AuthErr);
        };
        let Ok(proof): Result<[u8; KEY_LEN], _> = proof.try_into() else {
            return reject(RejectKind::AuthErr);
        };
        let client_sig = crypto::hmac_sha512(&pending.stored_key, auth_message.as_bytes());
        let recovered = crypto::xor(&proof, &client_sig);
        let mut stored = [0u8; KEY_LEN];
        if pending.stored_key.len() != KEY_LEN {
            return reject(RejectKind::AuthErr);
        }
        stored.copy_from_slice(&pending.stored_key);
        if !crypto::ct_eq(&crypto::sha512(&recovered), &stored) {
            return reject(RejectKind::AuthErr); // bad client proof
        }

        // Mutual auth: server-final v= = HMAC(ServerKey, AuthMessage).
        let server_sig = crypto::hmac_sha512(&pending.server_key, auth_message.as_bytes());
        let server_final = format!("v={}", encode_block(&server_sig));
        Outcome::Authenticated {
            identity: pending.identity,
            principal: Principal::User(pending.username),
            user_info: None,
            extra: Some(json!({ "scram": server_final })),
        }
    }
}

impl AuthStackBuilder {
    /// Enable SCRAM-SHA-512-PLUS under the [`SCRAM_TAG`] tag, looking credentials up via `source`.
    #[must_use]
    pub fn scram<C: CredentialSource + 'static>(self, source: C) -> Self {
        self.mechanism(SCRAM_TAG, Scram::new(source))
    }
}

// `ScramPending` must be `Send + Sync` to ride in `AuthProgress` (`Box<dyn Any + Send + Sync>`).
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync + Any>() {}
    assert_send_sync::<ScramPending>();
};
