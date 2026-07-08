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
use std::sync::Arc;

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

/// A source of the server's `tls-server-end-point` channel-binding value for connections where TLS
/// was terminated *upstream* (a reverse proxy), so the server has none of its own. SCRAM consults it
/// **only** on a channel where
/// [`binding_terminated_upstream`](crate::Channel::binding_terminated_upstream) holds — a
/// reverse-proxied AF_UNIX socket, including proxied `wss://` — never on server-terminated TLS or a
/// trusted-local socket. A keyring-backed implementation is `KeyringChannelBinding` (the `keyring`
/// feature).
pub trait ChannelBindingSource: Send + Sync {
    /// The active server certificate's `tls-server-end-point` value (RFC 5929), or `None` if
    /// unavailable.
    fn tls_server_end_point(&self) -> Option<Vec<u8>>;
}

/// The SCRAM-SHA-512 mechanism over a [`CredentialSource`] — **PLUS (channel-bound) by default**,
/// optionally with a [`ChannelBindingSource`] for reverse-proxied transports, and with an opt-in
/// **unbound** mode ([`allow_unbound`](Self::allow_unbound)) for clients that can't read the TLS
/// binding (e.g. browsers).
pub struct Scram<C> {
    source: C,
    binding: Option<Arc<dyn ChannelBindingSource>>,
    allow_unbound: bool,
}

impl<C> Scram<C> {
    /// Build the mechanism over a credential source. The channel binding is taken from the
    /// connection's own TLS; on a reverse-proxied transport (no server-side TLS) it is absent — use
    /// [`with_binding`](Self::with_binding) to supply it out of band.
    pub fn new(source: C) -> Self {
        Self {
            source,
            binding: None,
            allow_unbound: false,
        }
    }

    /// Build the mechanism with a `binding` source consulted when TLS was terminated upstream (a
    /// reverse-proxied AF_UNIX socket / proxied `wss://`); see [`ChannelBindingSource`].
    pub fn with_binding<B: ChannelBindingSource + 'static>(source: C, binding: B) -> Self {
        Self {
            source,
            binding: Some(Arc::new(binding)),
            allow_unbound: false,
        }
    }

    /// Also accept **unbound** SCRAM — a client `gs2-cbind-flag` of `n` (no channel binding), for
    /// clients that cannot read the TLS `tls-server-end-point` value (a browser over `wss://`). Off by
    /// default; the `y` downgrade flag is **always** rejected. Prefer channel-bound `-PLUS` wherever
    /// the client can supply the binding — unbound relies on TLS server authentication alone.
    #[must_use]
    pub fn allow_unbound(mut self) -> Self {
        self.allow_unbound = true;
        self
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

        // Channel-binding policy: SCRAM-PLUS (`p=tls-server-end-point`) binds to the TLS cert; unbound
        // SCRAM (`n`) is accepted only when explicitly enabled (a browser client that can't read the
        // binding). `y` is ALWAYS rejected — a `-PLUS`-capable server treats it as a downgrade attack.
        let binding = match cf.cbind {
            Cbind::TlsServerEndPoint => {
                // The server's own TLS if it terminated it, else — on a reverse-proxied transport where
                // TLS was terminated upstream — the out-of-band source (e.g. the keyring).
                let binding = channel.channel_binding.clone().or_else(|| {
                    if channel.binding_terminated_upstream() {
                        self.binding.as_ref().and_then(|b| b.tls_server_end_point())
                    } else {
                        None
                    }
                });
                match binding {
                    Some(b) => b,
                    None => return reject(RejectKind::Denied), // -PLUS requires a channel binding
                }
            }
            // Unbound: the cbind-input is just the gs2 header (no binding bytes appended).
            Cbind::NotUsed if self.allow_unbound => Vec::new(),
            _ => return reject(RejectKind::AuthErr), // unbound not allowed, or `y` downgrade
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
    /// The channel binding comes from the connection's own TLS; use
    /// [`scram_bound`](Self::scram_bound) for a reverse-proxied service where TLS is terminated
    /// upstream.
    #[must_use]
    pub fn scram<C: CredentialSource + 'static>(self, source: C) -> Self {
        self.mechanism(SCRAM_TAG, Scram::new(source))
    }

    /// Enable SCRAM-SHA-512-PLUS with an out-of-band [`ChannelBindingSource`] (e.g. a keyring-backed
    /// `KeyringChannelBinding`), consulted on reverse-proxied transports (proxied AF_UNIX / `wss://`)
    /// where TLS was terminated upstream and the active cert's `tls-server-end-point` is published
    /// out of band.
    #[must_use]
    pub fn scram_bound<C, B>(self, source: C, binding: B) -> Self
    where
        C: CredentialSource + 'static,
        B: ChannelBindingSource + 'static,
    {
        self.mechanism(SCRAM_TAG, Scram::with_binding(source, binding))
    }

    /// Enable SCRAM-SHA-512 under the [`SCRAM_TAG`] tag, **also accepting unbound** (`n,,`) clients —
    /// e.g. a browser over `wss://` that can't read the TLS channel binding. Channel-bound `-PLUS`
    /// clients still work and stay bound; the `y` downgrade flag is always rejected. Opt-in: the plain
    /// [`scram`](Self::scram) builder stays `-PLUS`-only (unbound relies on TLS server auth alone).
    #[must_use]
    pub fn scram_unbound<C: CredentialSource + 'static>(self, source: C) -> Self {
        self.mechanism(SCRAM_TAG, Scram::new(source).allow_unbound())
    }
}

// `ScramPending` must be `Send + Sync` to ride in `AuthProgress` (`Box<dyn Any + Send + Sync>`).
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync + Any>() {}
    assert_send_sync::<ScramPending>();
};
