//! A kernel-keyring-backed [`CredentialSource`] (the `keyring` feature).
//!
//! Looks SCRAM verifiers up in a sub-keyring of [`ScramRecord`]s — the `server_keys` ring written
//! by `truenas-keyring` or Python `truenas_keyring` (`store.server_keys()`). Each lookup reads the
//! `user` key named for the username, honours revocation/expiry, and decodes the record's base64
//! verifier fields into the [`ScramCredentials`] the mechanism verifies against. No plaintext key
//! is ever stored or read — only the salt, iteration count, and the RFC-5802 server-side keys.
//!
//! **Possession requirement.** The `$/sessionSetup` handler runs on a `spawn_blocking` worker, so
//! the lookup (`keyctl(KEYCTL_SEARCH)`) can land on any thread of the process. The backing keyring
//! must therefore be possessed *process-wide* — the **persistent** (the production default, uid 0),
//! **session**, or **user** keyring. A **thread** keyring is possessed only by the thread that
//! created it and will appear empty to the worker — don't back this source with one.

use std::time::{SystemTime, UNIX_EPOCH};

use openssl::base64::decode_block;
use serde_json::{json, Value};
use truenas_keyring::{KeyRing, ScramRecord};

use crate::scram::{CredentialSource, ScramCredentials};

/// The default record → identity mapping: `{ "username": <name> }`.
fn default_identity(record: &ScramRecord) -> Value {
    json!({ "username": record.username })
}

/// A [`CredentialSource`] that reads SCRAM verifiers from a kernel-keyring sub-keyring.
///
/// Construct over the ring holding the verifiers — typically
/// [`KeyringStore::server_keys`](truenas_keyring::KeyringStore::server_keys):
///
/// ```no_run
/// use truenas_rpc_auth::{AuthStack, KeyringCredentials};
/// use truenas_keyring::{KeyringConfig, KeyringStore};
///
/// let store = KeyringStore::open(&KeyringConfig::from_json(
///     r#"{ "keyring_type": "persistent", "keyring_identifier": 0 }"#,
/// )?)?;
/// let stack = AuthStack::builder().scram(KeyringCredentials::new(store.server_keys())).build();
/// # Ok::<(), truenas_keyring::Error>(())
/// ```
pub struct KeyringCredentials<F = fn(&ScramRecord) -> Value> {
    ring: KeyRing,
    identity: F,
}

impl KeyringCredentials {
    /// Look credentials up in `ring`, mapping each record to the default identity
    /// `{ "username": <name> }`.
    pub fn new(ring: KeyRing) -> Self {
        Self {
            ring,
            identity: default_identity,
        }
    }
}

impl<F: Fn(&ScramRecord) -> Value> KeyringCredentials<F> {
    /// Look credentials up in `ring`, mapping each record to an identity via `identity` (e.g. to
    /// attach the account's roles / db id from the record's username).
    pub fn with_identity(ring: KeyRing, identity: F) -> Self {
        Self { ring, identity }
    }
}

impl<F: Fn(&ScramRecord) -> Value + Send + Sync> CredentialSource for KeyringCredentials<F> {
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        let record: ScramRecord = self.ring.get_record(username).ok()??;

        // Defence in depth: the kernel TTL already drops wall-clock-expired keys, but the auth
        // decision re-checks both the logical revocation flag and the hard expiry here.
        if record.is_revoked() || is_expired(&record) {
            return None;
        }

        Some(ScramCredentials {
            salt: decode_block(&record.salt).ok()?,
            iterations: record.iterations,
            stored_key: decode_block(&record.stored_key).ok()?,
            server_key: decode_block(&record.server_key).ok()?,
            identity: (self.identity)(&record),
        })
    }
}

/// Whether `record` has a hard expiry that is already in the past. A record with no readable
/// clock is treated as *not* expired (the kernel TTL remains the primary guard).
fn is_expired(record: &ScramRecord) -> bool {
    if record.expiry <= 0 {
        return false; // 0 = never, < 0 = revoked (handled separately)
    }
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_secs() as i64 >= record.expiry,
        Err(_) => false,
    }
}
