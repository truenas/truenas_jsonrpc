//! [`ScramRecord`] — the SCRAM verifier stored per credential (fields modeled on TrueNAS's
//! `UserApiKey`).

use serde::{Deserialize, Serialize};

/// A SCRAM-SHA-512 verifier record — no plaintext key, only the salt, iteration count, and the
/// RFC-5802 server-side keys. Stored as the JSON payload of a `user` key in `server_keys`, keyed
/// by username. Fields mirror TrueNAS's `UserApiKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScramRecord {
    /// The account this verifier authenticates.
    pub username: String,
    /// The digest (always `"SHA512"` today).
    pub algorithm: String,
    /// The PBKDF2 iteration count.
    pub iterations: u32,
    /// The PBKDF2 salt, base64 (standard, padded).
    pub salt: String,
    /// `StoredKey = H(ClientKey)`, base64.
    pub stored_key: String,
    /// `ServerKey = HMAC(SaltedPassword, "Server Key")`, base64.
    pub server_key: String,
    /// Expiry: `-1` revoked, `0` never, `> 0` a Unix timestamp after which it is invalid.
    pub expiry: i64,
    /// The role names this credential grants. Converted to the session's
    /// [`RoleMask`](truenas_jsonrpc::RoleMask) at `sessionSetup`; absent in older records (an
    /// empty grant — only no-role methods are callable).
    #[serde(default)]
    pub roles: Vec<String>,
}

impl ScramRecord {
    /// Whether this record is revoked (`expiry < 0`).
    pub fn is_revoked(&self) -> bool {
        self.expiry < 0
    }

    /// The `keyctl` TTL (seconds from `now_unix`) this record's `expiry` implies, or `None` for a
    /// never-expiring (or already-revoked) record. Clamped to 0 if already past.
    pub fn ttl_secs(&self, now_unix: i64) -> Option<u32> {
        if self.expiry > 0 {
            Some((self.expiry - now_unix).max(0) as u32)
        } else {
            None
        }
    }
}
