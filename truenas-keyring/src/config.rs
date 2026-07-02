//! [`KeyringConfig`] — the JSON-declared keyring to open, plus its validation.

use std::collections::HashSet;

use serde::Deserialize;

use crate::error::Error;
use crate::keyring::{CLIENT_KEYS, SERVER_KEYS, SERVER_ROLES};

/// Which kernel keyring is the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyringType {
    /// A user's persistent keyring (`KEYCTL_GET_PERSISTENT`) — survives logout, needs an
    /// identifier (the uid). The intended production choice (`identifier = 0` for root).
    Persistent,
    /// The caller's session keyring.
    Session,
    /// The caller's per-uid user keyring.
    User,
    /// The caller's per-uid user-session keyring.
    UserSession,
    /// The caller's process keyring.
    Process,
    /// The caller's thread keyring.
    Thread,
}

/// The keyring configuration, deserialized from JSON and [`validate`](Self::validate)d. Unknown
/// fields are rejected.
///
/// ```json
/// { "keyring_type": "persistent", "keyring_identifier": 0, "subkeyrings": ["extra"] }
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringConfig {
    /// Which kernel keyring is the root.
    pub keyring_type: KeyringType,
    /// The uid whose persistent keyring to use — **required** for [`KeyringType::Persistent`],
    /// rejected for the others.
    #[serde(default)]
    pub keyring_identifier: Option<u32>,
    /// Additional sub-keyrings to ensure exist, on top of the always-present `server_keys` /
    /// `client_keys` built-ins.
    #[serde(default)]
    pub subkeyrings: Vec<String>,
}

impl KeyringConfig {
    /// Parse and validate from a JSON string. A schema/structure problem or a semantic one (e.g.
    /// `persistent` with no `keyring_identifier`) is an [`Error::Config`].
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let config: KeyringConfig =
            serde_json::from_str(json).map_err(|e| Error::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Semantic validation (deserialization already enforced the structure / field types).
    pub fn validate(&self) -> Result<(), Error> {
        match self.keyring_type {
            KeyringType::Persistent if self.keyring_identifier.is_none() => {
                return Err(Error::Config(
                    "keyring_type \"persistent\" requires keyring_identifier (the uid)".into(),
                ));
            }
            KeyringType::Persistent => {}
            _ if self.keyring_identifier.is_some() => {
                return Err(Error::Config(format!(
                    "keyring_identifier is only valid with keyring_type \"persistent\", not {:?}",
                    self.keyring_type
                )));
            }
            _ => {}
        }

        let mut seen = HashSet::new();
        for name in &self.subkeyrings {
            if name.is_empty() {
                return Err(Error::Config("a subkeyring name is empty".into()));
            }
            if name.contains('\0') {
                return Err(Error::Config(format!(
                    "subkeyring name {name:?} contains a NUL byte"
                )));
            }
            if name == SERVER_KEYS || name == CLIENT_KEYS || name == SERVER_ROLES {
                return Err(Error::Config(format!(
                    "subkeyring {name:?} duplicates a built-in (server_keys / client_keys / server_roles are always present)"
                )));
            }
            if !seen.insert(name.as_str()) {
                return Err(Error::Config(format!("duplicate subkeyring name {name:?}")));
            }
        }
        Ok(())
    }
}
