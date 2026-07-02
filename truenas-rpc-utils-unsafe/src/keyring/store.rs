//! [`KeyringStore`] — the config-opened root keyring with its built-in + extra sub-keyrings,
//! built on the low-level [`KeyRing`] primitives. The high-level analogue of the C
//! `truenas_api_key` package (but config-driven rather than the fixed PAM hierarchy).

use std::collections::HashMap;

use super::config::{KeyringConfig, KeyringType};
use super::error::Error;
use super::key::{Found, KeyRing, KeyType, SpecialKeyring};

/// The always-present sub-keyring for **inbound** SCRAM verifiers (authenticating clients to us).
pub const SERVER_KEYS: &str = "server_keys";
/// The always-present sub-keyring for **outbound** peer credentials (us → remote servers).
pub const CLIENT_KEYS: &str = "client_keys";
/// The always-present sub-keyring mapping a **uid → granted roles** (`RoleRecord`, keyed by the
/// uid). The auth stack resolves a principal to a uid (an AF_UNIX peer's `SO_PEERCRED`, or a SCRAM
/// username via `getpwnam`) and reads its roles here.
pub const SERVER_ROLES: &str = "server_roles";

/// A config-opened keyring: the resolved root [`KeyRing`] plus a handle to each sub-keyring (the
/// `server_keys` / `client_keys` built-ins plus any config extras).
pub struct KeyringStore {
    root: KeyRing,
    subkeyrings: HashMap<String, KeyRing>,
}

impl KeyringStore {
    /// Open the keyring described by `config`: resolve the root, then ensure each sub-keyring
    /// exists (creating any that don't). Idempotent — reopening reuses existing sub-keyrings.
    pub fn open(config: &KeyringConfig) -> Result<Self, Error> {
        config.validate()?;
        let root = resolve_root(config)?;
        let mut subkeyrings = HashMap::new();
        let names = [SERVER_KEYS, CLIENT_KEYS, SERVER_ROLES]
            .into_iter()
            .chain(config.subkeyrings.iter().map(String::as_str));
        for name in names {
            if subkeyrings.contains_key(name) {
                continue;
            }
            subkeyrings.insert(name.to_string(), ensure_subkeyring(&root, name)?);
        }
        Ok(Self { root, subkeyrings })
    }

    /// The built-in `server_keys` sub-keyring (inbound SCRAM verifiers).
    pub fn server_keys(&self) -> KeyRing {
        *self
            .subkeyrings
            .get(SERVER_KEYS)
            .expect("server_keys is a built-in sub-keyring")
    }

    /// The built-in `client_keys` sub-keyring (outbound peer credentials).
    pub fn client_keys(&self) -> KeyRing {
        *self
            .subkeyrings
            .get(CLIENT_KEYS)
            .expect("client_keys is a built-in sub-keyring")
    }

    /// The built-in `server_roles` sub-keyring (uid → granted roles).
    pub fn server_roles(&self) -> KeyRing {
        *self
            .subkeyrings
            .get(SERVER_ROLES)
            .expect("server_roles is a built-in sub-keyring")
    }

    /// A sub-keyring by name (a built-in or a config extra), or `None` if not configured.
    pub fn subkeyring(&self, name: &str) -> Option<KeyRing> {
        self.subkeyrings.get(name).copied()
    }

    /// The root keyring.
    pub fn root(&self) -> KeyRing {
        self.root
    }
}

fn resolve_root(config: &KeyringConfig) -> Result<KeyRing, Error> {
    Ok(match config.keyring_type {
        KeyringType::Persistent => KeyRing::get_persistent(config.keyring_identifier)?,
        KeyringType::Session => KeyRing::special(SpecialKeyring::Session),
        KeyringType::User => KeyRing::special(SpecialKeyring::User),
        KeyringType::UserSession => KeyRing::special(SpecialKeyring::UserSession),
        KeyringType::Process => KeyRing::special(SpecialKeyring::Process),
        KeyringType::Thread => KeyRing::special(SpecialKeyring::Thread),
    })
}

fn ensure_subkeyring(root: &KeyRing, name: &str) -> Result<KeyRing, Error> {
    if let Some(Found::Keyring(kr)) = root.search(KeyType::Keyring, name)? {
        return Ok(kr);
    }
    root.add_keyring(name)
}
