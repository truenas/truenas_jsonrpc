//! A Linux kernel-keyring store for TrueNAS credentials, modeled on the C `truenas_pykeyring`.
//!
//! Two layers, mirroring `truenas_pykeyring`:
//! - **Low-level primitives** ([`Key`] / [`KeyRing`], the peers of its `TNKey` / `TNKeyring`), with
//!   [`KeyType`], [`SpecialKeyring`], polymorphic [`Found`] search/listing, `describe`, `read_data`,
//!   `add_key`/`add_keyring`, `set_timeout`, `revoke`/`invalidate`, `list_contents`, `unlink`, etc.
//!   The kernel syscalls (`add_key(2)` / `request_key(2)` / `keyctl(2)`) are issued directly via
//!   `libc` in `sys` — the crate's only `unsafe` (audited per call) — so a key written by this
//!   crate or by the `truenas_keyring` extension is readable by the other.
//! - **A config-driven store** ([`KeyringStore`]): open a root keyring from a JSON [`KeyringConfig`]
//!   with the always-present [`SERVER_KEYS`] (inbound SCRAM verifiers) / [`CLIENT_KEYS`] (outbound
//!   peer credentials) sub-keyrings, plus config extras, and store [`ScramRecord`]s.
//!
//! Records are plaintext JSON `user` keys; the kernel keyring's UID/permission boundary is the
//! protection (no at-rest encryption — the privileged-container memory-scrape threat is out of
//! scope by design).
//!
//! ```no_run
//! use truenas_keyring::{KeyringStore, KeyringConfig, ScramRecord};
//!
//! let config = KeyringConfig::from_json(r#"{ "keyring_type": "persistent", "keyring_identifier": 0 }"#)?;
//! let store = KeyringStore::open(&config)?;
//!
//! let record = ScramRecord {
//!     username: "alice".into(), algorithm: "SHA512".into(), iterations: 500_000,
//!     salt: String::new(), stored_key: String::new(), server_key: String::new(), expiry: 0,
//! };
//! store.server_keys().put_record("alice", &record, None)?;
//! let got: Option<ScramRecord> = store.server_keys().get_record("alice")?;
//! # Ok::<(), truenas_keyring::Error>(())
//! ```

mod config;
mod error;
mod key;
mod keyring;
mod record;
mod sys;

pub use config::{KeyringConfig, KeyringType};
pub use error::Error;
pub use key::{Description, Found, Key, KeyRing, KeyType, SpecialKeyring};
pub use keyring::{KeyringStore, CLIENT_KEYS, SERVER_KEYS, SERVER_ROLES};
pub use record::{RoleRecord, ScramRecord};
