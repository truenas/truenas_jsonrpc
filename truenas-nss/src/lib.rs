//! Name-service (NSS) lookups for the auth stack.
//!
//! Scoped to what authorization needs today — the **passwd** database (the [`passwd`] module):
//! [`getpwnam`] resolves a SCRAM username to its account so roles can be keyed off the **uid**, and
//! [`getpwuid`] maps a uid (e.g. an AF_UNIX peer's `SO_PEERCRED`) back to an account. Both honour
//! the system's `nsswitch.conf` (local files plus any directory backend), use the reentrant `_r`
//! variants, and report "no such account" as `Ok(None)`.
//!
//! The crate is named for the wider NSS surface deliberately: the group database (`getgrnam` /
//! `getgrouplist`) and friends can land as sibling modules here when needed, without a new crate.
//! All `unsafe` is confined to the FFI call sites, each with a `// SAFETY:` note — the
//! audited-block policy the keyring/server crates use.
//!
//! ```no_run
//! // Resolve a SCRAM username to the uid the role lookup is keyed by.
//! if let Some(entry) = truenas_nss::getpwnam("alice")? {
//!     let _uid: u32 = entry.uid;
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

pub mod passwd;

pub use passwd::{getpwnam, getpwuid, PasswdEntry};
