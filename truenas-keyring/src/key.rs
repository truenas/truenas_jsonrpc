//! The low-level keyring primitives, modeled on the C `truenas_keyring` extension: [`Key`] /
//! [`KeyRing`] (the peers of its `TNKey` / `TNKeyring`), [`KeyType`], [`SpecialKeyring`], and a
//! polymorphic [`Found`] (a search/listing yields a `Key` or a `KeyRing` depending on the key's
//! type, exactly as `create_key_object_from_serial` does).

use std::ffi::CString;

use libc::c_int;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::Error;
use crate::sys::{self, Serial, KEY_SPEC_PROCESS_KEYRING};

/// A kernel key type (the peer of `truenas_keyring.KeyType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// A keyring (a container of other keys).
    Keyring,
    /// A `user` key — an arbitrary payload (how records are stored).
    User,
    /// A `logon` key — like `user`, but its payload can't be read back.
    Logon,
    /// A `big_key` — for large payloads (kept off the keyring's quota).
    BigKey,
}

impl KeyType {
    /// The kernel type string (`"user"`, `"keyring"`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            KeyType::Keyring => "keyring",
            KeyType::User => "user",
            KeyType::Logon => "logon",
            KeyType::BigKey => "big_key",
        }
    }

    /// Parse a kernel type string (e.g. from [`Description::key_type`]), or `None` if unrecognized.
    pub fn from_kernel_str(s: &str) -> Option<KeyType> {
        match s {
            "keyring" => Some(KeyType::Keyring),
            "user" => Some(KeyType::User),
            "logon" => Some(KeyType::Logon),
            "big_key" => Some(KeyType::BigKey),
            _ => None,
        }
    }

    fn c_bytes(self) -> &'static [u8] {
        match self {
            KeyType::Keyring => b"keyring\0",
            KeyType::User => b"user\0",
            KeyType::Logon => b"logon\0",
            KeyType::BigKey => b"big_key\0",
        }
    }
}

/// A special (per-caller) keyring (the peer of `truenas_keyring.SpecialKeyring`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SpecialKeyring {
    /// The caller's thread keyring.
    Thread = -1,
    /// The caller's process keyring.
    Process = -2,
    /// The caller's session keyring.
    Session = -3,
    /// The caller's per-uid user keyring.
    User = -4,
    /// The caller's per-uid user-session keyring.
    UserSession = -5,
}

impl SpecialKeyring {
    /// The negative serial the kernel resolves per caller.
    pub fn serial(self) -> Serial {
        self as Serial
    }
}

/// A key's metadata, parsed from `keyctl_describe` — `type;uid;gid;perm(hex);description`.
#[derive(Debug, Clone)]
pub struct Description {
    /// The kernel type string.
    pub key_type: String,
    /// The key owner's uid (`None` if the kernel reported a non-numeric field).
    pub uid: Option<u32>,
    /// The key owner's gid.
    pub gid: Option<u32>,
    /// The permission bitmask.
    pub permissions: Option<u32>,
    /// The key's description (the field after the last `;`, so it survives future kernel fields).
    pub description: String,
}

fn parse_description(s: &str) -> Description {
    // Fields come from the front; the description is everything after the last `;` (mirrors the C
    // `strrchr` so a future kernel field inserted before the description doesn't shift it).
    let description = s.rsplit(';').next().unwrap_or("").to_string();
    let mut fields = s.split(';');
    let key_type = fields.next().unwrap_or("").to_string();
    let uid = fields.next().and_then(|t| t.parse().ok());
    let gid = fields.next().and_then(|t| t.parse().ok());
    let permissions = fields.next().and_then(|t| u32::from_str_radix(t, 16).ok());
    Description { key_type, uid, gid, permissions, description }
}

fn cstring(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::InvalidName(format!("{s:?} contains an interior NUL byte")))
}

/// A handle to a single kernel key (the peer of `TNKey`). Cheap to copy (just a serial).
#[derive(Debug, Clone, Copy)]
pub struct Key {
    serial: Serial,
}

impl Key {
    /// Wrap an existing key serial.
    pub fn from_serial(serial: Serial) -> Key {
        Key { serial }
    }

    /// The key's serial.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// The key's metadata (`keyctl_describe`).
    pub fn describe(&self) -> Result<Description, Error> {
        Ok(parse_description(&sys::describe(self.serial)?))
    }

    /// The key's payload (`keyctl_read`). For a keyring use [`KeyRing::contents`] instead.
    pub fn read_data(&self) -> Result<Vec<u8>, Error> {
        Ok(sys::read(self.serial)?)
    }

    /// Expire the key after `seconds` (`keyctl_set_timeout`).
    pub fn set_timeout(&self, seconds: u32) -> Result<(), Error> {
        Ok(sys::set_timeout(self.serial, seconds)?)
    }

    /// Revoke the key (`keyctl_revoke`).
    pub fn revoke(&self) -> Result<(), Error> {
        Ok(sys::revoke(self.serial)?)
    }

    /// Invalidate the key — immediate removal (`keyctl_invalidate`).
    pub fn invalidate(&self) -> Result<(), Error> {
        Ok(sys::invalidate(self.serial)?)
    }
}

/// A handle to a keyring (the peer of `TNKeyring`) — a key whose type is `keyring`. Cheap to copy.
#[derive(Debug, Clone, Copy)]
pub struct KeyRing {
    serial: Serial,
}

impl KeyRing {
    /// Wrap an existing keyring serial.
    pub fn from_serial(serial: Serial) -> KeyRing {
        KeyRing { serial }
    }

    /// A handle to one of the caller's special keyrings.
    pub fn special(which: SpecialKeyring) -> KeyRing {
        KeyRing { serial: which.serial() }
    }

    /// `uid`'s persistent keyring (`keyctl_get_persistent`), linked into the process keyring.
    /// `None` uses the caller's own uid.
    pub fn get_persistent(uid: Option<u32>) -> Result<KeyRing, Error> {
        let uid_arg = uid.map_or(-1, |u| u as c_int);
        Ok(KeyRing { serial: sys::get_persistent(uid_arg, KEY_SPEC_PROCESS_KEYRING)? })
    }

    /// `request_key(2)` — search the caller's keyrings for a key by type + description.
    pub fn request_key(key_type: KeyType, description: &str) -> Result<Found, Error> {
        Found::from_serial(sys::request_key(key_type.c_bytes(), &cstring(description)?)?)
    }

    /// Add (or, by description, update) a non-keyring key in this keyring. Use [`add_keyring`](Self::add_keyring)
    /// for a sub-keyring.
    pub fn add_key(&self, key_type: KeyType, description: &str, data: &[u8]) -> Result<Key, Error> {
        if key_type == KeyType::Keyring {
            return Err(Error::InvalidName("add_key cannot create a keyring; use add_keyring".into()));
        }
        Ok(Key { serial: sys::add_key(key_type.c_bytes(), &cstring(description)?, data, self.serial)? })
    }

    /// Create a sub-keyring in this keyring.
    pub fn add_keyring(&self, description: &str) -> Result<KeyRing, Error> {
        Ok(KeyRing { serial: sys::add_key(KeyType::Keyring.c_bytes(), &cstring(description)?, &[], self.serial)? })
    }

    /// Recursively search for a key by type + description; `None` if not found.
    pub fn search(&self, key_type: KeyType, description: &str) -> Result<Option<Found>, Error> {
        match sys::search(self.serial, key_type.c_bytes(), &cstring(description)?)? {
            Some(serial) => Ok(Some(Found::from_serial(serial)?)),
            None => Ok(None),
        }
    }

    /// The raw child serials of this keyring (`keyctl_read` on a keyring).
    pub fn contents(&self) -> Result<Vec<Serial>, Error> {
        Ok(sys::read_serials(self.serial)?)
    }

    /// The live children of this keyring as typed handles, skipping (and optionally unlinking)
    /// expired/revoked keys — the peer of `list_keyring_contents`.
    pub fn list_contents(&self, unlink_expired: bool, unlink_revoked: bool) -> Result<Vec<Found>, Error> {
        let mut out = Vec::new();
        for serial in sys::read_serials(self.serial)? {
            // Peek for liveness before presenting (mirrors the C peek + optional unlink).
            if let Err(e) = sys::probe_read(serial) {
                match e.raw_os_error() {
                    Some(libc::ENOKEY) => continue, // unlinked since we read the list
                    Some(libc::EKEYEXPIRED) => {
                        if unlink_expired {
                            let _ = sys::unlink(serial, self.serial);
                        }
                        continue;
                    }
                    Some(libc::EKEYREVOKED) => {
                        if unlink_revoked {
                            let _ = sys::unlink(serial, self.serial);
                        }
                        continue;
                    }
                    _ => return Err(Error::Io(e)),
                }
            }
            match Found::from_serial(serial) {
                Ok(f) => out.push(f),
                // TOCTOU: the key vanished/expired between the peek and the describe.
                Err(Error::Io(e))
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::ENOKEY | libc::EKEYEXPIRED | libc::EKEYREVOKED)
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Unlink a key (by serial) from this keyring.
    pub fn unlink_key(&self, serial: Serial) -> Result<(), Error> {
        Ok(sys::unlink(serial, self.serial)?)
    }

    /// Unlink every key from this keyring.
    pub fn clear(&self) -> Result<(), Error> {
        Ok(sys::clear(self.serial)?)
    }

    /// This keyring as a plain [`Key`] (for [`describe`](Key::describe) etc.).
    pub fn key(&self) -> Key {
        Key::from_serial(self.serial)
    }

    /// This keyring's serial.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    // --- record convenience: store/fetch/remove a JSON record as a `user` key, keyed by string ---

    /// Store `record` (JSON) under `key` as a `user` key, upserting; `ttl_secs` expires it.
    pub fn put_record<T: Serialize>(&self, key: &str, record: &T, ttl_secs: Option<u32>) -> Result<Key, Error> {
        let bytes = serde_json::to_vec(record).map_err(Error::Record)?;
        let k = self.add_key(KeyType::User, key, &bytes)?;
        if let Some(secs) = ttl_secs {
            k.set_timeout(secs)?;
        }
        Ok(k)
    }

    /// Fetch and deserialize the record under `key`, or `None` if absent.
    pub fn get_record<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, Error> {
        let Some(serial) = sys::search(self.serial, KeyType::User.c_bytes(), &cstring(key)?)? else {
            return Ok(None);
        };
        let bytes = sys::read(serial)?;
        Ok(Some(serde_json::from_slice(&bytes).map_err(Error::Record)?))
    }

    /// Remove the record under `key`; returns whether it existed.
    pub fn remove_record(&self, key: &str) -> Result<bool, Error> {
        let Some(serial) = sys::search(self.serial, KeyType::User.c_bytes(), &cstring(key)?)? else {
            return Ok(false);
        };
        sys::unlink(serial, self.serial)?;
        Ok(true)
    }
}

/// The result of a search/listing: a non-keyring [`Key`] or a [`KeyRing`], dispatched by the key's
/// actual type (as the C `create_key_object_from_serial` does).
#[derive(Debug, Clone, Copy)]
pub enum Found {
    /// A non-keyring key.
    Key(Key),
    /// A keyring.
    Keyring(KeyRing),
}

impl Found {
    fn from_serial(serial: Serial) -> Result<Found, Error> {
        let desc = parse_description(&sys::describe(serial)?);
        Ok(if desc.key_type == KeyType::Keyring.as_str() {
            Found::Keyring(KeyRing::from_serial(serial))
        } else {
            Found::Key(Key::from_serial(serial))
        })
    }

    /// The found object's serial.
    pub fn serial(&self) -> Serial {
        match self {
            Found::Key(k) => k.serial(),
            Found::Keyring(r) => r.serial(),
        }
    }
}
