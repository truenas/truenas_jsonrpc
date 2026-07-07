//! A cache & state store for `truenas-rpc` services — one uniform [`Cache<V>`] over two backends the
//! caller picks per cache:
//!
//! - **in-memory** ([`Cache::memory`]) — a concurrent map; fast, ephemeral (lost on process exit),
//!   pure-safe Rust with no C. The default (no features needed).
//! - **persistent LMDB** ([`Cache::persistent`], the `lmdb` feature) — a memory-mapped, crash-safe
//!   store that **survives reboots**; values are XDR-encoded (compact binary, via the workspace's
//!   `truenas-xdr`) and copied through a transaction.
//!
//! The op-set mirrors the TrueNAS middleware cache (`middlewared/plugins/cache.py`): [`get`],
//! [`put`], [`has_key`], [`delete`], [`pop`], [`get_or_put`], [`traverse`], and [`cleanup_expired`].
//! Every entry carries an optional TTL (`{deadline, value}`); expiry is **lazy** on read and swept by
//! [`cleanup_expired`]. `pop` and `get_or_put` are **atomic** (one write transaction / one write lock).
//!
//! ```
//! use truenas_rpc_cache::Cache;
//! let cache: Cache<u64> = Cache::memory();
//! cache.put("answer", &42, None).unwrap();
//! assert_eq!(cache.get("answer").unwrap(), Some(42));
//! assert_eq!(cache.pop("answer").unwrap(), Some(42));
//! assert_eq!(cache.get("answer").unwrap(), None);
//! ```
//!
//! [`get`]: Cache::get
//! [`put`]: Cache::put
//! [`has_key`]: Cache::has_key
//! [`delete`]: Cache::delete
//! [`pop`]: Cache::pop
//! [`get_or_put`]: Cache::get_or_put
//! [`traverse`]: Cache::traverse
//! [`cleanup_expired`]: Cache::cleanup_expired

use std::ops::ControlFlow;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

mod error;
#[cfg(feature = "lmdb")]
mod lmdb;
mod memory;

pub use error::CacheError;
#[cfg(feature = "lmdb")]
pub use lmdb::{Env, EnvFlags};

/// A value storable in a [`Cache`]: cloneable (the in-memory backend hands back clones) and
/// serde-(de)serializable (the persistent backend stores bytes). Blanket-implemented, so any
/// `#[derive(Clone, Serialize, Deserialize)]` type qualifies.
pub trait CacheValue: Clone + Serialize + DeserializeOwned + Send + Sync + 'static {}
impl<T: Clone + Serialize + DeserializeOwned + Send + Sync + 'static> CacheValue for T {}

/// Milliseconds since the Unix epoch (wall clock, so a TTL deadline survives a reboot).
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Turn a TTL into an absolute unix-milliseconds deadline (`None` = no expiry).
fn deadline_from(ttl: Option<Duration>) -> Option<u64> {
    ttl.map(|d| now_unix_ms().saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)))
}

/// Whether an entry with this `deadline` (unix ms) has expired.
fn is_expired(deadline: Option<u64>) -> bool {
    deadline.is_some_and(|dl| now_unix_ms() > dl)
}

#[cfg(feature = "lmdb")]
fn encode<V: Serialize>(v: &V) -> Result<Vec<u8>, CacheError> {
    truenas_xdr::to_bytes(v).map_err(|e| CacheError::Codec(e.to_string()))
}
#[cfg(feature = "lmdb")]
fn decode<V: DeserializeOwned>(b: &[u8]) -> Result<V, CacheError> {
    truenas_xdr::from_bytes(b).map_err(|e| CacheError::Codec(e.to_string()))
}

/// The selected backend behind a [`Cache`].
enum Backend<V> {
    Memory(memory::MemoryStore<V>),
    #[cfg(feature = "lmdb")]
    Lmdb(lmdb::LmdbStore),
}

/// A typed cache over the selected backend. Cheap to share behind an `Arc` (every method takes
/// `&self`); not `Clone` — wrap it in `Arc<Cache<V>>` to hand to handlers / tasks.
pub struct Cache<V> {
    backend: Backend<V>,
}

impl<V: CacheValue> Cache<V> {
    /// An in-memory cache (ephemeral; lost on process exit).
    pub fn memory() -> Self {
        Cache {
            backend: Backend::Memory(memory::MemoryStore::new()),
        }
    }

    /// A persistent cache backed by named database `db` in an LMDB [`Env`] (survives reboots).
    #[cfg(feature = "lmdb")]
    pub fn persistent(env: &Env, db: &str) -> Result<Self, CacheError> {
        Ok(Cache {
            backend: Backend::Lmdb(lmdb::LmdbStore::open(env, db)?),
        })
    }

    /// Fetch `key`. `None` if absent or expired (an expired entry reads as absent).
    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<V>, CacheError> {
        let key = key.as_ref();
        match &self.backend {
            Backend::Memory(m) => Ok(m.get(key)),
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => match l.get(key)? {
                Some(bytes) => Ok(Some(decode(&bytes)?)),
                None => Ok(None),
            },
        }
    }

    /// Store `value` under `key` with an optional TTL (`None` = no expiry).
    pub fn put(
        &self,
        key: impl AsRef<[u8]>,
        value: &V,
        ttl: Option<Duration>,
    ) -> Result<(), CacheError> {
        let key = key.as_ref();
        match &self.backend {
            Backend::Memory(m) => {
                m.put(key, value.clone(), ttl);
                Ok(())
            }
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => l.put(key, &encode(value)?, ttl),
        }
    }

    /// Whether `key` is present and not expired.
    pub fn has_key(&self, key: impl AsRef<[u8]>) -> Result<bool, CacheError> {
        let key = key.as_ref();
        match &self.backend {
            Backend::Memory(m) => Ok(m.has_key(key)),
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => l.has_key(key),
        }
    }

    /// Remove `key`. Returns whether it was present.
    pub fn delete(&self, key: impl AsRef<[u8]>) -> Result<bool, CacheError> {
        let key = key.as_ref();
        match &self.backend {
            Backend::Memory(m) => Ok(m.delete(key)),
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => l.delete(key),
        }
    }

    /// Atomically remove and return `key` (`None` if absent or expired).
    pub fn pop(&self, key: impl AsRef<[u8]>) -> Result<Option<V>, CacheError> {
        let key = key.as_ref();
        match &self.backend {
            Backend::Memory(m) => Ok(m.pop(key)),
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => match l.pop(key)? {
                Some(bytes) => Ok(Some(decode(&bytes)?)),
                None => Ok(None),
            },
        }
    }

    /// Return `key` if live, else compute it with `f`, store it under `ttl`, and return it —
    /// atomically (so racing callers agree on one value). `f` runs only on a miss.
    pub fn get_or_put(
        &self,
        key: impl AsRef<[u8]>,
        ttl: Option<Duration>,
        f: impl FnOnce() -> V,
    ) -> Result<V, CacheError> {
        let key = key.as_ref();
        match &self.backend {
            Backend::Memory(m) => Ok(m.get_or_put(key, ttl, f)),
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => {
                let bytes = l.get_or_put(key, ttl, || encode(&f()))?;
                decode(&bytes)
            }
        }
    }

    /// Visit every live entry (skipping expired), calling `f(key, value)`. Return `ControlFlow::Break`
    /// to stop early with a value; `Ok(None)` means all entries were visited.
    pub fn traverse<B>(
        &self,
        mut f: impl FnMut(&[u8], V) -> ControlFlow<B>,
    ) -> Result<Option<B>, CacheError> {
        match &self.backend {
            // `&mut f` (itself `FnMut`) so the binding is used mutably in both feature builds.
            Backend::Memory(m) => Ok(m.traverse(&mut f)),
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => l.traverse(|k, vbytes| Ok(f(k, decode(vbytes)?))),
        }
    }

    /// Remove all expired entries; returns how many were swept. Call periodically to bound growth.
    pub fn cleanup_expired(&self) -> Result<usize, CacheError> {
        match &self.backend {
            Backend::Memory(m) => Ok(m.cleanup_expired()),
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => l.cleanup_expired(),
        }
    }

    /// Remove every entry.
    pub fn clear(&self) -> Result<(), CacheError> {
        match &self.backend {
            Backend::Memory(m) => {
                m.clear();
                Ok(())
            }
            #[cfg(feature = "lmdb")]
            Backend::Lmdb(l) => l.clear(),
        }
    }
}
