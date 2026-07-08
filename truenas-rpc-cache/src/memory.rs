//! The in-memory cache backend: a `RwLock<HashMap>` with the same `{deadline, value}` envelope,
//! lazy TTL expiry, and atomic `pop` / `get_or_put` as the persistent backend — but values are
//! stored **live** (a clone on read, no serialization) and everything is lost on process exit.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use crate::{deadline_from, is_expired};

/// One stored entry: an optional absolute expiry (unix seconds; `None` = never) + the live value.
struct MemEntry<V> {
    deadline: Option<u64>,
    value: V,
}

/// The in-memory store. Concurrent reads (a shared read lock); writes take the write lock.
pub(crate) struct MemoryStore<V> {
    map: RwLock<HashMap<Vec<u8>, MemEntry<V>>>,
}

impl<V: Clone> MemoryStore<V> {
    pub(crate) fn new() -> Self {
        MemoryStore {
            map: RwLock::new(HashMap::new()),
        }
    }

    // A poisoned lock only means a prior holder panicked mid-op; the map itself is still consistent,
    // so recover the guard rather than propagate poison (a cache should not become permanently dead).
    fn read(&self) -> RwLockReadGuard<'_, HashMap<Vec<u8>, MemEntry<V>>> {
        self.map.read().unwrap_or_else(|e| e.into_inner())
    }
    fn write(&self) -> RwLockWriteGuard<'_, HashMap<Vec<u8>, MemEntry<V>>> {
        self.map.write().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn get(&self, key: &[u8]) -> Option<V> {
        self.read()
            .get(key)
            .filter(|e| !is_expired(e.deadline))
            .map(|e| e.value.clone())
    }

    pub(crate) fn has_key(&self, key: &[u8]) -> bool {
        self.read()
            .get(key)
            .is_some_and(|e| !is_expired(e.deadline))
    }

    pub(crate) fn put(&self, key: &[u8], value: V, ttl: Option<Duration>) {
        self.write().insert(
            key.to_vec(),
            MemEntry {
                deadline: deadline_from(ttl),
                value,
            },
        );
    }

    pub(crate) fn delete(&self, key: &[u8]) -> bool {
        self.write().remove(key).is_some()
    }

    pub(crate) fn pop(&self, key: &[u8]) -> Option<V> {
        // Atomic get+remove under the single write lock; an expired entry is removed but read as absent.
        self.write()
            .remove(key)
            .filter(|e| !is_expired(e.deadline))
            .map(|e| e.value)
    }

    pub(crate) fn get_or_put(&self, key: &[u8], ttl: Option<Duration>, f: impl FnOnce() -> V) -> V {
        // Atomic: the compute-and-insert happens under the write lock, so two racing callers agree.
        let mut m = self.write();
        if let Some(e) = m.get(key) {
            if !is_expired(e.deadline) {
                return e.value.clone();
            }
        }
        let value = f();
        m.insert(
            key.to_vec(),
            MemEntry {
                deadline: deadline_from(ttl),
                value: value.clone(),
            },
        );
        value
    }

    pub(crate) fn traverse<B>(&self, mut f: impl FnMut(&[u8], V) -> ControlFlow<B>) -> Option<B> {
        for (k, e) in self.read().iter() {
            if is_expired(e.deadline) {
                continue;
            }
            if let ControlFlow::Break(b) = f(k, e.value.clone()) {
                return Some(b);
            }
        }
        None
    }

    pub(crate) fn cleanup_expired(&self) -> usize {
        let mut m = self.write();
        let before = m.len();
        m.retain(|_, e| !is_expired(e.deadline));
        before - m.len()
    }

    pub(crate) fn clear(&self) {
        self.write().clear();
    }
}
