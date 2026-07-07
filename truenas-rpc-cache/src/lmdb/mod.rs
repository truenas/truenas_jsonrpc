//! Safe wrappers over the vendored liblmdb: [`Env`] (the memory-mapped environment) and
//! [`LmdbStore`] (a named database implementing the cache op-set).
//!
//! # Safety model
//!
//! This module is the crate's FFI boundary, so it allows `unsafe` (the crate otherwise denies it);
//! every block carries a `// SAFETY:` note. The invariants we uphold:
//! - An [`Env`] wraps a `*mut MDB_env` reference-counted through a process-wide **per-path pool**:
//!   LMDB forbids opening the *same* environment twice in one process (it corrupts the lock table),
//!   so every open of a path shares one handle, closed — and force-synced — exactly once when the
//!   last [`Env`] for it drops. The pointer is created by `mdb_env_create`, never handed out, and is
//!   only created/closed while the pool mutex is held. LMDB serializes writers itself and we open
//!   with `MDB_NOTLS`, so the handle is `Send + Sync`.
//! - Every transaction is wrapped in [`TxnGuard`] (commit consumes it; otherwise `Drop` aborts) and
//!   every cursor in [`CursorGuard`] (closed on `Drop`, before its transaction). No txn/cursor
//!   outlives its guard.
//! - `mdb_get` / cursor reads return pointers **into the mmap** valid only until the transaction
//!   ends; we always copy the bytes out (`.to_vec()`) before committing/aborting, and never expose a
//!   raw mmap slice past the call.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ops::ControlFlow;
use std::os::raw::{c_int, c_uint, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use crate::error::CacheError;
use crate::{deadline_from, is_expired};

mod ffi;
use ffi::*;

// --- error mapping -------------------------------------------------------------------------------

fn strerror(rc: c_int) -> String {
    // SAFETY: `mdb_strerror` returns a valid static NUL-terminated string for any code (or null).
    let p = unsafe { mdb_strerror(rc) };
    if p.is_null() {
        return format!("lmdb error {rc}");
    }
    // SAFETY: `p` is a valid NUL-terminated static C string.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn check(rc: c_int) -> Result<(), CacheError> {
    match rc {
        MDB_SUCCESS => Ok(()),
        MDB_MAP_FULL => Err(CacheError::MapFull),
        _ => Err(CacheError::Lmdb(strerror(rc))),
    }
}

fn val_of(bytes: &[u8]) -> MDB_val {
    MDB_val {
        mv_size: bytes.len(),
        mv_data: bytes.as_ptr() as *mut c_void,
    }
}

fn empty_val() -> MDB_val {
    MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    }
}

// --- the {deadline, value} envelope: an 8-byte LE unix-milliseconds prefix (0 = no expiry) -------

fn wrap(deadline: Option<u64>, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + value.len());
    out.extend_from_slice(&deadline.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(value);
    out
}

/// `(deadline, value)` from a stored envelope, or `None` if it's malformed (too short).
fn unwrap_stored(stored: &[u8]) -> Option<(Option<u64>, &[u8])> {
    if stored.len() < 8 {
        return None;
    }
    let (head, value) = stored.split_at(8);
    let dl = u64::from_le_bytes(head.try_into().ok()?);
    Some(((dl != 0).then_some(dl), value))
}

/// The live value bytes from a stored envelope — `None` if malformed or expired.
fn live_value(stored: &[u8]) -> Option<Vec<u8>> {
    match unwrap_stored(stored) {
        Some((dl, val)) if !is_expired(dl) => Some(val.to_vec()),
        _ => None,
    }
}

// --- environment ---------------------------------------------------------------------------------

/// Flags for [`Env::open`]. Both presets set `MDB_NOTLS` (our read txns may run on any thread).
#[derive(Clone, Copy)]
pub struct EnvFlags(c_uint);

impl EnvFlags {
    /// Durable: fsync on every commit (crash-safe; the default).
    pub fn durable() -> Self {
        EnvFlags(MDB_NOTLS)
    }

    /// Fast, less durable: skip the per-commit fsync — a crash can lose the most recent writes.
    pub fn no_sync() -> Self {
        EnvFlags(MDB_NOTLS | MDB_NOSYNC)
    }
}

impl Default for EnvFlags {
    fn default() -> Self {
        EnvFlags::durable()
    }
}

/// One pooled environment: the raw handle and a count of the live [`Env`] handles that share it.
/// Created, handed out, and closed only while the `env_pool` mutex is held.
struct EnvSlot {
    env: *mut MDB_env,
    refcnt: usize,
}

// SAFETY: the `*mut MDB_env` is created and closed only under the pool mutex, and is otherwise used
// exactly as in `Env` (opened with `MDB_NOTLS`; LMDB serializes writers); it is never exposed. So a
// slot is safe to keep in the shared pool and touch across threads under the lock.
unsafe impl Send for EnvSlot {}

/// The process-wide environment pool: canonical directory path → its single open environment. LMDB
/// forbids opening the **same** environment twice in one process (it corrupts the lock table), so
/// every [`Env::open`] of a path shares one handle — reference-counted, closed only when the last
/// handle drops. Mirrors the env pool of the reference C consumer (`truenas_zfstierd`).
fn env_pool() -> &'static Mutex<HashMap<PathBuf, EnvSlot>> {
    static POOL: OnceLock<Mutex<HashMap<PathBuf, EnvSlot>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Lock the pool, recovering a poisoned mutex (a panic mid-update leaves the map itself intact).
fn lock_pool() -> MutexGuard<'static, HashMap<PathBuf, EnvSlot>> {
    env_pool().lock().unwrap_or_else(|e| e.into_inner())
}

/// An open LMDB environment (one directory holding `data.mdb` + `lock.mdb`), reference-counted
/// through a process-wide per-path pool (`env_pool`): cloning shares the one handle, and dropping
/// the last one force-syncs and closes it. Single-writer / many-readers.
pub struct Env {
    /// Canonical pool key — also this environment's directory. Identifies the slot on clone / drop.
    key: PathBuf,
    /// The pooled handle. Valid for as long as this `Env` lives (its existence keeps the slot's
    /// `refcnt` ≥ 1, so the environment is not yet closed), and read lock-free during transactions.
    env: *mut MDB_env,
}

// SAFETY: `env` is opened with `MDB_NOTLS` (read txns aren't thread-pinned) and LMDB serializes
// writers; the pointer is never exposed and is closed only under the pool mutex when the last handle
// drops. So an `Env` is safe to send and share across threads.
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

impl Env {
    /// Open (creating the directory if needed) the environment at `path` with the given `map_size`
    /// (the mmap's virtual-address reservation — oversize it; running out mid-write errors),
    /// `max_dbs` named databases, `flags`, and file `mode` (e.g. `0o600`).
    ///
    /// If this process already holds the environment at `path` open, this shares that handle and the
    /// `map_size` / `max_dbs` / `flags` arguments are ignored — environment-level parameters are
    /// fixed by the first open; later opens only bump the reference count.
    pub fn open(
        path: &Path,
        map_size: usize,
        max_dbs: u32,
        flags: EnvFlags,
        mode: u32,
    ) -> Result<Env, CacheError> {
        std::fs::create_dir_all(path)
            .map_err(|e| CacheError::Lmdb(format!("create {}: {e}", path.display())))?;
        // Canonicalize so different spellings of one directory map to a single pooled environment.
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

        let mut pool = lock_pool();
        if let Some(slot) = pool.get_mut(&key) {
            // Already open in this process: share the one handle.
            slot.refcnt += 1;
            return Ok(Env { key, env: slot.env });
        }

        // First open for this path: create + configure + open before publishing to the pool, so a
        // failure leaves nothing pooled.
        let cpath = CString::new(key.as_os_str().as_bytes())
            .map_err(|_| CacheError::Lmdb("path contains an interior NUL".into()))?;
        let mut env: *mut MDB_env = ptr::null_mut();
        // SAFETY: out-param for a freshly created env handle.
        check(unsafe { mdb_env_create(&mut env) })?;
        // SAFETY: `env` is a valid, not-yet-opened handle for each of these configuration calls.
        let configured = check(unsafe { mdb_env_set_maxdbs(env, max_dbs) })
            .and_then(|()| check(unsafe { mdb_env_set_mapsize(env, map_size) }))
            .and_then(|()| check(unsafe { mdb_env_open(env, cpath.as_ptr(), flags.0, mode) }));
        if let Err(e) = configured {
            // Not pooled yet, so close the half-open handle here.
            // SAFETY: `env` came from `mdb_env_create`, is non-null, and is closed exactly once.
            unsafe { mdb_env_close(env) };
            return Err(e);
        }
        pool.insert(key.clone(), EnvSlot { env, refcnt: 1 });
        Ok(Env { key, env })
    }

    /// Flush the environment to disk (`mdb_env_sync`). Meaningful when opened with
    /// [`EnvFlags::no_sync`]; a no-op-ish safety net otherwise.
    pub fn sync(&self, force: bool) -> Result<(), CacheError> {
        // SAFETY: `self.env` is a valid open environment (this handle keeps it alive).
        check(unsafe { mdb_env_sync(self.env, force as c_int) })
    }

    fn ptr(&self) -> *mut MDB_env {
        self.env
    }
}

impl Clone for Env {
    fn clone(&self) -> Env {
        let mut pool = lock_pool();
        // A live `self` guarantees the slot exists (its `refcnt` already counts `self`).
        if let Some(slot) = pool.get_mut(&self.key) {
            slot.refcnt += 1;
        }
        Env {
            key: self.key.clone(),
            env: self.env,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let mut pool = lock_pool();
        if let Some(slot) = pool.get_mut(&self.key) {
            slot.refcnt -= 1;
            if slot.refcnt == 0 {
                // Last handle for this path. Force a final flush (matters for `no_sync` envs), then
                // close — both under the lock, so a concurrent `open` of this path can't observe a
                // half-closed environment: it blocks, finds the slot gone, and opens a fresh one.
                // SAFETY: `slot.env == self.env`, a valid open environment, closed exactly once here.
                unsafe {
                    mdb_env_sync(self.env, 1);
                    mdb_env_close(self.env);
                }
                pool.remove(&self.key);
            }
        }
    }
}

// --- transaction / cursor guards -----------------------------------------------------------------

struct TxnGuard {
    txn: *mut MDB_txn,
    committed: bool,
}

impl TxnGuard {
    fn begin(env: &Env, read_only: bool) -> Result<TxnGuard, CacheError> {
        let flags = if read_only { MDB_RDONLY } else { 0 };
        let mut txn: *mut MDB_txn = ptr::null_mut();
        // SAFETY: valid env; no parent; out-param `txn`.
        check(unsafe { mdb_txn_begin(env.ptr(), ptr::null_mut(), flags, &mut txn) })?;
        Ok(TxnGuard {
            txn,
            committed: false,
        })
    }

    fn commit(mut self) -> Result<(), CacheError> {
        self.committed = true;
        // SAFETY: valid, not-yet-finished txn; consumed here so `Drop` won't also touch it.
        check(unsafe { mdb_txn_commit(self.txn) })
    }
}

impl Drop for TxnGuard {
    fn drop(&mut self) {
        if !self.committed {
            // SAFETY: valid txn that was neither committed nor aborted; abort releases it once.
            unsafe { mdb_txn_abort(self.txn) };
        }
    }
}

struct CursorGuard {
    cursor: *mut MDB_cursor,
}

impl CursorGuard {
    fn open(txn: &TxnGuard, dbi: MDB_dbi) -> Result<CursorGuard, CacheError> {
        let mut cursor: *mut MDB_cursor = ptr::null_mut();
        // SAFETY: valid txn + dbi; out-param `cursor`.
        check(unsafe { mdb_cursor_open(txn.txn, dbi, &mut cursor) })?;
        Ok(CursorGuard { cursor })
    }
}

impl Drop for CursorGuard {
    fn drop(&mut self) {
        // SAFETY: valid cursor, closed once. Declared after its `TxnGuard`, so it drops first.
        unsafe { mdb_cursor_close(self.cursor) };
    }
}

// --- the store -----------------------------------------------------------------------------------

/// A named database in an [`Env`], implementing the cache op-set over raw value bytes (the typed
/// `Cache<V>` layer adds serialization). `Send + Sync` via [`Env`].
pub(crate) struct LmdbStore {
    env: Env,
    dbi: MDB_dbi,
}

impl LmdbStore {
    pub(crate) fn open(env: &Env, name: &str) -> Result<LmdbStore, CacheError> {
        let cname =
            CString::new(name).map_err(|_| CacheError::Lmdb("db name contains a NUL".into()))?;
        let txn = TxnGuard::begin(env, false)?;
        let mut dbi: MDB_dbi = 0;
        // SAFETY: valid txn; `cname` is a valid C string; out-param `dbi`.
        check(unsafe { mdb_dbi_open(txn.txn, cname.as_ptr(), MDB_CREATE, &mut dbi) })?;
        txn.commit()?;
        Ok(LmdbStore {
            env: env.clone(),
            dbi,
        })
    }

    /// `mdb_get` into the txn's mmap — the returned slice is valid only while `txn` lives.
    fn raw_get<'t>(&self, txn: &'t TxnGuard, key: &[u8]) -> Result<Option<&'t [u8]>, CacheError> {
        let mut k = val_of(key);
        let mut d = empty_val();
        // SAFETY: valid txn + dbi; `k` points at `key` (valid for the call); `d` is filled with a
        // pointer into the mmap, valid for `'t`.
        let rc = unsafe { mdb_get(txn.txn, self.dbi, &mut k, &mut d) };
        match rc {
            MDB_SUCCESS => {
                // SAFETY: on success `d` describes a valid region in the mmap, live for `'t`.
                let slice =
                    unsafe { std::slice::from_raw_parts(d.mv_data as *const u8, d.mv_size) };
                Ok(Some(slice))
            }
            MDB_NOTFOUND => Ok(None),
            _ => Err(CacheError::Lmdb(strerror(rc))),
        }
    }

    fn raw_del(&self, txn: &TxnGuard, key: &[u8]) -> Result<bool, CacheError> {
        let mut k = val_of(key);
        // SAFETY: valid txn + dbi; `k` valid for the call; null data = delete by key.
        let rc = unsafe { mdb_del(txn.txn, self.dbi, &mut k, ptr::null_mut()) };
        match rc {
            MDB_SUCCESS => Ok(true),
            MDB_NOTFOUND => Ok(false),
            _ => Err(CacheError::Lmdb(strerror(rc))),
        }
    }

    fn raw_put(&self, txn: &TxnGuard, key: &[u8], stored: &[u8]) -> Result<(), CacheError> {
        let mut k = val_of(key);
        let mut d = val_of(stored);
        // SAFETY: valid txn + dbi; `k`/`d` point at valid buffers for the call; flags=0 (overwrite).
        check(unsafe { mdb_put(txn.txn, self.dbi, &mut k, &mut d, 0) })
    }

    pub(crate) fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CacheError> {
        let txn = TxnGuard::begin(&self.env, true)?;
        let out = self.raw_get(&txn, key)?.and_then(live_value); // copies out before txn drops
        Ok(out)
    }

    pub(crate) fn has_key(&self, key: &[u8]) -> Result<bool, CacheError> {
        let txn = TxnGuard::begin(&self.env, true)?;
        Ok(self
            .raw_get(&txn, key)?
            .is_some_and(|s| live_value(s).is_some()))
    }

    pub(crate) fn put(
        &self,
        key: &[u8],
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<(), CacheError> {
        let stored = wrap(deadline_from(ttl), value);
        let txn = TxnGuard::begin(&self.env, false)?;
        self.raw_put(&txn, key, &stored)?;
        txn.commit()
    }

    pub(crate) fn delete(&self, key: &[u8]) -> Result<bool, CacheError> {
        let txn = TxnGuard::begin(&self.env, false)?;
        let existed = self.raw_del(&txn, key)?;
        txn.commit()?;
        Ok(existed)
    }

    pub(crate) fn pop(&self, key: &[u8]) -> Result<Option<Vec<u8>>, CacheError> {
        let txn = TxnGuard::begin(&self.env, false)?;
        // Copy the value out (ending the mmap borrow) before mutating in the same txn.
        let value = self.raw_get(&txn, key)?.map(|s| (live_value(s), ()));
        let out = match value {
            Some((v, ())) => {
                self.raw_del(&txn, key)?;
                v
            }
            None => None,
        };
        txn.commit()?;
        Ok(out)
    }

    pub(crate) fn get_or_put(
        &self,
        key: &[u8],
        ttl: Option<Duration>,
        produce: impl FnOnce() -> Result<Vec<u8>, CacheError>,
    ) -> Result<Vec<u8>, CacheError> {
        let txn = TxnGuard::begin(&self.env, false)?;
        let existing = self.raw_get(&txn, key)?.and_then(live_value); // owned; borrow ends
        let out = match existing {
            Some(v) => v,
            None => {
                let value = produce()?; // runs inside the txn but touches no LMDB → atomic
                self.raw_put(&txn, key, &wrap(deadline_from(ttl), &value))?;
                value
            }
        };
        txn.commit()?;
        Ok(out)
    }

    pub(crate) fn traverse<B>(
        &self,
        mut f: impl FnMut(&[u8], &[u8]) -> Result<ControlFlow<B>, CacheError>,
    ) -> Result<Option<B>, CacheError> {
        let txn = TxnGuard::begin(&self.env, true)?;
        let cursor = CursorGuard::open(&txn, self.dbi)?;
        let mut op = MDB_FIRST;
        loop {
            let mut k = empty_val();
            let mut d = empty_val();
            // SAFETY: valid cursor; `k`/`d` are out-params filled with mmap pointers valid until the
            // next cursor move.
            let rc = unsafe { mdb_cursor_get(cursor.cursor, &mut k, &mut d, op) };
            match rc {
                MDB_SUCCESS => {}
                MDB_NOTFOUND => break,
                _ => return Err(CacheError::Lmdb(strerror(rc))),
            }
            op = MDB_NEXT;
            // SAFETY: on success both vals describe valid mmap regions, live until the next move
            // (and we only borrow them within this iteration).
            let key = unsafe { std::slice::from_raw_parts(k.mv_data as *const u8, k.mv_size) };
            let stored = unsafe { std::slice::from_raw_parts(d.mv_data as *const u8, d.mv_size) };
            if let Some((dl, val)) = unwrap_stored(stored) {
                if !is_expired(dl) {
                    if let ControlFlow::Break(b) = f(key, val)? {
                        return Ok(Some(b));
                    }
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn cleanup_expired(&self) -> Result<usize, CacheError> {
        let txn = TxnGuard::begin(&self.env, false)?;
        let mut expired: Vec<Vec<u8>> = Vec::new();
        {
            let cursor = CursorGuard::open(&txn, self.dbi)?;
            let mut op = MDB_FIRST;
            loop {
                let mut k = empty_val();
                let mut d = empty_val();
                // SAFETY: as in `traverse`.
                let rc = unsafe { mdb_cursor_get(cursor.cursor, &mut k, &mut d, op) };
                match rc {
                    MDB_SUCCESS => {}
                    MDB_NOTFOUND => break,
                    _ => return Err(CacheError::Lmdb(strerror(rc))),
                }
                op = MDB_NEXT;
                // SAFETY: valid mmap regions for this iteration; the key is copied before we mutate.
                let key = unsafe { std::slice::from_raw_parts(k.mv_data as *const u8, k.mv_size) };
                let stored =
                    unsafe { std::slice::from_raw_parts(d.mv_data as *const u8, d.mv_size) };
                if let Some((dl, _)) = unwrap_stored(stored) {
                    if is_expired(dl) {
                        expired.push(key.to_vec());
                    }
                }
            }
        } // cursor closed before we delete
        let count = expired.len();
        for key in &expired {
            self.raw_del(&txn, key)?;
        }
        txn.commit()?;
        Ok(count)
    }

    pub(crate) fn clear(&self) -> Result<(), CacheError> {
        let txn = TxnGuard::begin(&self.env, false)?;
        // SAFETY: valid txn + dbi; `del = 0` empties the database (keeps the handle).
        check(unsafe { mdb_drop(txn.txn, self.dbi, 0) })?;
        txn.commit()
    }
}

#[cfg(test)]
mod pool_tests {
    //! The per-path environment pool: one `MDB_env` per path per process, reference-counted, closed
    //! on last drop. Mirrors the reference C consumer's env pool (including a concurrency stress).
    use super::*;

    /// This path's refcount in the pool, or `None` if no environment is pooled for it.
    fn refcnt(path: &Path) -> Option<usize> {
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        lock_pool().get(&key).map(|s| s.refcnt)
    }

    /// A process-unique scratch directory (distinct per test tag, so tests don't share pool slots).
    fn scratch(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tn-envpool-{}-{}", tag, std::process::id()))
    }

    #[test]
    fn same_path_shares_one_env_and_closes_on_last_drop() {
        let dir = scratch("share");
        let _ = std::fs::remove_dir_all(&dir);

        let a = Env::open(&dir, 1 << 20, 4, EnvFlags::durable(), 0o600).unwrap();
        assert_eq!(refcnt(&dir), Some(1));

        // A second open of the same path shares the one handle (one env per path per process).
        let b = Env::open(&dir, 1 << 20, 4, EnvFlags::durable(), 0o600).unwrap();
        assert_eq!(refcnt(&dir), Some(2));
        assert_eq!(a.ptr(), b.ptr(), "shared: the identical MDB_env handle");

        drop(a);
        assert_eq!(refcnt(&dir), Some(1), "one handle remains → env stays open");
        drop(b);
        assert_eq!(refcnt(&dir), None, "last drop closes + unpools the env");

        // Reopen after a full close works — a fresh environment.
        let c = Env::open(&dir, 1 << 20, 4, EnvFlags::durable(), 0o600).unwrap();
        assert_eq!(refcnt(&dir), Some(1));
        drop(c);
        assert_eq!(refcnt(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_and_store_bump_refcnt() {
        let dir = scratch("clone");
        let _ = std::fs::remove_dir_all(&dir);

        let a = Env::open(&dir, 1 << 20, 4, EnvFlags::durable(), 0o600).unwrap();
        let b = a.clone();
        assert_eq!(refcnt(&dir), Some(2), "clone shares the pooled env");

        // A persistent `Cache` holds its own clone of the env.
        let cache: crate::Cache<String> = crate::Cache::persistent(&a, "d").unwrap();
        assert_eq!(refcnt(&dir), Some(3));
        cache.put("k", &"v".to_string(), None).unwrap();

        drop(cache);
        drop(b);
        assert_eq!(refcnt(&dir), Some(1));
        drop(a);
        assert_eq!(refcnt(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_open_close_is_race_free() {
        // Mirrors the reference's multithreaded test: many threads hammer open → use → drop on one
        // path. The pool mutex must keep the refcount consistent and never double-open / -close.
        let dir = scratch("threads");
        let _ = std::fs::remove_dir_all(&dir);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let d = dir.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let e = Env::open(&d, 1 << 20, 4, EnvFlags::durable(), 0o600).unwrap();
                    e.sync(false).unwrap(); // touch the shared handle
                    drop(e);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Every handle dropped → the env is fully closed and unpooled.
        assert_eq!(refcnt(&dir), None, "all threads released their handles");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
