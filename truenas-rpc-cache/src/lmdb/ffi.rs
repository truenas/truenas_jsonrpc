//! Hand-written FFI to the vendored liblmdb 0.9.35 — only the functions the cache uses, bound
//! directly (no `bindgen` → no `libclang`), mirroring `truenas-rpc-utils-unsafe`'s `gssapi` approach.
//! Everything here is a plain declaration; the `unsafe` calls (and their `// SAFETY:` notes) live in
//! the safe wrappers in `mod.rs`.
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

// Opaque C handles — only ever held behind a pointer.
pub enum MDB_env {}
pub enum MDB_txn {}
pub enum MDB_cursor {}

/// A database handle (a small integer, valid within its environment).
pub type MDB_dbi = c_uint;
/// `mode_t` on Linux.
pub type mdb_mode_t = c_uint;

/// A key or value: a length + a pointer (into the caller's buffer on the way in, into the mmap on
/// the way out).
#[repr(C)]
pub struct MDB_val {
    pub mv_size: usize, // size_t
    pub mv_data: *mut c_void,
}

// --- env-open / dbi-open flags -------------------------------------------------------------------
/// Create the named database if it does not exist (`mdb_dbi_open`).
pub const MDB_CREATE: c_uint = 0x40000;
/// Open a read-only transaction (`mdb_txn_begin`).
pub const MDB_RDONLY: c_uint = 0x20000;
/// Don't fsync after commit — faster, but a crash can lose recent writes (`mdb_env_open`).
pub const MDB_NOSYNC: c_uint = 0x10000;
/// Don't use the per-thread reader slot — read txns may be created/used on any thread (our model).
pub const MDB_NOTLS: c_uint = 0x200000;

// --- return codes --------------------------------------------------------------------------------
pub const MDB_SUCCESS: c_int = 0;
pub const MDB_NOTFOUND: c_int = -30798;
pub const MDB_MAP_FULL: c_int = -30792;

// --- MDB_cursor_op ordinals (from the vendored lmdb.h enum) --------------------------------------
pub const MDB_FIRST: c_uint = 0;
pub const MDB_NEXT: c_uint = 8;

extern "C" {
    pub fn mdb_strerror(err: c_int) -> *const c_char;

    pub fn mdb_env_create(env: *mut *mut MDB_env) -> c_int;
    pub fn mdb_env_set_mapsize(env: *mut MDB_env, size: usize) -> c_int;
    pub fn mdb_env_set_maxdbs(env: *mut MDB_env, dbs: MDB_dbi) -> c_int;
    pub fn mdb_env_open(
        env: *mut MDB_env,
        path: *const c_char,
        flags: c_uint,
        mode: mdb_mode_t,
    ) -> c_int;
    pub fn mdb_env_sync(env: *mut MDB_env, force: c_int) -> c_int;
    pub fn mdb_env_close(env: *mut MDB_env);

    pub fn mdb_txn_begin(
        env: *mut MDB_env,
        parent: *mut MDB_txn,
        flags: c_uint,
        txn: *mut *mut MDB_txn,
    ) -> c_int;
    pub fn mdb_txn_commit(txn: *mut MDB_txn) -> c_int;
    pub fn mdb_txn_abort(txn: *mut MDB_txn);

    pub fn mdb_dbi_open(
        txn: *mut MDB_txn,
        name: *const c_char,
        flags: c_uint,
        dbi: *mut MDB_dbi,
    ) -> c_int;
    pub fn mdb_drop(txn: *mut MDB_txn, dbi: MDB_dbi, del: c_int) -> c_int;

    pub fn mdb_get(txn: *mut MDB_txn, dbi: MDB_dbi, key: *mut MDB_val, data: *mut MDB_val)
        -> c_int;
    pub fn mdb_put(
        txn: *mut MDB_txn,
        dbi: MDB_dbi,
        key: *mut MDB_val,
        data: *mut MDB_val,
        flags: c_uint,
    ) -> c_int;
    pub fn mdb_del(txn: *mut MDB_txn, dbi: MDB_dbi, key: *mut MDB_val, data: *mut MDB_val)
        -> c_int;

    pub fn mdb_cursor_open(txn: *mut MDB_txn, dbi: MDB_dbi, cursor: *mut *mut MDB_cursor) -> c_int;
    pub fn mdb_cursor_get(
        cursor: *mut MDB_cursor,
        key: *mut MDB_val,
        data: *mut MDB_val,
        op: c_uint,
    ) -> c_int;
    pub fn mdb_cursor_close(cursor: *mut MDB_cursor);
}
