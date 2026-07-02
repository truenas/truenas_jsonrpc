//! The raw Linux kernel-keyring syscalls (`add_key(2)` / `request_key(2)` / `keyctl(2)`), issued
//! via `libc::syscall`. All `unsafe` in the crate lives here, each call site documented with a
//! `// SAFETY:` note — the audited-block policy the server crate uses for its `SO_PEERCRED` / kTLS
//! / `SCM_RIGHTS` FFI. These mirror the calls the C `truenas_keyring` extension makes.

use std::ffi::CStr;
use std::io;

use libc::{c_char, c_int, c_long, c_void};

// keyctl(2) operations (uapi/linux/keyctl.h).
const KEYCTL_REVOKE: c_long = 3;
const KEYCTL_DESCRIBE: c_long = 6;
const KEYCTL_CLEAR: c_long = 7;
const KEYCTL_UNLINK: c_long = 9;
const KEYCTL_SEARCH: c_long = 10;
const KEYCTL_READ: c_long = 11;
const KEYCTL_SET_TIMEOUT: c_long = 15;
const KEYCTL_INVALIDATE: c_long = 21;
const KEYCTL_GET_PERSISTENT: c_long = 22;

/// Special keyring ids (uapi/linux/keyctl.h) — negative serials the kernel resolves per-caller.
pub(crate) const KEY_SPEC_PROCESS_KEYRING: Serial = -2;

/// A kernel key/keyring serial (`key_serial_t`).
pub(crate) type Serial = i32;

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

/// `add_key(2)` — create (or, by description, update) a key of `key_type` in `ring`. `payload` is
/// empty for a `keyring`-type key.
pub(crate) fn add_key(
    key_type: &[u8],
    desc: &CStr,
    payload: &[u8],
    ring: Serial,
) -> io::Result<Serial> {
    let (ptr, len) = if payload.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (payload.as_ptr().cast::<c_void>(), payload.len())
    };
    // SAFETY: add_key(2) reads the NUL-terminated `key_type`/`desc` and `len` bytes at `ptr` (valid
    // for `len`, or null with `len == 0`); it writes nothing through them. Returns a serial or -1.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            key_type.as_ptr().cast::<c_char>(),
            desc.as_ptr(),
            ptr,
            len,
            ring as c_long,
        )
    };
    if rc < 0 {
        Err(last_err())
    } else {
        Ok(rc as Serial)
    }
}

/// `request_key(2)` — search the caller's keyrings for a `key_type`/`desc` key (no callout).
pub(crate) fn request_key(key_type: &[u8], desc: &CStr) -> io::Result<Serial> {
    // SAFETY: request_key(2) reads the NUL-terminated `key_type`/`desc`; callout/dest are null/0.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_request_key,
            key_type.as_ptr().cast::<c_char>(),
            desc.as_ptr(),
            std::ptr::null::<c_char>(),
            0 as c_long,
        )
    };
    if rc < 0 {
        Err(last_err())
    } else {
        Ok(rc as Serial)
    }
}

/// `keyctl(KEYCTL_GET_PERSISTENT, uid, dest)` — link `uid`'s persistent keyring into `dest` and
/// return its serial. `uid < 0` (e.g. `u32::MAX` cast) means the caller's uid.
pub(crate) fn get_persistent(uid: c_int, dest: Serial) -> io::Result<Serial> {
    // SAFETY: scalar arguments only.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_GET_PERSISTENT,
            c_long::from(uid),
            dest as c_long,
            0 as c_long,
            0 as c_long,
        )
    };
    if rc < 0 {
        Err(last_err())
    } else {
        Ok(rc as Serial)
    }
}

/// `keyctl(KEYCTL_SEARCH, ring, key_type, desc, 0)` — recursive search. `Ok(None)` on ENOKEY.
pub(crate) fn search(ring: Serial, key_type: &[u8], desc: &CStr) -> io::Result<Option<Serial>> {
    // SAFETY: keyctl(SEARCH) reads the NUL-terminated `key_type`/`desc`; dest = 0 (no link).
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SEARCH,
            ring as c_long,
            key_type.as_ptr().cast::<c_char>(),
            desc.as_ptr(),
            0 as c_long,
        )
    };
    if rc >= 0 {
        return Ok(Some(rc as Serial));
    }
    let e = last_err();
    if e.raw_os_error() == Some(libc::ENOKEY) {
        Ok(None)
    } else {
        Err(e)
    }
}

/// `keyctl(KEYCTL_READ, key, NULL, 0)` — the payload length without reading (the size probe).
/// Surfaces the errno (ENOKEY / EKEYEXPIRED / EKEYREVOKED) so callers can react.
pub(crate) fn probe_read(key: Serial) -> io::Result<usize> {
    // SAFETY: keyctl(READ) with a null buffer and length 0 returns the payload length, writing
    // nothing.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_READ,
            key as c_long,
            std::ptr::null_mut::<c_void>(),
            0 as c_long,
            0 as c_long,
        )
    };
    if rc < 0 {
        Err(last_err())
    } else {
        Ok(rc as usize)
    }
}

fn read_into(key: Serial, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: keyctl(READ) writes up to `buf.len()` bytes into `buf` (valid for that length) and
    // returns the full payload length.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_READ,
            key as c_long,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len() as c_long,
            0 as c_long,
        )
    };
    if rc < 0 {
        Err(last_err())
    } else {
        Ok(rc as usize)
    }
}

/// Read a key's payload (size-probe then read), as the C `get_key_data` does.
pub(crate) fn read(key: Serial) -> io::Result<Vec<u8>> {
    let len = probe_read(key)?;
    let mut buf = vec![0u8; len];
    let n = read_into(key, &mut buf)?;
    buf.truncate(n.min(buf.len()));
    Ok(buf)
}

/// `keyctl(KEYCTL_DESCRIBE, key, …)` — the `"type;uid;gid;perm;description"` string (NUL stripped).
pub(crate) fn describe(key: Serial) -> io::Result<String> {
    // SAFETY: keyctl(DESCRIBE) with a null buffer and length 0 returns the buffer size (incl NUL).
    #[allow(unsafe_code)]
    let len = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_DESCRIBE,
            key as c_long,
            std::ptr::null_mut::<c_void>(),
            0 as c_long,
            0 as c_long,
        )
    };
    if len < 0 {
        return Err(last_err());
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: keyctl(DESCRIBE) writes up to `buf.len()` bytes (a NUL-terminated string) into `buf`.
    #[allow(unsafe_code)]
    let n = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_DESCRIBE,
            key as c_long,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len() as c_long,
            0 as c_long,
        )
    };
    if n < 0 {
        return Err(last_err());
    }
    buf.truncate(n as usize);
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read a keyring's child serials (`KEYCTL_READ` on a keyring returns a `key_serial_t` array).
pub(crate) fn read_serials(keyring: Serial) -> io::Result<Vec<Serial>> {
    let bytes = read(keyring)?;
    if bytes.len() % std::mem::size_of::<Serial>() != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(bytes
        .chunks_exact(std::mem::size_of::<Serial>())
        .map(|c| Serial::from_ne_bytes(c.try_into().unwrap()))
        .collect())
}

/// `keyctl(KEYCTL_SET_TIMEOUT, key, seconds)`.
pub(crate) fn set_timeout(key: Serial, seconds: u32) -> io::Result<()> {
    scalar(
        KEYCTL_SET_TIMEOUT,
        key as c_long,
        c_long::from(seconds as c_int),
    )
}

/// `keyctl(KEYCTL_UNLINK, key, ring)`.
pub(crate) fn unlink(key: Serial, ring: Serial) -> io::Result<()> {
    scalar(KEYCTL_UNLINK, key as c_long, ring as c_long)
}

/// `keyctl(KEYCTL_CLEAR, ring)`.
pub(crate) fn clear(ring: Serial) -> io::Result<()> {
    scalar(KEYCTL_CLEAR, ring as c_long, 0)
}

/// `keyctl(KEYCTL_REVOKE, key)`.
pub(crate) fn revoke(key: Serial) -> io::Result<()> {
    scalar(KEYCTL_REVOKE, key as c_long, 0)
}

/// `keyctl(KEYCTL_INVALIDATE, key)`.
pub(crate) fn invalidate(key: Serial) -> io::Result<()> {
    scalar(KEYCTL_INVALIDATE, key as c_long, 0)
}

/// A `keyctl` op with up to two scalar args and no pointers.
fn scalar(op: c_long, a: c_long, b: c_long) -> io::Result<()> {
    // SAFETY: scalar arguments only; the kernel reads no memory through this call.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::syscall(libc::SYS_keyctl, op, a, b, 0 as c_long, 0 as c_long) };
    if rc < 0 {
        Err(last_err())
    } else {
        Ok(())
    }
}
