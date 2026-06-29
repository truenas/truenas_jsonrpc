//! The passwd database: resolve an account by name ([`getpwnam`]) or by uid ([`getpwuid`]).
//!
//! Thin wrappers over the reentrant glibc `getpwnam_r` / `getpwuid_r`: they grow the scratch buffer
//! on `ERANGE` up to a cap, marshal the `struct passwd` into an owned [`PasswdEntry`], and report
//! "no such account" as `Ok(None)` (only a real failure is `Err`). The `pw_passwd` field is never
//! read — this resolves identity, not secrets.

use std::ffi::{CStr, CString};
use std::io;

use libc::{c_char, c_int, passwd};

/// Initial scratch-buffer size handed to `getpw*_r` (grown on `ERANGE`).
const INIT_BUFLEN: usize = 1024;
/// Upper bound on the scratch buffer — a passwd entry never approaches this, so hitting it means a
/// misbehaving NSS backend rather than a legitimately large record; we stop doubling and surface
/// the `ERANGE`.
const MAX_BUFLEN: usize = 1 << 20;

/// A resolved passwd-database entry. The `pw_passwd` field is intentionally omitted — this crate
/// resolves identity (name/uid/gid + the informational fields), never secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// The login name (`pw_name`).
    pub name: String,
    /// The user id (`pw_uid`) — the key the role lookup uses.
    pub uid: u32,
    /// The primary group id (`pw_gid`).
    pub gid: u32,
    /// The GECOS / comment field (`pw_gecos`).
    pub gecos: String,
    /// The home directory (`pw_dir`).
    pub dir: String,
    /// The login shell (`pw_shell`).
    pub shell: String,
}

impl PasswdEntry {
    /// Marshal a populated `libc::passwd` into an owned [`PasswdEntry`].
    ///
    /// # Safety
    /// `pw` must have been filled by a successful `getpw*_r` whose scratch buffer is **still
    /// alive**, so its `pw_name`/`pw_gecos`/`pw_dir`/`pw_shell` point at valid NUL-terminated C
    /// strings within that buffer.
    #[allow(unsafe_code)]
    unsafe fn from_raw(pw: &passwd) -> PasswdEntry {
        // A null char pointer (possible for optional fields) maps to an empty string.
        let cstr = |p: *const c_char| -> String {
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        PasswdEntry {
            name: cstr(pw.pw_name),
            uid: pw.pw_uid,
            gid: pw.pw_gid,
            gecos: cstr(pw.pw_gecos),
            dir: cstr(pw.pw_dir),
            shell: cstr(pw.pw_shell),
        }
    }
}

/// Look the account named `name` up in the passwd database.
///
/// `Ok(None)` means there is no such account; `Err` is a real lookup failure (e.g. a backend
/// error). An interior NUL in `name` is rejected as [`io::ErrorKind::InvalidInput`].
pub fn getpwnam(name: &str) -> io::Result<Option<PasswdEntry>> {
    let cname = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "username contains an interior NUL"))?;
    run(|pwd, buf, buflen, result| {
        // SAFETY: getpwnam_r reads the NUL-terminated name at `cname`, writes the entry into `*pwd`
        // and up to `buflen` bytes at `buf`, and sets `*result` to `pwd` (found) or NULL (absent).
        // Returns 0 on success/absent or a positive errno. All pointers are valid for the call.
        #[allow(unsafe_code)]
        unsafe {
            libc::getpwnam_r(cname.as_ptr(), pwd, buf, buflen, result)
        }
    })
}

/// Look the account with user id `uid` up in the passwd database. `Ok(None)` means no such account.
pub fn getpwuid(uid: u32) -> io::Result<Option<PasswdEntry>> {
    run(|pwd, buf, buflen, result| {
        // SAFETY: getpwuid_r writes the entry into `*pwd` and up to `buflen` bytes at `buf`, and
        // sets `*result` to `pwd` (found) or NULL (absent). Returns 0 or a positive errno.
        #[allow(unsafe_code)]
        unsafe {
            libc::getpwuid_r(uid, pwd, buf, buflen, result)
        }
    })
}

/// Drive a reentrant passwd lookup: allocate the scratch buffer, invoke `call`, grow on `ERANGE`
/// (up to [`MAX_BUFLEN`]), and marshal the result. `call` receives the out-`passwd`, the scratch
/// buffer + its length, and the out-`result` pointer, and returns the C `int` status.
fn run<F>(mut call: F) -> io::Result<Option<PasswdEntry>>
where
    F: FnMut(*mut passwd, *mut c_char, usize, *mut *mut passwd) -> c_int,
{
    let mut buflen = INIT_BUFLEN;
    loop {
        let mut buf: Vec<c_char> = vec![0; buflen];
        // SAFETY: `passwd` is a plain repr(C) struct of pointers and integers; an all-zero bit
        // pattern is a valid (null pointers, 0 ids) initial value that `call` overwrites on success.
        #[allow(unsafe_code)]
        let mut pwd: passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut passwd = std::ptr::null_mut();

        let rc = call(&mut pwd, buf.as_mut_ptr(), buflen, &mut result);

        if rc == libc::ERANGE && buflen < MAX_BUFLEN {
            buflen = buflen.saturating_mul(2).min(MAX_BUFLEN);
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        if result.is_null() {
            return Ok(None); // no such account — not an error
        }
        // SAFETY: rc == 0 and `result` is non-null, so `pwd` is fully populated and its string
        // fields point into `buf`, which is still alive for this block.
        #[allow(unsafe_code)]
        let entry = unsafe { PasswdEntry::from_raw(&pwd) };
        return Ok(Some(entry));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise the real passwd database, so they're best-effort: if `root`/uid 0 can't be
    // resolved (an unusual environment with no passwd db), we skip rather than fail — mirroring the
    // keyring crate's "skip when the syscall surface is unavailable" convention.

    #[test]
    fn uid_zero_resolves_to_a_root_account() {
        let entry = match getpwuid(0) {
            Ok(Some(e)) => e,
            other => return eprintln!("passwd db unavailable ({other:?}); skipping"),
        };
        assert_eq!(entry.uid, 0);
        // uid 0 is conventionally "root"; assert the round-trip by name lands back on uid 0 rather
        // than hard-coding the name (some images localize it).
        let by_name = getpwnam(&entry.name).expect("getpwnam").expect("name resolves");
        assert_eq!(by_name.uid, 0);
        assert_eq!(by_name.name, entry.name);
    }

    #[test]
    fn an_unknown_account_is_none_not_error() {
        // A name no sane passwd db contains → Ok(None). Skip only on a hard error.
        match getpwnam("truenas-nss-no-such-account-xyzzy") {
            Ok(found) => assert!(found.is_none(), "unexpected account"),
            Err(e) => eprintln!("passwd db unavailable ({e}); skipping"),
        }
    }

    #[test]
    fn an_interior_nul_username_is_rejected() {
        let err = getpwnam("a\0b").expect_err("interior NUL must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
