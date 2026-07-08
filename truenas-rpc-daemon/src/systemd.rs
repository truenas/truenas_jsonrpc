//! Minimal `sd_notify` — the systemd service-manager readiness protocol, in pure `std`.
//!
//! Each function sends one datagram to the socket named by `$NOTIFY_SOCKET` (a filesystem path, or a
//! leading `@` for the Linux abstract namespace). When the variable is unset — i.e. not running under
//! a `Type=notify` unit — every function is a no-op that returns `Ok(())`. No dependency, no `unsafe`.

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Send one `sd_notify` `state` line. No-op (returns `Ok`) when `$NOTIFY_SOCKET` is unset.
fn notify(state: &str) -> io::Result<()> {
    let socket = match std::env::var_os("NOTIFY_SOCKET") {
        Some(s) => s,
        None => return Ok(()),
    };
    let bytes = socket.as_os_str().as_bytes();
    let addr = if bytes.first() == Some(&b'@') {
        // Abstract namespace: systemd encodes the leading NUL as '@'; the name is the remainder.
        SocketAddr::from_abstract_name(&bytes[1..])?
    } else {
        SocketAddr::from_pathname(&socket)?
    };
    let sock = UnixDatagram::unbound()?;
    sock.connect_addr(&addr)?;
    sock.send(state.as_bytes())?;
    Ok(())
}

/// Tell the service manager the daemon is up and serving (`READY=1`).
pub(crate) fn ready() -> io::Result<()> {
    notify("READY=1")
}

/// Tell the service manager a configuration reload has begun (`RELOADING=1`).
pub(crate) fn reloading() -> io::Result<()> {
    notify("RELOADING=1")
}

/// Tell the service manager the daemon has begun shutting down (`STOPPING=1`).
pub(crate) fn stopping() -> io::Result<()> {
    notify("STOPPING=1")
}
