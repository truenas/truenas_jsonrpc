//! UNIX signal handling via `nix` signalfd, driven through tokio's [`AsyncFd`].
//!
//! The daemon [`block`]s the handled set on the main thread *before* the tokio runtime spawns its
//! worker threads (so every worker inherits the blocked mask and none runs the default disposition),
//! then reads delivered signals from a non-blocking [`SignalFd`] registered with the reactor.

use std::io;

use nix::errno::Errno;
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use tokio::io::unix::AsyncFd;

/// Map a `nix` errno to a [`std::io::Error`].
fn io_err(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// Block `set` for the calling (main) thread. Call **before** building the tokio runtime, so worker
/// threads inherit the mask — the race-free precondition for signalfd delivery.
pub(crate) fn block(set: &SigSet) -> io::Result<()> {
    set.thread_block().map_err(io_err)
}

/// Create a non-blocking, close-on-exec [`SignalFd`] for `set` and register it with the reactor.
pub(crate) fn signal_fd(set: &SigSet) -> io::Result<AsyncFd<SignalFd>> {
    let sfd = SignalFd::with_flags(set, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
        .map_err(io_err)?;
    AsyncFd::new(sfd)
}

/// Await readiness and drain every pending signal, returning the batch. Loops past a spurious
/// readiness with nothing to read.
pub(crate) async fn wait_signals(afd: &AsyncFd<SignalFd>) -> io::Result<Vec<Signal>> {
    loop {
        let mut guard = afd.readable().await?;
        let mut out = Vec::new();
        loop {
            match afd.get_ref().read_signal() {
                // A delivered signal; ignore any number we can't map (shouldn't happen for our set).
                Ok(Some(si)) => {
                    if let Ok(sig) = Signal::try_from(si.ssi_signo as i32) {
                        out.push(sig);
                    }
                }
                // Drained (SFD_NONBLOCK reports no more as `Ok(None)`): clear readiness and stop.
                Ok(None) => {
                    guard.clear_ready();
                    break;
                }
                Err(e) => return Err(io_err(e)),
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }
}
