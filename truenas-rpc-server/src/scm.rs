//! `SCM_RIGHTS` control-frame primitives (the **Transport** layer, layer 1) for the passthrough
//! broker (the `passthrough` feature): send / receive a small header together with a single passed
//! file descriptor over an AF_UNIX socket. The auth crate above uses these to hand a client
//! connection's fd to a local authentication broker (and, on the broker side, to receive it).
//!
//! Like [`transfer`](crate::FileTransferExt), the `unsafe` is confined here: the `nix`
//! `sendmsg` / `recvmsg` wrappers are safe; only `CMSG_SPACE` (a size calc) and adopting a
//! received raw fd as an [`OwnedFd`] need an audited block.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags, UnixAddr};

/// Send `header` plus one file descriptor (`SCM_RIGHTS`) over `sock` in a single message
/// (**AF_UNIX only**). The peer receives a *new* fd referring to the same open file; the caller
/// retains ownership of `fd` (close it when done). `header` must be small enough to go in one
/// `sendmsg` — the broker protocol uses a 4-byte length prefix, which always fits.
pub fn send_with_fd(sock: &UnixStream, header: &[u8], fd: RawFd) -> io::Result<()> {
    let iov = [IoSlice::new(header)];
    let fds = [fd];
    let cmsgs = [ControlMessage::ScmRights(&fds)];
    let sent = sendmsg::<UnixAddr>(sock.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
        .map_err(io::Error::from)?;
    if sent != header.len() {
        return Err(io::Error::other("short SCM_RIGHTS header write"));
    }
    Ok(())
}

/// Receive up to `header_len` bytes plus an optional single file descriptor (`SCM_RIGHTS`) over
/// `sock` (**AF_UNIX only**). Returns the header bytes actually read and the received fd (owned by
/// the caller), or `None` for the fd if the peer passed none. Errors if the ancillary data was
/// truncated (the peer sent more fds than the one-fd buffer holds).
pub fn recv_with_fd(
    sock: &UnixStream,
    header_len: usize,
) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut buf = vec![0u8; header_len];
    // Scope the `iov` borrow of `buf` so we can truncate `buf` to the received length afterwards.
    let (n, truncated, received) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        // SAFETY: `CMSG_SPACE` is a pure size calculation (no dereference).
        #[allow(unsafe_code)]
        let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as libc::c_uint) };
        let mut cmsg_buf: Vec<u8> = Vec::with_capacity(space as usize);

        let msg = recvmsg::<UnixAddr>(
            sock.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        )
        .map_err(io::Error::from)?;

        let mut received: Option<OwnedFd> = None;
        for cmsg in msg.cmsgs().map_err(io::Error::from)? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                for raw in fds {
                    // SAFETY: the kernel just created this fd for us; we take sole ownership of it.
                    // Extras (the protocol passes exactly one) are adopted and dropped → closed.
                    #[allow(unsafe_code)]
                    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                    if received.is_none() {
                        received = Some(owned);
                    }
                }
            }
        }
        (
            msg.bytes,
            msg.flags.contains(MsgFlags::MSG_CTRUNC),
            received,
        )
    };
    if truncated {
        return Err(io::Error::other("passed file descriptors were truncated"));
    }
    buf.truncate(n);
    Ok((buf, received))
}
