//! The concrete [`FileTransfer`] over a connection's raw socket fd, plus the blocking I/O
//! helpers a `transfer` callback uses. The dispatch core defines only the contract
//! (`as_raw_fd`); the syscalls live here, where `unsafe` is allowed.
//!
//! During a transfer the connection's fd is put in **blocking** mode (see
//! `peer::set_blocking`) and the writer is gated, so these helpers have exclusive use of the
//! socket and block until the stream completes or the peer closes.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags, UnixAddr};
use truenas_jsonrpc::FileTransfer;

/// A [`FileTransfer`] backed by the connection's raw socket fd.
pub(crate) struct ConnFileTransfer {
    pub(crate) fd: RawFd,
}

impl FileTransfer for ConnFileTransfer {
    fn as_raw_fd(&self) -> i32 {
        self.fd
    }
}

/// Blocking byte-stream helpers on a [`FileTransfer`]'s fd, for use inside a `transfer`
/// callback (e.g. `download` writes the stream, `upload` reads it). Blanket-implemented for
/// every `FileTransfer`, so a handler calls `ft.write_all(..)` / `ft.read_exact(..)` on the
/// `&dyn FileTransfer` it receives. `import truenas_jsonrpc_server::FileTransferExt` to use it.
pub trait FileTransferExt: FileTransfer {
    /// Write the whole buffer to the stream, looping over short writes.
    fn write_all(&self, buf: &[u8]) -> std::io::Result<()>;
    /// Read up to `buf.len()` bytes; returns the number read (`< buf.len()` only if the peer
    /// closed the stream early).
    fn read_exact(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Pass open file descriptors to the peer via `SCM_RIGHTS` (**AF_UNIX only**): the peer
    /// receives new fds referring to the same open files. One sentinel byte carries the
    /// ancillary data. The caller retains ownership of `fds` (close them when done).
    fn send_fds(&self, fds: &[RawFd]) -> std::io::Result<()>;
    /// Receive up to `max_fds` file descriptors the peer passed via `SCM_RIGHTS` (**AF_UNIX
    /// only**); the returned fds are owned by the caller. Errors if the ancillary data was
    /// truncated (the peer sent more than `max_fds`).
    fn recv_fds(&self, max_fds: usize) -> std::io::Result<Vec<OwnedFd>>;
}

impl<T: FileTransfer + ?Sized> FileTransferExt for T {
    fn write_all(&self, mut buf: &[u8]) -> std::io::Result<()> {
        let fd = self.as_raw_fd();
        while !buf.is_empty() {
            // SAFETY: `fd` is the connection's live, blocking socket; `buf` is valid for `len`.
            #[allow(unsafe_code)]
            let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if n == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    fn read_exact(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let fd = self.as_raw_fd();
        let mut got = 0;
        while got < buf.len() {
            // SAFETY: `fd` is the connection's live, blocking socket; `buf[got..]` is valid.
            #[allow(unsafe_code)]
            let n = unsafe {
                libc::read(fd, buf[got..].as_mut_ptr().cast(), buf.len() - got)
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if n == 0 {
                break; // peer closed
            }
            got += n as usize;
        }
        Ok(got)
    }

    fn send_fds(&self, fds: &[RawFd]) -> std::io::Result<()> {
        let iov = [IoSlice::new(&[0u8])]; // one sentinel byte carries the ancillary fds
        let cmsgs = [ControlMessage::ScmRights(fds)];
        sendmsg::<UnixAddr>(self.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
            .map(drop)
            .map_err(std::io::Error::from)
    }

    fn recv_fds(&self, max_fds: usize) -> std::io::Result<Vec<OwnedFd>> {
        let mut byte = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut byte)];
        // Buffer sized for `max_fds` descriptors of ancillary data.
        // SAFETY: `CMSG_SPACE` is a pure size calculation.
        #[allow(unsafe_code)]
        let space =
            unsafe { libc::CMSG_SPACE((max_fds * std::mem::size_of::<RawFd>()) as libc::c_uint) };
        let mut cmsg_buf: Vec<u8> = Vec::with_capacity(space as usize);

        let msg = recvmsg::<UnixAddr>(self.as_raw_fd(), &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
            .map_err(std::io::Error::from)?;

        let mut out = Vec::new();
        for cmsg in msg.cmsgs().map_err(std::io::Error::from)? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                for raw in fds {
                    // SAFETY: each fd was just created by the kernel for us; we own it.
                    #[allow(unsafe_code)]
                    out.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        }
        if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
            return Err(std::io::Error::other(
                "received file descriptors were truncated (max_fds too small)",
            ));
        }
        Ok(out)
    }
}
