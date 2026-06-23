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
    /// Zero-copy send `count` bytes from `file_fd` (a regular file), starting at `offset`, to
    /// the stream via `sendfile(2)`. Returns the number sent (`< count` only if the peer closed
    /// early). Works over a kTLS connection — the kernel encrypts.
    fn sendfile(&self, file_fd: RawFd, offset: u64, count: usize) -> std::io::Result<usize>;
    /// Receive `count` bytes from the stream into `file_fd`, zero-copy via `splice(2)` through a
    /// kernel pipe (so the payload never enters the process). This stays zero-copy over a kTLS
    /// connection too — `tls_sw_splice_read` decrypts and splices the plaintext. It falls back
    /// to a buffered copy only where `splice` can't apply: non-Linux, or when the kernel hands
    /// back a non-data TLS record (kTLS `splice` returns `EINVAL` for control records — alerts,
    /// key-updates — which must be read via `recvmsg`). Returns the number received (`< count`
    /// only if the peer closed early).
    fn recvfile(&self, file_fd: RawFd, count: usize) -> std::io::Result<usize>;
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

    fn sendfile(&self, file_fd: RawFd, offset: u64, count: usize) -> std::io::Result<usize> {
        let out = self.as_raw_fd();
        let mut off = offset as libc::off_t;
        let mut sent = 0;
        while sent < count {
            // SAFETY: out/file_fd are live; `off` is a valid out-param that sendfile advances.
            #[allow(unsafe_code)]
            let n = unsafe { libc::sendfile(out, file_fd, &mut off, count - sent) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if n == 0 {
                break; // peer closed
            }
            sent += n as usize;
        }
        Ok(sent)
    }

    fn recvfile(&self, file_fd: RawFd, count: usize) -> std::io::Result<usize> {
        let in_fd = self.as_raw_fd();
        match splice_to_fd(in_fd, file_fd, count)? {
            Some(moved) => return Ok(moved), // zero-copy path
            None => {}                        // unsupported here → buffered fallback
        }
        let mut buf = vec![0u8; 1 << 16];
        let mut got = 0;
        while got < count {
            let want = (count - got).min(buf.len());
            // SAFETY: in_fd is live; buf is valid for `want` bytes.
            #[allow(unsafe_code)]
            let n = unsafe { libc::read(in_fd, buf.as_mut_ptr().cast(), want) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if n == 0 {
                break;
            }
            write_all_fd(file_fd, &buf[..n as usize])?;
            got += n as usize;
        }
        Ok(got)
    }
}

/// Move up to `count` bytes `src` → `dst` zero-copy via `splice(2)` through a kernel pipe
/// (`splice` needs one end to be a pipe, so socket → pipe → fd; this is zero-copy over kTLS
/// too — the kernel decrypts in `tls_sw_splice_read`). Returns the number moved, or `None` —
/// *before consuming anything* — when the first `splice` is rejected, so the caller can fall
/// back to a buffered copy: non-Linux, or a kTLS socket whose next record is a control message
/// (`splice` returns `EINVAL` for non-data records). A failure after partial progress is a real
/// I/O error. Mirrors Python's `_splice_socket_to_fd`.
fn splice_to_fd(src: RawFd, dst: RawFd, count: usize) -> std::io::Result<Option<usize>> {
    let mut pipe = [0 as libc::c_int; 2];
    // SAFETY: `pipe` is a 2-element array `pipe(2)` fills with the read/write ends.
    #[allow(unsafe_code)]
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (r, w) = (pipe[0], pipe[1]);
    let result = splice_loop(src, dst, count, r, w);
    // SAFETY: closing the pipe ends we created.
    #[allow(unsafe_code)]
    unsafe {
        libc::close(r);
        libc::close(w);
    }
    result
}

fn splice_loop(src: RawFd, dst: RawFd, count: usize, r: RawFd, w: RawFd) -> std::io::Result<Option<usize>> {
    let mut moved = 0;
    while moved < count {
        // SAFETY: src/w are live fds; null offsets mean "use the fds' own positions".
        #[allow(unsafe_code)]
        let n = unsafe {
            libc::splice(src, std::ptr::null_mut(), w, std::ptr::null_mut(), count - moved, 0)
        };
        if n < 0 {
            // First call rejected (unsupported fds, or a kTLS control record → EINVAL) →
            // signal a buffered fallback; a failure mid-stream is a real I/O error.
            return if moved == 0 { Ok(None) } else { Err(std::io::Error::last_os_error()) };
        }
        if n == 0 {
            break; // peer closed
        }
        let mut off = 0;
        while off < n {
            // SAFETY: r/dst are live fds; drain the n buffered bytes pipe → dst.
            #[allow(unsafe_code)]
            let m = unsafe {
                libc::splice(r, std::ptr::null_mut(), dst, std::ptr::null_mut(), (n - off) as usize, 0)
            };
            if m < 0 {
                return Err(std::io::Error::last_os_error());
            }
            off += m;
        }
        moved += n as usize;
    }
    Ok(Some(moved))
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: fd is live; buf is valid for `len`.
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
