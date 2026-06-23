//! The concrete [`FileTransfer`] over a connection's raw socket fd, plus the blocking I/O
//! helpers a `transfer` callback uses. The dispatch core defines only the contract
//! (`as_raw_fd`); the syscalls live here, where `unsafe` is allowed.
//!
//! During a transfer the connection's fd is put in **blocking** mode (see
//! `peer::set_blocking`) and the writer is gated, so these helpers have exclusive use of the
//! socket and block until the stream completes or the peer closes.

use std::os::fd::RawFd;

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
}
