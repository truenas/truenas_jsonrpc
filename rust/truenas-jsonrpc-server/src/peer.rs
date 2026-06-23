//! The connected peer's identity — handed to the server's state-from-peer builder so the
//! per-connection session state (the protocol's `S`) can carry the caller's credentials /
//! address. Mirrors how Python's server sets `server_state` to the peer.

use std::net::SocketAddr;

/// Which transport a connection arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// An AF_UNIX (local) socket — carries [`Ucred`] and supports raw-fd transfer.
    Unix,
    /// A TCP socket — carries the peer [`SocketAddr`].
    Tcp,
}

/// Unix peer credentials from `SO_PEERCRED` (the connecting process's pid/uid/gid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ucred {
    /// Connecting process id.
    pub pid: i32,
    /// Connecting effective user id.
    pub uid: u32,
    /// Connecting effective group id.
    pub gid: u32,
}

/// Identity of the connected peer, passed to the server's state-from-peer builder.
#[derive(Clone, Debug)]
pub struct Peer {
    /// The transport the connection arrived on.
    pub transport: Transport,
    /// Peer credentials — `Some` on AF_UNIX (`SO_PEERCRED`), `None` on TCP.
    pub ucred: Option<Ucred>,
    /// Peer address — `Some` on TCP, `None` on AF_UNIX.
    pub addr: Option<SocketAddr>,
}

/// Read `SO_PEERCRED` for an AF_UNIX socket fd (Linux). `None` if the syscall fails or the
/// platform isn't Linux (BSD uses a different mechanism; TrueNAS SCALE is Linux).
#[cfg(target_os = "linux")]
pub(crate) fn peer_cred(fd: std::os::fd::RawFd) -> Option<Ucred> {
    // SAFETY: `getsockopt` writes a `struct ucred` of `len` bytes into `cred` and updates
    // `len`; both out-params are valid for the call and the size matches `SO_PEERCRED`.
    #[allow(unsafe_code)]
    unsafe {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
            &mut len,
        );
        (rc == 0).then_some(Ucred { pid: cred.pid, uid: cred.uid, gid: cred.gid })
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn peer_cred(_fd: std::os::fd::RawFd) -> Option<Ucred> {
    None
}
