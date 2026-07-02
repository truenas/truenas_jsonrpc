//! The `NETLINK_AUDIT` socket — the only `unsafe` in the crate, each call site documented with a
//! `// SAFETY:` note (the audited-block policy the keyring/nss crates use).
//!
//! Open one socket and send one `nlmsghdr` per record (an `AUDIT_*` type + a NUL-terminated
//! `key=value` payload), then read the kernel's `NLMSG_ERROR` ack. Writing needs `CAP_AUDIT_WRITE`;
//! without it (or with kernel audit compiled out / nobody listening) the kernel replies
//! `EPERM`/`ECONNREFUSED`, which we report as [`SendStatus::Unavailable`] — a benign no-op, matching
//! libaudit's `audit_send_user_message`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `NETLINK_AUDIT` protocol number (uapi/linux/netlink.h).
const NETLINK_AUDIT: libc::c_int = 9;
/// `nlmsghdr` flags (uapi/linux/netlink.h): a request that wants an ack.
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
/// `nlmsghdr` type for an error/ack reply (uapi/linux/netlink.h).
const NLMSG_ERROR: u16 = 0x2;
/// The fixed `nlmsghdr` size, 4-byte aligned: len(u32) type(u16) flags(u16) seq(u32) pid(u32).
const NLMSG_HDRLEN: usize = 16;
/// Cap on a single audit message (libaudit `MAX_AUDIT_MESSAGE_LENGTH`).
const MAX_AUDIT_MESSAGE_LENGTH: usize = 8970;

/// The outcome of one emit attempt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendStatus {
    /// The kernel accepted (ack'd) the record.
    Delivered,
    /// Audit is benignly unavailable — no `CAP_AUDIT_WRITE` (`EPERM`) or kernel audit compiled out /
    /// nobody listening (`ECONNREFUSED`). A no-op, not an error.
    Unavailable,
}

/// An open `NETLINK_AUDIT` socket plus its per-socket sequence counter. Single-owner (the drain
/// thread) — concurrent use would race the ack reads and the counter.
pub(crate) struct AuditSocket {
    fd: OwnedFd,
    seq: u32,
}

impl AuditSocket {
    /// Open the audit netlink socket.
    pub(crate) fn open() -> io::Result<AuditSocket> {
        // SAFETY: socket(2) with constant args; returns a fresh fd or -1 (errno set).
        #[allow(unsafe_code)]
        let raw = unsafe {
            libc::socket(
                libc::PF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_AUDIT,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, valid, owned fd (checked >= 0); `OwnedFd` takes ownership and
        // closes it on drop.
        #[allow(unsafe_code)]
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(AuditSocket { fd, seq: 0 })
    }

    /// Send one `AUDIT_*` user message (`msg` is the `key=value` record text), then read the ack.
    /// `Ok(Delivered)` = accepted, `Ok(Unavailable)` = benignly off, `Err` = a real failure.
    ///
    /// Note: under kernel-audit backpressure (`auditd` behind, backlog over `audit_backlog_limit`)
    /// this `sendto` can **block the calling thread uninterruptibly** for up to
    /// `audit_backlog_wait_time` — regardless of `O_NONBLOCK`. That is why it only ever runs on the
    /// drain thread; see the `sink` module docs.
    pub(crate) fn send(&mut self, msg_type: u16, msg: &str) -> io::Result<SendStatus> {
        // libaudit sends `strlen(msg)+1` — the payload is NUL-terminated.
        let payload_len = msg.len() + 1;
        if NLMSG_HDRLEN + payload_len > MAX_AUDIT_MESSAGE_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit record exceeds 8970 bytes",
            ));
        }
        self.seq = self.seq.wrapping_add(1).max(1); // never 0

        let mut buf = Vec::with_capacity(NLMSG_HDRLEN + payload_len);
        buf.extend_from_slice(&((NLMSG_HDRLEN + payload_len) as u32).to_ne_bytes()); // nlmsg_len
        buf.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&self.seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (0 → kernel assigns)
        buf.extend_from_slice(msg.as_bytes());
        buf.push(0); // NUL terminator

        let addr = kernel_addr();
        // SAFETY: sendto(2) reads `buf.len()` bytes at `buf` and a `sockaddr_nl` at `&addr` (both
        // valid for the call); it writes nothing through them. Returns bytes sent or -1.
        #[allow(unsafe_code)]
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                buf.as_ptr().cast(),
                buf.len(),
                0,
                std::ptr::addr_of!(addr).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ECONNREFUSED | libc::EPERM) => Ok(SendStatus::Unavailable),
                _ => Err(e),
            };
        }
        self.read_ack()
    }

    /// Read the kernel's `NLMSG_ERROR` ack: `error == 0` is success, `-EPERM`/`-ECONNREFUSED` is
    /// benign unavailability, any other negative errno is an error. A poll timeout (the kernel acks
    /// promptly, so this is only a safety net) is treated as delivered rather than wedging the
    /// drain thread.
    fn read_ack(&self) -> io::Result<SendStatus> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll(2) with one valid pollfd for 1s; writes only `revents`.
        #[allow(unsafe_code)]
        let pr = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if pr <= 0 {
            return Ok(SendStatus::Delivered); // poll error/timeout → best-effort
        }
        let mut buf = [0u8; 256];
        // SAFETY: recvfrom(2) writes up to `buf.len()` bytes into `buf`; null source-addr pointers
        // mean "don't report the peer". Returns bytes read or -1.
        #[allow(unsafe_code)]
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // An NLMSG_ERROR carries an `i32` errno immediately after the 16-byte header.
        if (n as usize) >= NLMSG_HDRLEN + 4 {
            let nlmsg_type = u16::from_ne_bytes([buf[4], buf[5]]);
            if nlmsg_type == NLMSG_ERROR {
                let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
                return match err.unsigned_abs() as i32 {
                    0 => Ok(SendStatus::Delivered),
                    libc::EPERM | libc::ECONNREFUSED => Ok(SendStatus::Unavailable),
                    e => Err(io::Error::from_raw_os_error(e)),
                };
            }
        }
        Ok(SendStatus::Delivered)
    }
}

/// A `sockaddr_nl` addressed to the kernel (`nl_pid = 0`, `nl_groups = 0`).
fn kernel_addr() -> libc::sockaddr_nl {
    // SAFETY: `sockaddr_nl` is a plain repr(C) struct of integers; an all-zero value is valid
    // (nl_pid = 0 = the kernel, nl_groups = 0). We then set only the family.
    #[allow(unsafe_code)]
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr
}
