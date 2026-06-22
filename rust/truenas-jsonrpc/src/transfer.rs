//! Raw-fd transfer methods — lend a handler exclusive access to the connection's socket
//! file descriptor for a **self-delimiting** bulk stream (e.g. libzfs
//! `lzc_send`/`lzc_receive` for `zfs send`/`recv`), then resume normal JSON-RPC.
//!
//! A transfer method runs in two steps (mirroring Python's `JSONRPCFdTransferMethod`): a
//! `negotiate` callback validates the request and returns an interim "ready" result, and —
//! after the server's wire handshake — a `transfer` callback receives a [`FileTransfer`] and
//! does the bulk stream. [`crate::JsonRpcProtocol::dispatch`] produces a [`Transfer`]
//! directive ([`crate::Dispatched::Transfer`]); the **server** drives the wire handshake and
//! supplies the concrete fd.
//!
//! This module defines only the *contract* — the core never touches a socket, so it stays
//! `unsafe`-free and platform-agnostic. [`FileTransfer`] exposes just the raw fd; the I/O
//! helpers (`sendfile`/`splice`/`SCM_RIGHTS`) live in `truenas-jsonrpc-server`, where the
//! concrete fd-backed implementation and the syscalls belong.

use serde::Serialize;

/// Which way the bulk stream flows once the fd is handed over.
///
/// `Download` — the **server produces** and the client consumes (server writes the stream).
/// `Upload` — the **client produces** and the server consumes (server reads the stream).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    /// Server produces, client consumes.
    Download,
    /// Client produces, server consumes.
    Upload,
}

/// Exclusive handle to the connection's raw socket fd for one transfer.
///
/// The handler's `transfer` callback receives this. [`FileTransfer::as_raw_fd`] is the point
/// of it — hand that fd to libzfs (`lzc_send`/`lzc_receive`), `sendfile(2)`, `splice(2)`, etc.
/// The fd is **blocking** for the duration of the transfer and carries **plaintext** even
/// over an encrypted (kTLS) connection.
///
/// This is the fd-source-agnostic contract; the concrete implementation (and the streaming /
/// `SCM_RIGHTS` helpers built on the fd) lives in `truenas-jsonrpc-server`. Keeping the trait
/// minimal here is what lets the core stay `unsafe`-free.
pub trait FileTransfer {
    /// The raw, blocking socket file descriptor to read/write the stream on (a
    /// `std::os::fd::RawFd` on unix).
    fn as_raw_fd(&self) -> i32;
}

/// The boxed, `S`-erased work that finishes a transfer: given the connection's
/// [`FileTransfer`], run the handler's `transfer` callback, encode/validate the result,
/// audit, and return the final reply envelope bytes.
type Complete = Box<dyn FnOnce(&dyn FileTransfer) -> Vec<u8> + Send>;

/// Directive returned by [`crate::JsonRpcProtocol::dispatch`] (as
/// [`crate::Dispatched::Transfer`]) for a transfer method.
///
/// The server sends [`Transfer::ready_bytes`] (the `$/transferReady` envelope), runs the wire
/// handshake for [`Transfer::direction`], builds a concrete [`FileTransfer`] over the
/// connection's fd, then calls [`Transfer::complete`] with it to run the `transfer` callback
/// and obtain the final reply to send. The struct is **state-agnostic** (`S` is captured
/// inside `complete`), so it rides the non-generic [`crate::Dispatched`].
pub struct Transfer {
    rid: String,
    direction: TransferDirection,
    af_unix: bool,
    ready: Vec<u8>,
    complete: Complete,
}

impl Transfer {
    /// Build a transfer directive. Used by the dispatch core; the server only *consumes* it.
    pub(crate) fn new(
        rid: String,
        direction: TransferDirection,
        af_unix: bool,
        ready: Vec<u8>,
        complete: Complete,
    ) -> Self {
        Transfer { rid, direction, af_unix, ready, complete }
    }

    /// The request id this transfer is finishing.
    pub fn request_id(&self) -> &str {
        &self.rid
    }

    /// Which way the stream flows (server drives the handshake accordingly).
    pub fn direction(&self) -> TransferDirection {
        self.direction
    }

    /// Whether this is an `SCM_RIGHTS` fd-passing method, which **requires** an AF_UNIX
    /// connection (the server rejects it on any other transport before the handshake).
    pub fn is_fd_pass(&self) -> bool {
        self.af_unix
    }

    /// The `$/transferReady` envelope bytes the server sends before the fd handoff.
    pub fn ready_bytes(&self) -> &[u8] {
        &self.ready
    }

    /// Run the `transfer` callback over `file_transfer` and return the final reply envelope
    /// bytes (a success response, or an error envelope if the callback failed). Consumes the
    /// directive — it finishes exactly one transfer.
    pub fn complete(self, file_transfer: &dyn FileTransfer) -> Vec<u8> {
        (self.complete)(file_transfer)
    }
}

impl std::fmt::Debug for Transfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transfer")
            .field("rid", &self.rid)
            .field("direction", &self.direction)
            .field("af_unix", &self.af_unix)
            .finish_non_exhaustive()
    }
}
