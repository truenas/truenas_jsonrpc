//! The **protocol-agnostic client engine** — the inverse of the server's `connection::serve`.
//!
//! [`Client<P>`] owns the connection, a receive task (frame → classify → route) and a writer task
//! (frame + coalesce), and the reply-correlation registry. It knows nothing wire-specific: a
//! [`ProtocolRuntime`] supplies the framing + envelope, and **optional capability traits**
//! ([`Negotiates`], [`Authenticates`], [`GracefulClose`], …) each unlock one engine method via
//! `impl<P: Cap>` — so a protocol implements only the capabilities it has (mirroring the server's
//! `NetworkWire: Wire`). The minimal required seam is just: frame + encode-a-call + classify-a-reply.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use bytes::BytesMut;
use serde_json::value::RawValue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use truenas_rpc::{JsonRpcError, TransferDirection};

use crate::config::{ClientConfig, Endpoint};
use crate::error::ClientError;
use crate::transport::{connect_endpoint, BoxRead, BoxWrite, ConnFacts};

/// Delimit one message in the byte stream — a per-protocol hook (JSON-RPC = a 4-byte length prefix).
pub trait Framing: Send + Sync + 'static {
    /// Pull one complete frame out of `acc` (leaving any trailing partial bytes), or `None` if more
    /// bytes are needed. `Err` on a frame that would exceed `limit`.
    fn take_frame(&self, acc: &mut BytesMut, limit: usize) -> Result<Option<Vec<u8>>, ClientError>;
    /// Append `payload` framed onto `out`.
    fn frame_into(&self, out: &mut Vec<u8>, payload: &[u8]);
}

/// One classified inbound frame.
pub enum Inbound<P: ProtocolRuntime + ?Sized> {
    /// A reply to a call, correlated by `key`.
    Reply {
        /// The correlation key of the call this replies to.
        key: P::CorrelationKey,
        /// The call's raw result bytes (JSON text or XDR, per the wire), or the server's error.
        result: Result<Vec<u8>, JsonRpcError>,
    },
    /// A **per-call** progress update (`$/progress` on the JSON-RPC wire), correlated to an in-flight
    /// call by `key`. Routed to that call's progress sink if it opted in via
    /// [`Client::call_with_progress`]; otherwise dropped. Unlike a [`Notification`](Self::Notification)
    /// it does not complete the call — the reply still follows.
    Progress {
        /// The correlation key of the in-flight call this update belongs to.
        key: P::CorrelationKey,
        /// The raw progress payload bytes (the update's params — decode with your progress type).
        payload: Vec<u8>,
    },
    /// A `$/transferReady` handshake for an in-flight raw-fd transfer, correlated by `key`. The
    /// engine hands the payload to the waiting [`transfer`](Client::transfer) and **parks the recv
    /// task** — the bytes that follow are the raw stream, read off the fd by the transfer, not framed.
    TransferReady {
        /// The correlation key of the in-flight transfer this readies.
        key: P::CorrelationKey,
        /// The raw `$/transferReady` params bytes (`{id, direction, result}`).
        payload: Vec<u8>,
    },
    /// A server→client notification on `topic`.
    Notification {
        /// The topic (e.g. a method name).
        topic: P::Topic,
        /// The raw notification payload bytes.
        payload: Vec<u8>,
    },
}

/// The per-protocol runtime: framing + envelope, as **pure sync transforms** (the engine owns all
/// I/O). The required client seam — implement it for a wire; add capability traits for the rest.
pub trait ProtocolRuntime: Send + Sync + 'static {
    /// How a method is addressed on the wire (a method name, a proc-id, …).
    type MethodKey;
    /// How a reply correlates to its call (a UUID, an xid, …).
    type CorrelationKey: Eq + std::hash::Hash + Clone + Send + Sync + 'static;
    /// A notification topic (a method name; `()` for a protocol with no server-push).
    type Topic: Send + 'static;
    /// The framing hook.
    type Framing: Framing;

    /// This runtime's framing.
    fn framing(&self) -> &Self::Framing;
    /// Map a per-connection monotonic sequence number to the correlation key a call's reply will
    /// arrive under. The engine draws `seq` under the pending-registry lock it already takes per call
    /// (so the id costs no separate atomic and no random-UUID generation); the runtime combines it
    /// with an immutable per-connection prefix so the wire id stays globally unique.
    fn key_for_seq(&self, seq: u64) -> Self::CorrelationKey;
    /// Encode a call to its unframed wire bytes under correlation `key`. `params` are the
    /// already-serialized request bytes (JSON for a name key, XDR for a proc-id key).
    fn encode_call(&self, method: &Self::MethodKey, params: &[u8], key: &Self::CorrelationKey) -> Vec<u8>;
    /// Classify one inbound frame (the engine never inspects bytes itself).
    fn parse_inbound(&self, frame: &[u8]) -> Result<Inbound<Self>, ClientError>;
    /// Encode a best-effort cancellation for an in-flight call's `key`, if the wire has one
    /// (JSON-RPC → a fire-and-forget `$/cancelRequest`). Returns `None` (the default) for a wire with
    /// no cancellation. The engine fires this when a `call` future is **dropped before its reply
    /// arrives** — i.e. idiomatic Rust cancellation: drop the future (via `tokio::time::timeout`,
    /// `select!`, `JoinHandle::abort`, …) and the outstanding request is cancelled server-side.
    fn encode_cancel(&self, _target: &Self::CorrelationKey) -> Option<Vec<u8>> {
        None
    }
}

type ReplyTx = oneshot::Sender<Result<Vec<u8>, JsonRpcError>>;
/// A per-call progress sink (opted into via [`Client::call_with_progress`]). Each in-flight call may
/// have one; the call's progress updates are pushed here (non-blocking, drop on backpressure) until
/// the reply arrives and the entry is removed, ending the stream.
type ProgressTx = mpsc::UnboundedSender<Vec<u8>>;

/// One outstanding call's registry entry: the reply channel + an optional progress sink + (for a
/// raw-fd transfer) a one-shot for the `$/transferReady` handshake payload.
struct PendingEntry {
    reply: ReplyTx,
    progress: Option<ProgressTx>,
    ready: Option<oneshot::Sender<Vec<u8>>>,
}

/// The correlation registry behind one `Mutex`: outstanding calls keyed by correlation id, plus the
/// monotonic id source. `next_seq` lives **inside** this lock — the same lock a call must take anyway
/// to register its reply slot — so minting an id adds no second synchronization point (no separate
/// atomic, no random-UUID generation on the send path).
struct Pending<K> {
    map: HashMap<K, PendingEntry>,
    next_seq: u64,
}

/// Shared, task-spanning state: the correlation registry + the writer channel + a closed flag + the
/// raw-fd-transfer resume signal (the recv task parks on it at `$/transferReady`; the transfer fires
/// it once the raw stream is done, so the recv task reads the final reply).
struct Shared<P: ProtocolRuntime> {
    pending: Mutex<Pending<P::CorrelationKey>>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    closed: AtomicBool,
    transfer_resume: Notify,
}

impl<P: ProtocolRuntime> Shared<P> {
    fn lock_pending(&self) -> std::sync::MutexGuard<'_, Pending<P::CorrelationKey>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Guards an in-flight call's reply slot for the duration of the await. If the call future is dropped
/// before its reply arrives, [`Drop`] clears the slot (so it doesn't leak in the pending map) and
/// fires the runtime's best-effort cancellation ([`ProtocolRuntime::encode_cancel`], fire-and-forget).
/// [`round_trip`](Client::round_trip) sets `key = None` the moment the reply is in hand, so a
/// completed call's drop is a no-op.
struct DropCancel<'a, P: ProtocolRuntime> {
    shared: &'a Arc<Shared<P>>,
    runtime: &'a Arc<P>,
    key: Option<P::CorrelationKey>,
}

impl<P: ProtocolRuntime> Drop for DropCancel<'_, P> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.shared.lock_pending().map.remove(&key);
            if let Some(wire) = self.runtime.encode_cancel(&key) {
                let _ = self.shared.out_tx.send(wire); // fire-and-forget; a dead connection is moot
            }
        }
    }
}

/// An async stream of server→client notifications, `(topic, payload-bytes)`.
pub struct NotificationStream<T> {
    rx: mpsc::UnboundedReceiver<(T, Vec<u8>)>,
}

impl<T> NotificationStream<T> {
    /// The next notification, or `None` once the connection is gone.
    pub async fn recv(&mut self) -> Option<(T, Vec<u8>)> {
        self.rx.recv().await
    }
}

/// The protocol-agnostic client engine. Generic over a [`ProtocolRuntime`]; the wire specifics live
/// entirely in `P`.
pub struct Client<P: ProtocolRuntime> {
    runtime: Arc<P>,
    shared: Arc<Shared<P>>,
    recv: JoinHandle<()>,
    writer: JoinHandle<()>,
    // The connection's raw socket fd, kept open by the split halves — lent (blocking) to a raw-fd
    // transfer handler. `None` when the transport exposes no plaintext fd (userspace TLS carries
    // ciphertext; WebSocket's wire is library-owned), so `transfer` is refused — mirroring the
    // reference client's per-channel `transfer_target`.
    transfer_fd: Option<RawFd>,
    // The TLS `tls-server-end-point` channel binding (`Some` on a TLS transport), for the SCRAM-PLUS
    // auth mechanism to bind the exchange to this channel. `None` on a plaintext transport.
    channel_binding: Option<Vec<u8>>,
}

impl<P: ProtocolRuntime> Drop for Client<P> {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.recv.abort();
        self.writer.abort();
    }
}

impl<P: ProtocolRuntime> Client<P> {
    /// Connect `endpoint` and spawn the receive + writer tasks. No negotiate/auth happens here —
    /// those are capabilities a protocol opts into.
    pub async fn connect(
        runtime: P,
        endpoint: &Endpoint,
        config: ClientConfig,
    ) -> Result<(Self, NotificationStream<P::Topic>), ClientError> {
        let (reader, writer, facts) = connect_endpoint(endpoint, config.tcp_keepalive).await?;
        Ok(Self::spawn(runtime, reader, writer, facts, config))
    }

    fn spawn(
        runtime: P,
        reader: BoxRead,
        writer: BoxWrite,
        facts: ConnFacts,
        config: ClientConfig,
    ) -> (Self, NotificationStream<P::Topic>) {
        let runtime = Arc::new(runtime);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (notif_tx, notif_rx) = mpsc::unbounded_channel::<(P::Topic, Vec<u8>)>();
        let shared = Arc::new(Shared {
            pending: Mutex::new(Pending { map: HashMap::new(), next_seq: 0 }),
            out_tx,
            closed: AtomicBool::new(false),
            transfer_resume: Notify::new(),
        });
        let writer_task = tokio::spawn(writer_loop(runtime.clone(), writer, out_rx));
        let recv_task =
            tokio::spawn(recv_loop(runtime.clone(), shared.clone(), reader, config.limit, notif_tx));
        let client = Client {
            runtime,
            shared,
            recv: recv_task,
            writer: writer_task,
            transfer_fd: facts.transfer_fd,
            channel_binding: facts.channel_binding,
        };
        (client, NotificationStream { rx: notif_rx })
    }

    /// This connection's TLS `tls-server-end-point` channel binding, if it is a TLS transport
    /// (`tls://` / `wss://`). `None` on a plaintext transport. The SCRAM-PLUS mechanism binds its
    /// exchange to this value so the login can't be relayed onto a different TLS channel.
    pub fn channel_binding(&self) -> Option<&[u8]> {
        self.channel_binding.as_deref()
    }

    /// Send one method call and await its reply. The codegen-facing typed methods build on this.
    /// `params` are the already-serialized request bytes for the wire.
    pub async fn call(
        &self,
        method: &P::MethodKey,
        params: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        self.round_trip(|key| self.runtime.encode_call(method, params, key)).await
    }

    /// Like [`call`](Self::call), but the call's **progress** updates (`$/progress` on the JSON-RPC
    /// wire) are delivered to `progress` — the raw params bytes of each update (decode with your
    /// progress type, e.g. [`Progress`](crate::Progress)) — while the reply is awaited. The sender is
    /// dropped when the call completes, ending the stream; a wire with no progress simply never sends.
    /// Drain it concurrently (the reply won't arrive until progress stops), from another task:
    ///
    /// ```ignore
    /// let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    /// let job = tokio::spawn(async move { client.call_with_progress(&method, &params, tx).await });
    /// while let Some(update) = rx.recv().await { /* report progress */ }
    /// let reply = job.await??;
    /// ```
    pub async fn call_with_progress(
        &self,
        method: &P::MethodKey,
        params: &[u8],
        progress: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<Vec<u8>, ClientError> {
        self.round_trip_tracked(|key| self.runtime.encode_call(method, params, key), Some(progress))
            .await
    }

    /// Draw the next correlation id and register its reply slot (+ optional progress sink) under a
    /// **single** acquisition of the pending lock. The oneshot is allocated *before* the lock (so it
    /// isn't held across a malloc); the id (`next_seq`) is drawn *inside* it, so minting the id needs
    /// no separate atomic and no random-UUID generation — the runtime maps the sequence number to the
    /// wire id via an immutable per-connection prefix.
    fn register(
        &self,
        progress: Option<ProgressTx>,
        ready: Option<oneshot::Sender<Vec<u8>>>,
    ) -> (P::CorrelationKey, oneshot::Receiver<Result<Vec<u8>, JsonRpcError>>) {
        let (tx, rx) = oneshot::channel();
        let mut pending = self.shared.lock_pending();
        let seq = pending.next_seq;
        pending.next_seq = seq.wrapping_add(1);
        let key = self.runtime.key_for_seq(seq);
        pending.map.insert(key.clone(), PendingEntry { reply: tx, progress, ready });
        (key, rx)
    }

    /// The one correlated round-trip: register the pending reply **before** writing (race-free), let
    /// the caller `encode` the wire under the just-minted `key`, then await the oneshot. There is
    /// **no timer** — per JSON-RPC a request is outstanding until it is answered, so the call waits
    /// for its reply however long the op runs. A doomed call is failed not by a duration scavenger
    /// but by the connection dying: the sender is dropped → `Closed`.
    pub(crate) async fn round_trip(
        &self,
        encode: impl FnOnce(&P::CorrelationKey) -> Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        self.round_trip_tracked(encode, None).await
    }

    async fn round_trip_tracked(
        &self,
        encode: impl FnOnce(&P::CorrelationKey) -> Vec<u8>,
        progress: Option<ProgressTx>,
    ) -> Result<Vec<u8>, ClientError> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(ClientError::Closed);
        }
        let (key, rx) = self.register(progress, None);
        let wire = encode(&key);
        if self.shared.out_tx.send(wire).is_err() {
            self.shared.lock_pending().map.remove(&key);
            return Err(ClientError::Closed);
        }
        // If this future is dropped before the reply lands (a timeout / `select!` / abort), the guard
        // clears the pending slot (else it would leak until the connection closes) and fires a
        // best-effort cancellation. Disarmed the instant the reply is in hand, so the happy path pays
        // only a branch.
        let mut guard = DropCancel { shared: &self.shared, runtime: &self.runtime, key: Some(key) };
        let result = rx.await;
        guard.key = None;
        match result {
            Ok(result) => result.map_err(ClientError::Rpc),
            Err(_recv) => Err(ClientError::Closed), // sender dropped → connection gone
        }
    }

    /// Tear the connection down (the lifecycle-less path). In-flight calls fail with `Closed`.
    pub async fn disconnect(self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        // `Drop` aborts the tasks; dropping the pending senders fails awaiting calls with `Closed`.
    }
}

async fn writer_loop<P: ProtocolRuntime>(
    runtime: Arc<P>,
    mut writer: BoxWrite,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    // Coalesce: frame the first body, then drain everything already queued into one write per burst.
    // `batch` is reused across bursts (cleared, capacity kept) so steady-state pays no per-burst alloc.
    let mut batch: Vec<u8> = Vec::new();
    while let Some(first) = out_rx.recv().await {
        batch.clear();
        runtime.framing().frame_into(&mut batch, &first);
        while let Ok(next) = out_rx.try_recv() {
            runtime.framing().frame_into(&mut batch, &next);
        }
        if writer.write_all(&batch).await.is_err() || writer.flush().await.is_err() {
            break;
        }
    }
}

async fn recv_loop<P: ProtocolRuntime>(
    runtime: Arc<P>,
    shared: Arc<Shared<P>>,
    mut reader: BoxRead,
    limit: usize,
    notif_tx: mpsc::UnboundedSender<(P::Topic, Vec<u8>)>,
) {
    let mut acc = BytesMut::with_capacity(8 * 1024);
    'outer: loop {
        // Drain every complete frame currently buffered.
        loop {
            match runtime.framing().take_frame(&mut acc, limit) {
                Ok(Some(frame)) => match runtime.parse_inbound(&frame) {
                    Ok(Inbound::Reply { key, result }) => {
                        if let Some(entry) = shared.lock_pending().map.remove(&key) {
                            let _ = entry.reply.send(result);
                        }
                    }
                    // Progress is per-call and mid-flight: peek the entry (don't remove — the reply
                    // still follows) and push to its sink if the call opted in. Never `.await` under
                    // the lock (unbounded send is sync; drops on backpressure).
                    Ok(Inbound::Progress { key, payload }) => {
                        let pending = shared.lock_pending();
                        if let Some(sink) = pending.map.get(&key).and_then(|e| e.progress.as_ref()) {
                            let _ = sink.send(payload);
                        }
                    }
                    // `$/transferReady`: hand the payload to the waiting `transfer`, then PARK. The
                    // bytes after this frame are the raw stream — the transfer reads them off the fd,
                    // so the recv task must not read them as frames. It resumes (reads the final
                    // reply) once the transfer fires `transfer_resume`.
                    Ok(Inbound::TransferReady { key, payload }) => {
                        // Take the ready-sender out under a tight lock, THEN send + park (never hold
                        // the pending lock across the `.await`).
                        let ready =
                            shared.lock_pending().map.get_mut(&key).and_then(|e| e.ready.take());
                        if let Some(ready) = ready {
                            let _ = ready.send(payload);
                            shared.transfer_resume.notified().await;
                        }
                    }
                    Ok(Inbound::Notification { topic, payload }) => {
                        let _ = notif_tx.send((topic, payload));
                    }
                    Err(_) => {} // a malformed inbound frame is dropped, not fatal
                },
                Ok(None) => break,
                Err(_) => break 'outer, // oversized frame → tear down
            }
        }
        match reader.read_buf(&mut acc).await {
            Ok(0) | Err(_) => break, // EOF or read error
            Ok(_) => {}
        }
    }
    // Connection gone: fail every in-flight call (drop the senders → callers see `Closed`).
    shared.closed.store(true, Ordering::SeqCst);
    shared.lock_pending().map.clear();
}

// --- Optional capabilities (each unlocks one engine method) ------------------------------------

/// A protocol that binds itself with a `$/negotiate`-style handshake.
pub trait Negotiates: ProtocolRuntime {
    /// The decoded negotiate result.
    type Negotiated: serde::de::DeserializeOwned;
    /// Encode the negotiate request for `protocol` under correlation `key`.
    fn encode_negotiate(&self, protocol: &str, key: &Self::CorrelationKey) -> Vec<u8>;
}

impl<P: Negotiates> Client<P> {
    /// Bind a named protocol (the `$/negotiate` handshake).
    pub async fn negotiate(&self, protocol: &str) -> Result<P::Negotiated, ClientError> {
        let bytes = self.round_trip(|key| self.runtime.encode_negotiate(protocol, key)).await?;
        serde_json::from_slice(&bytes).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// A protocol with a session-setup (authentication) handshake.
pub trait Authenticates: ProtocolRuntime {
    /// Encode `$/sessionSetup` under correlation `key`.
    fn encode_setup(&self, params: Option<&RawValue>, key: &Self::CorrelationKey) -> Vec<u8>;
    /// Encode `$/sessionSetupContinue` (multi-step auth) under correlation `key`.
    fn encode_setup_continue(&self, params: Option<&RawValue>, key: &Self::CorrelationKey) -> Vec<u8>;
}

impl<P: Authenticates> Client<P> {
    /// Run the session-setup handshake; returns the raw setup-result bytes.
    pub async fn authenticate(
        &self,
        params: Option<&RawValue>,
    ) -> Result<Vec<u8>, ClientError> {
        self.round_trip(|key| self.runtime.encode_setup(params, key)).await
    }
    /// Continue a multi-step session setup.
    pub async fn authenticate_continue(
        &self,
        params: Option<&RawValue>,
    ) -> Result<Vec<u8>, ClientError> {
        self.round_trip(|key| self.runtime.encode_setup_continue(params, key)).await
    }
}

/// A protocol with a graceful close (`$/sessionClose`).
pub trait GracefulClose: ProtocolRuntime {
    /// Encode the close request under correlation `key`.
    fn encode_close(&self, key: &Self::CorrelationKey) -> Vec<u8>;
}

impl<P: GracefulClose> Client<P> {
    /// Close the session gracefully (best-effort), then tear the connection down.
    pub async fn close(self) -> Result<(), ClientError> {
        let _ = self.round_trip(|key| self.runtime.encode_close(key)).await;
        Ok(())
    }
}

/// A protocol that can host a **raw-fd transfer** — the `$/transferReady` → (`$/transferGo`)
/// handshake that lends a handler the connection's socket fd for a self-delimiting bulk stream.
pub trait Transfers: ProtocolRuntime {
    /// Parse a `$/transferReady` payload (an [`Inbound::TransferReady`]) into the stream direction +
    /// the negotiated interim-result bytes.
    fn parse_transfer_ready(
        &self,
        payload: &[u8],
    ) -> Result<(TransferDirection, Vec<u8>), ClientError>;
    /// Encode a `$/transferGo` for a **download**'s `key` (client-consumes: sent once the reader has
    /// parked, so the raw stream that follows is read off the fd, not by the recv task).
    fn encode_transfer_go(&self, key: &Self::CorrelationKey) -> Vec<u8>;
}

/// The exclusive, **blocking** raw-fd handle a [`transfer`](Client::transfer) callback receives. Its
/// fd carries plaintext for the duration; hand it to libzfs (`lzc_send`/`lzc_receive`), `sendfile`,
/// `splice`, or SCM_RIGHTS fd-passing. [`result`](Self::result) is the `$/transferReady` interim the
/// producer reported (e.g. a byte count so a download consumer knows how much to read).
pub struct TransferHandle {
    fd: RawFd,
    direction: TransferDirection,
    result: Vec<u8>,
}

impl TransferHandle {
    /// Which way the stream flows (`Download` = server produces / client reads; `Upload` = reverse).
    pub fn direction(&self) -> TransferDirection {
        self.direction
    }
    /// The `$/transferReady` interim-result bytes the producer reported.
    pub fn result(&self) -> &[u8] {
        &self.result
    }

    /// Read exactly `buf.len()` bytes of the stream (blocking) — for a `Download`. Errors with
    /// `UnexpectedEof` if the peer closes early. (A convenience over the raw fd; you may also drive
    /// it yourself via [`as_raw_fd`](Self::as_raw_fd) with `splice`/`sendfile`/libzfs.)
    pub fn read_exact(&self, mut buf: &mut [u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            // SAFETY: `fd` is the live, blocking connection socket; `read` fills up to `buf.len()`.
            #[allow(unsafe_code)]
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            match n {
                -1 => return Err(std::io::Error::last_os_error()),
                0 => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "transfer peer closed early",
                    ))
                }
                n => {
                    let tmp = buf;
                    buf = &mut tmp[n as usize..];
                }
            }
        }
        Ok(())
    }

    /// Write all of `buf` to the stream (blocking) — for an `Upload`.
    pub fn write_all(&self, buf: &[u8]) -> std::io::Result<()> {
        write_all_blocking(self.fd, buf)
    }

    /// **Zero-copy** send for an `Upload`: `sendfile(2)` `count` bytes from `file` (a regular file)
    /// to the peer, entirely in-kernel — the payload never enters the process. Returns bytes sent
    /// (< `count` if the peer closed early).
    pub fn sendfile(&self, file: &impl AsRawFd, count: usize) -> std::io::Result<usize> {
        let in_fd = file.as_raw_fd();
        let mut offset: libc::off_t = 0;
        let mut sent = 0usize;
        while sent < count {
            // SAFETY: out = the blocking socket, in = a readable file; `sendfile` copies in-kernel
            // and advances `offset` by the number of bytes moved.
            #[allow(unsafe_code)]
            let n = unsafe { libc::sendfile(self.fd, in_fd, &mut offset, count - sent) };
            match n {
                -1 => return Err(std::io::Error::last_os_error()),
                0 => break, // peer closed
                n => sent += n as usize,
            }
        }
        Ok(sent)
    }

    /// **Zero-copy** receive for a `Download`: move `count` bytes from the peer into `file` (a regular
    /// file) through a kernel pipe with `splice(2)` — the payload never enters the process. Falls back
    /// to a buffered copy where the kernel can't `splice` these fds. Returns bytes moved (< `count` if
    /// the peer closed early).
    pub fn recvfile(&self, file: &impl AsRawFd, count: usize) -> std::io::Result<usize> {
        let dst = file.as_raw_fd();
        if let Some(res) = splice_socket_to_fd(self.fd, dst, count) {
            return res;
        }
        // Fallback: a buffered read → write copy.
        let mut buf = vec![0u8; 1 << 20];
        let mut moved = 0usize;
        while moved < count {
            let want = (count - moved).min(buf.len());
            let n = read_once(self.fd, &mut buf[..want])?;
            if n == 0 {
                break;
            }
            write_all_blocking(dst, &buf[..n])?;
            moved += n;
        }
        Ok(moved)
    }
}

/// `SCM_RIGHTS` file-descriptor passing over the lent connection fd (AF_UNIX only), mirroring the
/// server's `FileTransferExt`. One sentinel byte carries the ancillary data.
#[cfg(feature = "fd-passing")]
impl TransferHandle {
    /// Send `fds` to the peer as `SCM_RIGHTS` ancillary data (an **upload** fd-pass). The peer receives
    /// dup'd copies; the caller keeps ownership of `fds`.
    pub fn send_fds(&self, fds: &[RawFd]) -> std::io::Result<()> {
        use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixAddr};
        let iov = [std::io::IoSlice::new(&[0u8])];
        let cmsgs = [ControlMessage::ScmRights(fds)];
        sendmsg::<UnixAddr>(self.fd, &iov, &cmsgs, MsgFlags::empty(), None)
            .map(drop)
            .map_err(std::io::Error::from)
    }

    /// Receive up to `max_fds` fds from the peer as `SCM_RIGHTS` (a **download** fd-pass). The caller
    /// owns the returned fds; errors if the kernel truncated the ancillary data (`MSG_CTRUNC`).
    pub fn recv_fds(&self, max_fds: usize) -> std::io::Result<Vec<std::os::fd::OwnedFd>> {
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, UnixAddr};
        use std::os::fd::FromRawFd;
        let mut byte = [0u8; 1];
        let mut iov = [std::io::IoSliceMut::new(&mut byte)];
        // SAFETY: `CMSG_SPACE` is a pure size computation (no dereference).
        #[allow(unsafe_code)]
        let space =
            unsafe { libc::CMSG_SPACE((max_fds * std::mem::size_of::<RawFd>()) as libc::c_uint) };
        let mut cmsg_buf = vec![0u8; space as usize];
        let msg = recvmsg::<UnixAddr>(self.fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
            .map_err(std::io::Error::from)?;
        let mut out = Vec::new();
        for cmsg in msg.cmsgs().map_err(std::io::Error::from)? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                for raw in fds {
                    // SAFETY: `raw` is a fd the kernel just installed for us; we take sole ownership.
                    #[allow(unsafe_code)]
                    out.push(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
                }
            }
        }
        if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
            return Err(std::io::Error::other("received file descriptors were truncated"));
        }
        Ok(out)
    }
}

/// Write all of `buf` to a blocking fd, looping over short writes.
fn write_all_blocking(fd: RawFd, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `fd` is the live, blocking connection socket; `write` sends up to `buf.len()`.
        #[allow(unsafe_code)]
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        match n {
            -1 => return Err(std::io::Error::last_os_error()),
            0 => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "transfer peer closed")),
            n => buf = &buf[n as usize..],
        }
    }
    Ok(())
}

/// One `read(2)` into `buf` (blocking); the buffered-copy fallback for [`TransferHandle::recvfile`].
fn read_once(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    // SAFETY: `fd` is the live, blocking connection socket; `read` fills up to `buf.len()`.
    #[allow(unsafe_code)]
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Move up to `count` bytes socket→`dst` **zero-copy** via a kernel pipe (`splice`, socket→pipe→fd —
/// `splice` needs one end to be a pipe). Returns `None` — *before consuming anything* — when `splice`
/// is unavailable/rejected for these fds (the caller falls back to a buffered copy); `Some(..)` once
/// it has committed (a failure after partial progress is a real error).
fn splice_socket_to_fd(src: RawFd, dst: RawFd, count: usize) -> Option<std::io::Result<usize>> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid 2-int array `pipe` fills with the {read, write} ends.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Some(Err(std::io::Error::last_os_error()));
    }
    let (pr, pw) = (fds[0], fds[1]);
    let mut moved = 0usize;
    let result = loop {
        if moved >= count {
            break Ok(moved);
        }
        // socket → pipe
        // SAFETY: `src` is the blocking socket, `pw` the pipe write end we just made.
        #[allow(unsafe_code)]
        let n = unsafe { libc::splice(src, std::ptr::null_mut(), pw, std::ptr::null_mut(), count - moved, 0) };
        if n < 0 {
            if moved == 0 {
                close_fd(pr); // unsupported here, nothing consumed → let the caller fall back
                close_fd(pw);
                return None;
            }
            break Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            break Ok(moved); // peer closed early
        }
        // pipe → fd: drain the `n` buffered bytes into the file.
        let mut drained = 0usize;
        let err = loop {
            if drained >= n as usize {
                break None;
            }
            // SAFETY: `pr` is the pipe read end, `dst` the destination file.
            #[allow(unsafe_code)]
            let m = unsafe {
                libc::splice(pr, std::ptr::null_mut(), dst, std::ptr::null_mut(), n as usize - drained, 0)
            };
            if m < 0 {
                break Some(std::io::Error::last_os_error());
            }
            drained += m as usize;
        };
        if let Some(e) = err {
            break Err(e);
        }
        moved += n as usize;
    };
    close_fd(pr);
    close_fd(pw);
    Some(result)
}

/// `close(2)` a pipe fd we own.
fn close_fd(fd: RawFd) {
    // SAFETY: `fd` is a pipe end this module created and owns.
    #[allow(unsafe_code)]
    unsafe {
        libc::close(fd);
    }
}

impl AsRawFd for TransferHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl<P: Transfers> Client<P> {
    /// Run a raw-fd transfer method (e.g. a dataset send/receive). Sends the request, does the
    /// `$/transferReady` (+ `$/transferGo` for a download) handshake, **parks the reader**, then runs
    /// `callback` on a blocking worker with exclusive access to the connection's blocking socket fd
    /// (a [`TransferHandle`]) — the callback drives the bulk stream. On a clean return it resumes the
    /// reader and returns the server's final result. Monopolizes the connection for the duration; a
    /// callback error/panic tears the connection down (the wire is then indeterminate).
    pub async fn transfer<F>(
        &self,
        method: &P::MethodKey,
        params: &[u8],
        callback: F,
    ) -> Result<Vec<u8>, ClientError>
    where
        F: FnOnce(TransferHandle) -> std::io::Result<()> + Send + 'static,
    {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(ClientError::Closed);
        }
        // A transfer needs a plaintext fd to lend; transports that don't expose one (userspace TLS,
        // WebSocket) refuse it up front — before sending a request we could never fulfil.
        let Some(fd) = self.transfer_fd else {
            return Err(ClientError::NoTransfer);
        };
        // Register the reply slot + a ready slot, then send the request.
        let (ready_tx, mut ready_rx) = oneshot::channel();
        let (key, mut reply_rx) = self.register(None, Some(ready_tx));
        let wire = self.runtime.encode_call(method, params, &key);
        if self.shared.out_tx.send(wire).is_err() {
            self.shared.lock_pending().map.remove(&key);
            return Err(ClientError::Closed);
        }

        // Await `$/transferReady`, or an early error reply (the server rejected before ready — the
        // recv task never parked, so the connection stays usable).
        let ready_payload = tokio::select! {
            r = &mut reply_rx => {
                self.shared.lock_pending().map.remove(&key);
                return match r {
                    Ok(res) => res.map_err(ClientError::Rpc),
                    Err(_) => Err(ClientError::Closed),
                };
            }
            r = &mut ready_rx => match r {
                Ok(p) => p,
                Err(_) => return Err(ClientError::Closed),
            },
        };
        // From here the recv task is PARKED. Every exit below must unpark it (via `abort_transfer`
        // on error, or `transfer_resume` on success) or the connection wedges.
        let (direction, result) = match self.runtime.parse_transfer_ready(&ready_payload) {
            Ok(dr) => dr,
            Err(e) => {
                self.abort_transfer(&key);
                return Err(e);
            }
        };
        // Make the fd blocking for the handler. Then, for a download (client consumes), send
        // `$/transferGo` **directly on the fd** (framed) so the server starts streaming — bypassing
        // the async writer task, which must not poll a now-blocking fd. The reader is already parked,
        // and the request was flushed before `$/transferReady`, so the writer queue is empty here.
        if let Err(e) = set_blocking(fd, true) {
            self.abort_transfer(&key);
            return Err(ClientError::Transport(e));
        }
        if direction == TransferDirection::Download {
            let mut framed = Vec::new();
            self.runtime.framing().frame_into(&mut framed, &self.runtime.encode_transfer_go(&key));
            if let Err(e) = write_all_blocking(fd, &framed) {
                let _ = set_blocking(fd, false);
                self.abort_transfer(&key);
                return Err(ClientError::Transport(e));
            }
        }
        let handle = TransferHandle { fd, direction, result };
        let outcome = tokio::task::spawn_blocking(move || callback(handle)).await;
        let _ = set_blocking(fd, false);

        match outcome {
            Ok(Ok(())) => {
                // Clean stream: resume the reader and await the server's final reply.
                self.shared.transfer_resume.notify_one();
                let reply = reply_rx.await;
                self.shared.lock_pending().map.remove(&key);
                match reply {
                    Ok(res) => res.map_err(ClientError::Rpc),
                    Err(_) => Err(ClientError::Closed),
                }
            }
            Ok(Err(e)) => {
                self.abort_transfer(&key);
                Err(ClientError::Transport(e))
            }
            Err(_panic) => {
                self.abort_transfer(&key);
                Err(ClientError::Rpc(JsonRpcError::internal("transfer callback panicked")))
            }
        }
    }
}

/// `SCM_RIGHTS` fd passing over an fd-pass method (AF_UNIX only) — reuses the transfer takeover
/// ([`Client::transfer`]); the callback just does a `sendmsg`/`recvmsg` instead of a byte stream.
#[cfg(feature = "fd-passing")]
impl<P: Transfers> Client<P> {
    /// Pass `fds` to the server over an **upload** fd-pass `method`; returns the server's final result
    /// bytes. `params` are the already-serialized request bytes. AF_UNIX only (else
    /// [`ClientError::NoTransfer`]).
    pub async fn send_fds(
        &self,
        method: &P::MethodKey,
        params: &[u8],
        fds: &[RawFd],
    ) -> Result<Vec<u8>, ClientError> {
        let fds = fds.to_vec();
        self.transfer(method, params, move |ht| ht.send_fds(&fds)).await
    }

    /// Receive up to `max_fds` fds from the server over a **download** fd-pass `method`; returns the
    /// server's final result bytes plus the received, owned fds.
    pub async fn recv_fds(
        &self,
        method: &P::MethodKey,
        params: &[u8],
        max_fds: usize,
    ) -> Result<(Vec<u8>, Vec<std::os::fd::OwnedFd>), ClientError> {
        // The callback runs on a blocking worker; hand the received fds back over a sync channel.
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let reply = self
            .transfer(method, params, move |ht| {
                let _ = tx.send(ht.recv_fds(max_fds)?);
                Ok(())
            })
            .await?;
        Ok((reply, rx.recv().unwrap_or_default()))
    }
}

impl<P: ProtocolRuntime> Client<P> {
    /// Abort a transfer whose wire state is indeterminate (a mid-stream failure, or a bad handshake):
    /// drop its pending slot, mark the connection closed, and unpark the recv task so it observes the
    /// close and exits. Only called after the reader has parked.
    fn abort_transfer(&self, key: &P::CorrelationKey) {
        self.shared.lock_pending().map.remove(key);
        self.shared.closed.store(true, Ordering::SeqCst);
        self.shared.transfer_resume.notify_one();
    }
}

/// Toggle `O_NONBLOCK` on the connection fd for a transfer: blocking while the handler owns it, then
/// non-blocking again so tokio's reactor can drive it. The fd stays owned by the connection's split
/// halves — this only rewrites its status flags.
fn set_blocking(fd: RawFd, blocking: bool) -> std::io::Result<()> {
    // SAFETY: `fd` is the live connection socket, kept open by the split halves; the borrow neither
    // outlives this call nor takes ownership (no close), and `set_nonblocking` only `fcntl`s flags.
    #[allow(unsafe_code)]
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    socket2::SockRef::from(&borrowed).set_nonblocking(!blocking)
}

// --- The codegen seam --------------------------------------------------------------------------

/// A subscription id.
pub type SubId = String;

/// How a generated method addresses its call: by name (JSON-RPC) or proc-id (a binary wire).
#[derive(Clone, Copy, Debug)]
pub enum MethodKey<'a> {
    /// Address by method name (JSON-RPC).
    Name(&'a str),
    /// Address by XDR proc-id (a binary wire).
    Proc(u32),
}

/// The result of a filterable query: a row list, a single record (`get`), or a count.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum QueryResult<E> {
    /// The matching rows.
    Rows(Vec<E>),
    /// A single record (`query-options.get`).
    One(E),
    /// A count (`query-options.count`).
    Count(i64),
}

/// The minimal, object-safe call seam a **generated** client sits on. A concrete runtime client (e.g.
/// `JsonRpcClient`) implements it; the codegen stays protocol-agnostic by going through it.
#[async_trait::async_trait]
pub trait CallEngine: Send + Sync {
    /// Encode-free call: `params` are the already-serialized request bytes; returns the serialized
    /// result bytes (or the flattened [`JsonRpcError`]).
    async fn call(&self, method: MethodKey<'_>, params: &[u8]) -> Result<Vec<u8>, JsonRpcError>;

    /// Run a raw-fd transfer (a mode switch that streams on the connection fd — e.g. a dataset
    /// send/receive). `callback` is **boxed** (so the seam stays object-safe) and receives the
    /// blocking fd via a [`TransferHandle`] for the bulk stream; returns the server's final result.
    async fn transfer(
        &self,
        method: MethodKey<'_>,
        params: &[u8],
        callback: Box<dyn FnOnce(TransferHandle) -> std::io::Result<()> + Send>,
    ) -> Result<Vec<u8>, JsonRpcError>;
}
