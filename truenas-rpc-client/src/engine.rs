//! The **protocol-agnostic client engine** — the inverse of the server's `connection::serve`.
//!
//! [`Client<P>`] owns the connection, a receive task (frame → classify → route) and a writer task
//! (frame + coalesce), and the reply-correlation registry. It knows nothing wire-specific: a
//! [`ProtocolRuntime`] supplies the framing + envelope, and **optional capability traits**
//! ([`Negotiates`], [`Authenticates`], [`GracefulClose`], …) each unlock one engine method via
//! `impl<P: Cap>` — so a protocol implements only the capabilities it has (mirroring the server's
//! `NetworkWire: Wire`). The minimal required seam is just: frame + encode-a-call + classify-a-reply.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use bytes::BytesMut;
use serde_json::value::RawValue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use truenas_rpc::JsonRpcError;

use crate::config::{ClientConfig, Endpoint};
use crate::error::ClientError;
use crate::transport::{connect_endpoint, BoxRead, BoxWrite};

/// Delimit one message in the byte stream — a per-protocol hook (JSON-RPC = a 4-byte length prefix).
pub trait Framing: Send + Sync + 'static {
    /// Pull one complete frame out of `acc` (leaving any trailing partial bytes), or `None` if more
    /// bytes are needed. `Err` on a frame that would exceed `limit`.
    fn take_frame(&self, acc: &mut BytesMut, limit: usize) -> Result<Option<Vec<u8>>, ClientError>;
    /// Append `payload` framed onto `out`.
    fn frame_into(&self, out: &mut Vec<u8>, payload: &[u8]);
}

/// One classified inbound frame. (`Progress`/`Control` arrive with later capabilities.)
pub enum Inbound<P: ProtocolRuntime + ?Sized> {
    /// A reply to a call, correlated by `key`.
    Reply {
        /// The correlation key of the call this replies to.
        key: P::CorrelationKey,
        /// The call's raw result bytes (JSON text or XDR, per the wire), or the server's error.
        result: Result<Vec<u8>, JsonRpcError>,
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

/// The correlation registry behind one `Mutex`: outstanding replies keyed by correlation id, plus
/// the monotonic id source. `next_seq` lives **inside** this lock — the same lock a call must take
/// anyway to register its reply slot — so minting an id adds no second synchronization point (no
/// separate atomic, no random-UUID generation on the send path).
struct Pending<K> {
    map: HashMap<K, ReplyTx>,
    next_seq: u64,
}

/// Shared, task-spanning state: the correlation registry + the writer channel + a closed flag.
struct Shared<P: ProtocolRuntime> {
    pending: Mutex<Pending<P::CorrelationKey>>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    closed: AtomicBool,
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
        let (reader, writer) = connect_endpoint(endpoint, config.tcp_keepalive).await?;
        Ok(Self::spawn(runtime, reader, writer, config))
    }

    fn spawn(
        runtime: P,
        reader: BoxRead,
        writer: BoxWrite,
        config: ClientConfig,
    ) -> (Self, NotificationStream<P::Topic>) {
        let runtime = Arc::new(runtime);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (notif_tx, notif_rx) = mpsc::unbounded_channel::<(P::Topic, Vec<u8>)>();
        let shared = Arc::new(Shared {
            pending: Mutex::new(Pending { map: HashMap::new(), next_seq: 0 }),
            out_tx,
            closed: AtomicBool::new(false),
        });
        let writer_task = tokio::spawn(writer_loop(runtime.clone(), writer, out_rx));
        let recv_task =
            tokio::spawn(recv_loop(runtime.clone(), shared.clone(), reader, config.limit, notif_tx));
        let client = Client { runtime, shared, recv: recv_task, writer: writer_task };
        (client, NotificationStream { rx: notif_rx })
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

    /// Draw the next correlation id and register its reply slot under a **single** acquisition of the
    /// pending lock. The oneshot is allocated *before* the lock (so it isn't held across a malloc);
    /// the id (`next_seq`) is drawn *inside* it, so minting the id needs no separate atomic and no
    /// random-UUID generation — the runtime maps the sequence number to the wire id via an immutable
    /// per-connection prefix.
    fn register(&self) -> (P::CorrelationKey, oneshot::Receiver<Result<Vec<u8>, JsonRpcError>>) {
        let (tx, rx) = oneshot::channel();
        let mut pending = self.shared.lock_pending();
        let seq = pending.next_seq;
        pending.next_seq = seq.wrapping_add(1);
        let key = self.runtime.key_for_seq(seq);
        pending.map.insert(key.clone(), tx);
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
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(ClientError::Closed);
        }
        let (key, rx) = self.register();
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
                        if let Some(tx) = shared.lock_pending().map.remove(&key) {
                            let _ = tx.send(result);
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
}
