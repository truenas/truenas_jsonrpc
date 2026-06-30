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

/// A call encoded to its (unframed) wire bytes, plus the correlation key its reply will arrive under.
pub struct EncodedCall<K> {
    /// The unframed call body (the writer task frames it).
    pub wire: Vec<u8>,
    /// The key the reply correlates on.
    pub key: K,
}

/// One classified inbound frame. (`Progress`/`Control` arrive with later capabilities.)
pub enum Inbound<P: ProtocolRuntime + ?Sized> {
    /// A reply to a call, correlated by `key`.
    Reply {
        /// The correlation key of the call this replies to.
        key: P::CorrelationKey,
        /// The call's result bytes, or the error the server returned.
        result: Result<Box<RawValue>, JsonRpcError>,
    },
    /// A server→client notification on `topic`.
    Notification {
        /// The topic (e.g. a method name).
        topic: P::Topic,
        /// The notification payload.
        payload: Box<RawValue>,
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
    /// Encode a call and allocate the correlation key its reply will arrive under.
    fn encode_call(
        &self,
        method: &Self::MethodKey,
        params: Option<&RawValue>,
    ) -> EncodedCall<Self::CorrelationKey>;
    /// Classify one inbound frame (the engine never inspects bytes itself).
    fn parse_inbound(&self, frame: &[u8]) -> Result<Inbound<Self>, ClientError>;
}

type ReplyTx = oneshot::Sender<Result<Box<RawValue>, JsonRpcError>>;

/// Shared, task-spanning state: the correlation registry + the writer channel + a closed flag.
struct Shared<P: ProtocolRuntime> {
    pending: Mutex<HashMap<P::CorrelationKey, ReplyTx>>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    closed: AtomicBool,
}

impl<P: ProtocolRuntime> Shared<P> {
    fn lock_pending(&self) -> std::sync::MutexGuard<'_, HashMap<P::CorrelationKey, ReplyTx>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// An async stream of server→client notifications, `(topic, payload)`.
pub struct NotificationStream<T> {
    rx: mpsc::UnboundedReceiver<(T, Box<RawValue>)>,
}

impl<T> NotificationStream<T> {
    /// The next notification, or `None` once the connection is gone.
    pub async fn recv(&mut self) -> Option<(T, Box<RawValue>)> {
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
    config: ClientConfig,
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
        let (reader, writer) = connect_endpoint(endpoint).await?;
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
        let (notif_tx, notif_rx) = mpsc::unbounded_channel::<(P::Topic, Box<RawValue>)>();
        let shared = Arc::new(Shared {
            pending: Mutex::new(HashMap::new()),
            out_tx,
            closed: AtomicBool::new(false),
        });
        let writer_task = tokio::spawn(writer_loop(runtime.clone(), writer, out_rx));
        let recv_task =
            tokio::spawn(recv_loop(runtime.clone(), shared.clone(), reader, config.limit, notif_tx));
        let client = Client { runtime, shared, recv: recv_task, writer: writer_task, config };
        (client, NotificationStream { rx: notif_rx })
    }

    /// Send one method call and await its reply. The codegen-facing typed methods build on this.
    pub async fn call(
        &self,
        method: &P::MethodKey,
        params: Option<&RawValue>,
    ) -> Result<Box<RawValue>, ClientError> {
        let enc = self.runtime.encode_call(method, params);
        self.send(enc).await
    }

    /// The one correlated round-trip: register the pending reply **before** writing (race-free), then
    /// await the oneshot (with a timeout). A timeout/close removes the pending entry.
    async fn send(
        &self,
        enc: EncodedCall<P::CorrelationKey>,
    ) -> Result<Box<RawValue>, ClientError> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(ClientError::Closed);
        }
        let key = enc.key.clone();
        let (tx, rx) = oneshot::channel();
        self.shared.lock_pending().insert(key.clone(), tx);
        if self.shared.out_tx.send(enc.wire).is_err() {
            self.shared.lock_pending().remove(&key);
            return Err(ClientError::Closed);
        }
        match tokio::time::timeout(self.config.call_timeout, rx).await {
            Ok(Ok(result)) => result.map_err(ClientError::Rpc),
            Ok(Err(_recv)) => Err(ClientError::Closed), // sender dropped → connection gone
            Err(_timeout) => {
                self.shared.lock_pending().remove(&key);
                Err(ClientError::Timeout)
            }
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
    while let Some(first) = out_rx.recv().await {
        let mut batch = Vec::with_capacity(first.len() + 4);
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
    notif_tx: mpsc::UnboundedSender<(P::Topic, Box<RawValue>)>,
) {
    let mut acc = BytesMut::with_capacity(8 * 1024);
    'outer: loop {
        // Drain every complete frame currently buffered.
        loop {
            match runtime.framing().take_frame(&mut acc, limit) {
                Ok(Some(frame)) => match runtime.parse_inbound(&frame) {
                    Ok(Inbound::Reply { key, result }) => {
                        if let Some(tx) = shared.lock_pending().remove(&key) {
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
    shared.lock_pending().clear();
}

// --- Optional capabilities (each unlocks one engine method) ------------------------------------

/// A protocol that binds itself with a `$/negotiate`-style handshake.
pub trait Negotiates: ProtocolRuntime {
    /// The decoded negotiate result.
    type Negotiated: serde::de::DeserializeOwned;
    /// Encode the negotiate request for `protocol`.
    fn encode_negotiate(&self, protocol: &str) -> EncodedCall<Self::CorrelationKey>;
}

impl<P: Negotiates> Client<P> {
    /// Bind a named protocol (the `$/negotiate` handshake).
    pub async fn negotiate(&self, protocol: &str) -> Result<P::Negotiated, ClientError> {
        let raw = self.send(self.runtime.encode_negotiate(protocol)).await?;
        serde_json::from_str(raw.get()).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// A protocol with a session-setup (authentication) handshake.
pub trait Authenticates: ProtocolRuntime {
    /// Encode `$/sessionSetup`.
    fn encode_setup(&self, params: Option<&RawValue>) -> EncodedCall<Self::CorrelationKey>;
    /// Encode `$/sessionSetupContinue` (multi-step auth).
    fn encode_setup_continue(&self, params: Option<&RawValue>) -> EncodedCall<Self::CorrelationKey>;
}

impl<P: Authenticates> Client<P> {
    /// Run the session-setup handshake; returns the setup result.
    pub async fn authenticate(
        &self,
        params: Option<&RawValue>,
    ) -> Result<Box<RawValue>, ClientError> {
        self.send(self.runtime.encode_setup(params)).await
    }
    /// Continue a multi-step session setup.
    pub async fn authenticate_continue(
        &self,
        params: Option<&RawValue>,
    ) -> Result<Box<RawValue>, ClientError> {
        self.send(self.runtime.encode_setup_continue(params)).await
    }
}

/// A protocol with a graceful close (`$/sessionClose`).
pub trait GracefulClose: ProtocolRuntime {
    /// Encode the close request.
    fn encode_close(&self) -> EncodedCall<Self::CorrelationKey>;
}

impl<P: GracefulClose> Client<P> {
    /// Close the session gracefully (best-effort), then tear the connection down.
    pub async fn close(self) -> Result<(), ClientError> {
        let _ = self.send(self.runtime.encode_close()).await;
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
