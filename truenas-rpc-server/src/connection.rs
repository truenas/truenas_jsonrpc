//! Per-connection handling — the **Transport** + **Framing** layers (1–2): the `$/negotiate` →
//! bound-dispatch state machine, the async I/O
//! pump, and the raw-fd transfer takeover.
//!
//! Inbound bytes accumulate in a buffer fed by the cancel-safe [`AsyncReadExt::read_buf`];
//! complete length-prefixed frames are extracted from it. The loop `select!`s between reading
//! more bytes and taking a completed dispatch outcome — because `read_buf` is cancel-safe,
//! choosing the outcome branch never drops buffered bytes. Dispatch is **pipelined without a task
//! per request**: each bound message becomes an in-flight future in a [`FuturesUnordered`] set,
//! polled in the same `select!` as the read, so a `$/cancelRequest` is read and dispatched while a
//! prior handler is still running (cancellation is a cooperative flag in the core).
//!
//! All outbound bytes (replies + pub/sub notifications pushed through the session's [`Outbound`])
//! go through one channel drained by a writer task that **coalesces everything queued into one
//! write per burst**; the `WriteHalf` sits behind a mutex so a transfer can gate it. A
//! [`Dispatched::Transfer`] triggers [`run_transfer`], which holds that mutex (no notification
//! interleaves the raw stream), runs the `$/transferReady` → (`$/transferGo`) handshake, hands the
//! blocking fd to the handler's `transfer` callback on a blocking worker, then writes the final
//! response.

use std::future::Future;
use std::io::IoSlice;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{json, Value};
use tokio::io::{split, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio::io::AsyncRead;
use truenas_rpc::{
    Dispatched, ErrorCode, JsonRpcProtocol, Outbound, Session, SessionOrigin, SetupTakeover,
    Transfer, TransferDirection,
};

use crate::negotiate::{NegotiateParams, NegotiateResult, NEGOTIATE_METHOD};
use crate::peer::{set_blocking, Peer, Transport};
use crate::server::ServerShared;
use crate::transfer::ConnFileTransfer;

const VERSION: &str = "2.0";
const TRANSFER_GO_METHOD: &str = "$/transferGo";
const HEADER: usize = 4;

/// The per-connection [`Outbound`]: pub/sub + `$/progress` messages the core pushes are
/// enqueued (non-blocking) onto the connection's writer channel. The core is push-based, so
/// the session's sink *is* the connection's queue.
struct ConnOutbound {
    tx: UnboundedSender<Vec<u8>>,
}

impl Outbound for ConnOutbound {
    fn send(&self, message: Vec<u8>) {
        let _ = self.tx.send(message);
    }
}

/// Build the per-connection [`Outbound`] sink over `tx` — shared by the byte-stream pump and
/// (feature `websocket`) the WebSocket pump.
pub(crate) fn conn_outbound(tx: UnboundedSender<Vec<u8>>) -> Arc<dyn Outbound> {
    Arc::new(ConnOutbound { tx })
}

/// Extract one length-prefixed frame from `acc` if a whole one is buffered: `Ok(Some(body))`,
/// `Ok(None)` if more bytes are needed, `Err(len)` if the declared length exceeds `limit`.
fn take_frame(acc: &mut BytesMut, limit: usize) -> Result<Option<Bytes>, usize> {
    if acc.len() < HEADER {
        return Ok(None);
    }
    let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
    if len > limit {
        return Err(len);
    }
    if acc.len() < HEADER + len {
        return Ok(None);
    }
    let _ = acc.split_to(HEADER); // drop the length prefix
    Ok(Some(acc.split_to(len).freeze()))
}

/// Read frames until one is available (used inside a transfer, which has paused the main
/// loop). `None` on EOF or an oversized frame.
async fn next_frame<IO: AsyncRead + Unpin>(
    reader: &mut ReadHalf<IO>,
    acc: &mut BytesMut,
    limit: usize,
) -> Option<Bytes> {
    loop {
        match take_frame(acc, limit) {
            Ok(Some(frame)) => return Some(frame),
            Ok(None) => {}
            Err(_) => return None,
        }
        match reader.read_buf(acc).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

/// Frame `payload` and write it (with a flush), through `w`.
async fn write_framed<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&crate::framing::frame(payload)).await?;
    w.flush().await
}

/// Drain the outbound channel, **coalescing** every payload already queued into a single
/// `write_all` + `flush` under the shared write mutex, until it closes. Batching cuts the syscall
/// count (one write per *burst* of replies/notifications instead of one per message — each socket
/// write is taxed by the kernel + any LSM/audit hooks), which dominates under pipelining.
///
/// Two invariants are preserved: payloads are written in FIFO order (so framed messages never
/// interleave on the wire), and the channel is awaited (`recv`) **only outside** the write lock —
/// a transfer/passthrough takeover fences the wire by acquiring this same mutex, so blocking on
/// `recv()` while holding it would deadlock the handoff. Inside the lock we only ever `try_recv`.
async fn write_loop<IO: AsyncWrite + Unpin>(
    writer: Arc<Mutex<WriteHalf<IO>>>,
    mut rx: UnboundedReceiver<Vec<u8>>,
) {
    // Reused across bursts so the per-burst gather (`bodies`) and the non-vectored coalesce buffer
    // (`batch`) keep their capacity instead of reallocating on every flush.
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    let mut batch: Vec<u8> = Vec::new();
    while let Some(first) = rx.recv().await {
        // Collect the burst before taking the lock: the first payload (awaited above) plus whatever
        // else is already queued, drained non-blockingly so we never await the channel under lock.
        // Just move the body handles in here — no copy; framing happens at write time below.
        bodies.clear();
        bodies.push(first);
        while let Ok(next) = rx.try_recv() {
            bodies.push(next);
        }
        let mut w = writer.lock().await;
        // Prefer a vectored write — each reply as `[len4][body]` IoSlices in one syscall with **no
        // body copy** — when the socket supports it (plain TCP/Unix, and kTLS, which is a plain
        // socket to us). Userspace TLS reports `is_write_vectored() == false` (it needs one
        // contiguous buffer), so fall back to coalescing into one buffer (one memcpy per reply).
        let wrote = if w.is_write_vectored() {
            write_all_vectored(&mut *w, &bodies).await
        } else {
            batch.clear();
            for body in &bodies {
                crate::framing::frame_into(&mut batch, body);
            }
            w.write_all(&batch).await
        };
        if wrote.is_err() || w.flush().await.is_err() {
            break;
        }
    }
}

/// Write each `body` framed (`[4-byte big-endian length][body]`) in one vectored write, looping on
/// partial writes via [`IoSlice::advance_slices`]. Avoids copying the bodies into one contiguous
/// buffer — the small length headers are the only allocation. Used when the socket reports
/// [`AsyncWrite::is_write_vectored`] (a plain/kTLS socket); FIFO order is the slice order.
async fn write_all_vectored<W: AsyncWrite + Unpin>(
    w: &mut W,
    bodies: &[Vec<u8>],
) -> std::io::Result<()> {
    // The length prefixes need stable storage for the `IoSlice`s to borrow across the writes.
    let headers: Vec<[u8; 4]> = bodies.iter().map(|b| (b.len() as u32).to_be_bytes()).collect();
    let mut slices: Vec<IoSlice<'_>> = Vec::with_capacity(bodies.len() * 2);
    for (header, body) in headers.iter().zip(bodies) {
        slices.push(IoSlice::new(header));
        slices.push(IoSlice::new(body));
    }
    let mut rest: &mut [IoSlice<'_>] = &mut slices;
    while !rest.is_empty() {
        match w.write_vectored(rest).await? {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "write_vectored wrote 0 bytes",
                ))
            }
            n => IoSlice::advance_slices(&mut rest, n),
        }
    }
    Ok(())
}

/// Serve one accepted connection to completion. `transfer_fd` is the connection's socket fd
/// **iff it carries plaintext** (a plain or kTLS connection) — `None` for a userspace-TLS
/// connection, where the fd holds ciphertext and a raw-fd transfer must be refused.
pub(crate) async fn serve<S, IO>(
    stream: IO,
    transfer_fd: Option<RawFd>,
    peer: Peer,
    shared: Arc<ServerShared<S>>,
) where
    S: Send + Sync + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = split(stream);
    let writer = Arc::new(Mutex::new(writer));
    let (out_tx, out_rx) = unbounded_channel::<Vec<u8>>();
    let writer_task = tokio::spawn(write_loop(writer.clone(), out_rx));

    let outbound = conn_outbound(out_tx.clone());
    // In-flight dispatches run concurrently **on this connection task** via `FuturesUnordered` —
    // no per-request `tokio::spawn`, and completions are taken straight out of the set (no separate
    // outcome channel). The set is polled in the `select!` below alongside reading, so a new frame
    // (e.g. `$/cancelRequest`) is still read and dispatched while prior requests are pending. CPU /
    // blocking handlers must be **sync** methods (the core runs those on `spawn_blocking`), so the
    // connection task only ever awaits cheap completions here.
    let mut inflight: FuturesUnordered<DispatchFut> = FuturesUnordered::new();
    let mut bound: Option<BoundConn<S>> = None;
    let mut acc = BytesMut::with_capacity(8 * 1024);

    'conn: loop {
        // Process every whole frame already buffered before awaiting more bytes.
        loop {
            match take_frame(&mut acc, shared.limit) {
                Ok(Some(msg)) => match &bound {
                    // BOUND: pipeline the dispatch as an in-flight future (driven in the `select!`).
                    Some((proto, session)) => {
                        let proto = proto.clone();
                        let session = session.clone();
                        inflight.push(Box::pin(async move { proto.dispatch(&msg, &session).await }));
                    }
                    // AWAIT_NEGOTIATE: bind a protocol (or reply with an error and keep waiting).
                    None => match handle_negotiate(&msg, &peer, &shared, &outbound) {
                        Ok((proto, session, reply)) => {
                            let _ = out_tx.send(reply);
                            bound = Some((proto, session));
                        }
                        Err(reply) => {
                            let _ = out_tx.send(reply);
                        }
                    },
                },
                Ok(None) => break, // need more bytes
                Err(len) => {
                    let _ = out_tx.send(error_envelope(
                        None,
                        ErrorCode::InvalidRequest.code(),
                        "Message too large",
                        Some(json!(format!("frame of {len} bytes exceeds limit of {}", shared.limit))),
                    ));
                    break 'conn;
                }
            }
        }

        tokio::select! {
            read = reader.read_buf(&mut acc) => match read {
                Ok(0) | Err(_) => break 'conn,    // clean EOF or read error
                Ok(_) => {}                        // got bytes; loop to extract frames
            },
            // `, if !inflight.is_empty()` disables this branch when nothing is pending — otherwise
            // `next()` on an empty set resolves to `None` and would spin the loop.
            Some(outcome) = inflight.next(), if !inflight.is_empty() => match outcome {
                Dispatched::Reply(bytes) => {
                    let _ = out_tx.send(bytes);
                }
                Dispatched::Nothing => {}
                // A transfer takes over the connection, handled inline: the main loop is
                // paused for the handshake + blocking handoff. `reader`/`acc` are free here.
                Dispatched::Transfer(t) => {
                    run_transfer(t, &mut reader, &mut acc, &writer, transfer_fd, &peer, shared.limit).await;
                }
                // Passthrough auth: hand the connection fd to the broker. Handled inline (reader
                // paused) like a transfer; the broker conducts the client handshake on the fd.
                Dispatched::Passthrough(takeover) => {
                    run_passthrough(takeover, &writer, transfer_fd, &peer).await;
                }
                // A FULL_ADMIN `$/sessions` listing (the core gated + audited it): assemble the
                // server-wide list by walking every protocol's session registry, then reply.
                Dispatched::Sessions { rid, caller } => {
                    let entries: Vec<Value> =
                        shared.protocols.values().flat_map(|p| p.render_sessions(caller)).collect();
                    let _ = out_tx.send(success_envelope(Some(&rid), &Value::Array(entries)));
                }
            },
        }
    }

    if let Some((proto, session)) = &bound {
        proto.close_session(session);
    }
    // Dropping `inflight` abandons any still-pending dispatches (their replies are discarded — the
    // connection is closing), and dropping `out_tx` lets the writer task drain what's queued + exit.
    drop(inflight);
    drop(out_tx);
    let _ = writer_task.await;
}

/// Drive the raw-fd transfer: gate the writer, run the `$/transferReady` (+ `$/transferGo` for
/// a download) handshake, hand the blocking fd to the `transfer` callback, then write the
/// final response.
async fn run_transfer<IO>(
    t: Transfer,
    reader: &mut ReadHalf<IO>,
    acc: &mut BytesMut,
    writer: &Arc<Mutex<WriteHalf<IO>>>,
    transfer_fd: Option<RawFd>,
    peer: &Peer,
    limit: usize,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // Hold the write mutex for the whole transfer: it is the notification gate (so pub/sub
    // can't interleave the raw stream) and the channel for the framed ready/final messages.
    let mut w = writer.lock().await;

    // A raw-fd transfer needs a plaintext fd: a userspace-TLS connection (ciphertext on the
    // fd) has none, so refuse. Plain and kTLS connections carry plaintext.
    let Some(raw_fd) = transfer_fd else {
        let _ = write_framed(
            &mut *w,
            &error_envelope(
                Some(t.request_id()),
                ErrorCode::RequestFailed.code(),
                "Request failed",
                Some(json!("raw-fd transfer requires a plain or kTLS connection")),
            ),
        )
        .await;
        return;
    };

    // SCM_RIGHTS fd passing is AF_UNIX-only.
    if t.is_fd_pass() && peer.transport != Transport::Unix {
        let _ = write_framed(
            &mut *w,
            &error_envelope(
                Some(t.request_id()),
                ErrorCode::RequestFailed.code(),
                "Request failed",
                Some(json!("fd passing requires an AF_UNIX connection")),
            ),
        )
        .await;
        return;
    }

    if write_framed(&mut *w, t.ready_bytes()).await.is_err() {
        return;
    }

    // A download (server produces) waits for the client's `$/transferGo` before streaming, so
    // the client has paused its own reader and no stream byte is buffered out of reach.
    if t.direction() == TransferDirection::Download {
        let go = next_frame(reader, acc, limit).await;
        if !matches!(&go, Some(bytes) if is_transfer_go(bytes)) {
            let _ = write_framed(
                &mut *w,
                &error_envelope(
                    Some(t.request_id()),
                    ErrorCode::RequestFailed.code(),
                    "Request failed",
                    Some(json!("expected $/transferGo")),
                ),
            )
            .await;
            return;
        }
    }

    // Hand the (now blocking) fd to the `transfer` callback on a blocking worker.
    let rid = t.request_id().to_string();
    let _ = set_blocking(raw_fd, true);
    let ft = ConnFileTransfer { fd: raw_fd };
    let final_bytes = match tokio::task::spawn_blocking(move || t.complete(&ft)).await {
        Ok(bytes) => bytes,
        Err(_panicked) => {
            error_envelope(Some(&rid), ErrorCode::InternalError.code(), "Internal error", None)
        }
    };
    let _ = set_blocking(raw_fd, false);

    let _ = write_framed(&mut *w, &final_bytes).await;
    // `w` (the gate) is released here; the writer task resumes draining notifications.
}

/// Drive a passthrough takeover: gate the writer (the reader is already paused, since this runs
/// inline in the main loop), check the transport, put the fd in blocking mode, and run the
/// hand-off on a blocking worker. The broker conducts the client handshake on the fd and the core
/// commits the verdict (lifecycle + identity); **no reply is written here** — the broker already
/// replied to the client over the fd. Mirrors [`run_transfer`]'s gating.
///
/// Assumes the client waits for its `$/sessionSetup` reply (so no post-setup bytes are buffered in
/// `acc` out of the broker's reach); the broker then owns the fd until it returns its verdict.
async fn run_passthrough<IO>(
    takeover: SetupTakeover,
    writer: &Arc<Mutex<WriteHalf<IO>>>,
    transfer_fd: Option<RawFd>,
    peer: &Peer,
) where
    IO: AsyncWrite + Unpin,
{
    // Hold the write mutex for the whole hand-off: it gates pub/sub so nothing interleaves the
    // broker's client I/O on the shared fd.
    let _gate = writer.lock().await;

    // Passthrough needs a passable plaintext fd (WebSocket / userspace-TLS have none → `transfer_fd`
    // is `None`) *and* a secure transport posture (plain TCP has a fd but no posture). If either is
    // missing, refuse: the session stays unauthenticated (the directive is dropped without committing).
    let Some(raw_fd) = transfer_fd else { return };
    if takeover.hands_off_fd() && peer.posture.is_none() {
        return;
    }

    // The broker does blocking reads/writes on its dup of the fd (a dup shares the open file
    // description, so its status flags too) → put the fd in blocking mode for the hand-off.
    let _ = set_blocking(raw_fd, true);
    let ft = ConnFileTransfer { fd: raw_fd };
    let _ = tokio::task::spawn_blocking(move || takeover.run(&ft)).await;
    let _ = set_blocking(raw_fd, false);
    // `_gate` is released here; the main loop resumes reading the (now authenticated) connection.
}

fn is_transfer_go(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Envelope>(bytes)
        .ok()
        .and_then(|e| e.method)
        .as_deref()
        == Some(TRANSFER_GO_METHOD)
}

/// A permissive view of an inbound envelope, enough to drive `$/negotiate` / `$/transferGo`.
#[derive(serde::Deserialize)]
struct Envelope {
    jsonrpc: Option<String>,
    method: Option<String>,
    id: Option<Value>,
    params: Option<Box<RawValue>>,
}

/// A bound connection: the negotiated protocol and its session.
pub(crate) type BoundConn<S> = (Arc<JsonRpcProtocol<S>>, Arc<Session<S>>);

/// One in-flight dispatch the connection task drives to completion (boxed because every pushed
/// future is the same anonymous `async` block type but unnameable). Its output is the
/// [`Dispatched`] the core produced, handled in the `serve` `select!`.
type DispatchFut = Pin<Box<dyn Future<Output = Dispatched> + Send>>;

/// A successful `$/negotiate`: the bound protocol, its new session, and the reply bytes.
pub(crate) type Bound<S> = (Arc<JsonRpcProtocol<S>>, Arc<Session<S>>, Vec<u8>);

/// Handle one `$/negotiate` message: validate, bind a named protocol, create the session, and
/// return `(protocol, session, reply-bytes)`; on any failure return the error reply bytes.
pub(crate) fn handle_negotiate<S>(
    msg: &[u8],
    peer: &Peer,
    shared: &ServerShared<S>,
    outbound: &Arc<dyn Outbound>,
) -> Result<Bound<S>, Vec<u8>>
where
    S: Send + Sync + 'static,
{
    let env: Envelope = serde_json::from_slice(msg).map_err(|e| {
        error_envelope(None, ErrorCode::InvalidJson.code(), "Parse error", Some(json!(e.to_string())))
    })?;
    let rid = env.id.as_ref().and_then(Value::as_str);

    if env.method.as_deref() != Some(NEGOTIATE_METHOD) {
        return Err(error_envelope(
            rid,
            ErrorCode::SessionNotEstablished.code(),
            "negotiate a protocol first",
            None,
        ));
    }
    if env.jsonrpc.as_deref() != Some(VERSION) || rid.is_none() {
        return Err(error_envelope(
            rid,
            ErrorCode::InvalidRequest.code(),
            "Invalid request",
            Some(json!("$/negotiate needs jsonrpc '2.0' and a string id")),
        ));
    }
    let params: NegotiateParams = match env.params {
        Some(raw) => serde_json::from_str(raw.get()).map_err(|e| {
            error_envelope(rid, ErrorCode::InvalidParams.code(), "Invalid params", Some(json!(e.to_string())))
        })?,
        None => {
            return Err(error_envelope(
                rid,
                ErrorCode::InvalidParams.code(),
                "Invalid params",
                Some(json!("$/negotiate requires a 'protocol'")),
            ))
        }
    };

    let Some(proto) = shared.protocols.get(&params.protocol).cloned() else {
        return Err(error_envelope(
            rid,
            ErrorCode::RequestFailed.code(),
            "Request failed",
            Some(json!({ "reason": "unknown protocol", "available": shared.protocol_names() })),
        ));
    };

    let state = (shared.state_fn)(peer);
    let session = proto.new_session(state, outbound.clone());
    session.set_origin(origin_from_peer(peer)); // surface the connection origin in `$/sessions`
    let result = NegotiateResult {
        protocol: params.protocol,
        server: shared.name.clone(),
        available: shared.protocol_names(),
    };
    let reply = success_envelope(rid, &result);
    Ok((proto, session, reply))
}

/// Derive the connection [`SessionOrigin`] from the peer — surfaced in the `$/sessions` listing.
fn origin_from_peer(peer: &Peer) -> SessionOrigin {
    // A reverse-proxied connection: surface the *real client* the proxy reported, not the proxy's
    // own socket (peer-cred / addr here belong to the proxy). The forwarded origin is set only on a
    // `Proxied` listener by the configured `forwarded_extractor`.
    if let Some(f) = &peer.forwarded {
        return SessionOrigin {
            transport: "proxied",
            remote: Some(f.render()),
            uid: None,
            secure: f.secure,
        };
    }
    SessionOrigin {
        transport: match peer.transport {
            Transport::Unix => "unix",
            Transport::Tcp => "tcp",
        },
        remote: peer.addr.map(|a| a.to_string()),
        uid: peer.ucred.map(|c| c.uid),
        // Confidential over TLS or AF_UNIX local trust (mirrors `Channel::from_peer`).
        secure: peer.transport == Transport::Unix || peer.tls.is_some(),
    }
}

pub(crate) fn success_envelope<T: Serialize>(id: Option<&str>, result: &T) -> Vec<u8> {
    serde_json::to_vec(&json!({ "jsonrpc": VERSION, "result": result, "id": id }))
        .expect("encoding a success reply cannot fail")
}

pub(crate) fn error_envelope(id: Option<&str>, code: i32, message: &str, data: Option<Value>) -> Vec<u8> {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    serde_json::to_vec(&json!({ "jsonrpc": VERSION, "error": error, "id": id }))
        .expect("encoding an error envelope cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Poll};

    /// An `AsyncWrite` that accepts at most `chunk` bytes per (vectored) write and records all bytes
    /// written — to exercise `write_all_vectored`'s partial-write loop, framing, and FIFO order.
    struct ChunkWriter {
        out: Vec<u8>,
        chunk: usize,
    }

    impl AsyncWrite for ChunkWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let n = buf.len().min(this.chunk);
            this.out.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            // Emulate a real vectored write that may stop early: write at most `chunk` bytes total.
            let this = self.get_mut();
            let mut remaining = this.chunk;
            let mut written = 0;
            for s in bufs {
                if remaining == 0 {
                    break;
                }
                let n = s.len().min(remaining);
                this.out.extend_from_slice(&s[..n]);
                written += n;
                remaining -= n;
            }
            Poll::Ready(Ok(written))
        }
        fn is_write_vectored(&self) -> bool {
            true
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn vectored_write_frames_each_body_in_fifo_order_across_partial_writes() {
        let bodies = vec![b"hello".to_vec(), Vec::new(), b"world!".to_vec()];
        // chunk=3 forces repeated short vectored writes, exercising the advance_slices loop and an
        // empty-body frame.
        let mut w = ChunkWriter { out: Vec::new(), chunk: 3 };
        write_all_vectored(&mut w, &bodies).await.unwrap();
        // Each body framed `[len4][body]`, concatenated in order — identical to the coalescing path.
        let mut expected = Vec::new();
        for body in &bodies {
            crate::framing::frame_into(&mut expected, body);
        }
        assert_eq!(w.out, expected);
    }

    /// An `AsyncRead`+`AsyncWrite` that records everything written into a shared buffer, so a
    /// spawned `write_loop` can be inspected after it runs. `vectored` selects which reuse path the
    /// loop exercises: `false` → the coalescing `batch` buffer, `true` → the `bodies` gather.
    struct Recorder {
        out: Arc<std::sync::Mutex<Vec<u8>>>,
        vectored: bool,
    }

    impl AsyncRead for Recorder {
        // `write_loop` only writes; the read half is dropped, so this is never polled.
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.out.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            let mut out = self.out.lock().unwrap();
            let mut n = 0;
            for s in bufs {
                out.extend_from_slice(s);
                n += s.len();
            }
            Poll::Ready(Ok(n))
        }
        fn is_write_vectored(&self) -> bool {
            self.vectored
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// `write_loop` reuses its `bodies`/`batch` buffers across bursts (kept for capacity). Drive a
    /// LARGE burst, wait until it is fully on the wire, then a TINY burst — and assert the wire bytes
    /// are exactly `framed(large…) ++ framed(tiny)`: no tail of the large burst leaks into the small
    /// one (the stale-data risk the reuse introduces). A missing/misplaced `clear()` makes the small
    /// burst carry the large burst's bytes, which this catches.
    async fn write_loop_burst_reuse(vectored: bool) {
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (_read, w) = split(Recorder { out: out.clone(), vectored });
        let writer = Arc::new(Mutex::new(w));
        let (tx, rx) = unbounded_channel::<Vec<u8>>();

        // Burst 1: four 500-byte payloads queued before the loop runs → drained into one burst,
        // growing the reused buffers to ~2 KiB.
        let big: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 500]).collect();
        for b in &big {
            tx.send(b.clone()).unwrap();
        }
        let task = tokio::spawn(write_loop(writer, rx));

        // Wait until burst 1 is fully on the wire, so burst 2 is a SEPARATE burst that must shrink
        // the reused buffers back down.
        let big_len: usize = big.iter().map(|b| HEADER + b.len()).sum();
        let mut spun = 0;
        while out.lock().unwrap().len() < big_len {
            tokio::task::yield_now().await;
            spun += 1;
            assert!(spun < 100_000, "burst 1 never flushed");
        }
        assert_eq!(out.lock().unwrap().len(), big_len, "burst 1 should be exactly its framed length");

        // Burst 2: a single 3-byte payload. A stale tail of burst 1 would surface here.
        let small = vec![0xABu8; 3];
        tx.send(small.clone()).unwrap();
        drop(tx); // close → the loop exits after burst 2
        task.await.unwrap();

        let mut expected = Vec::new();
        for b in &big {
            crate::framing::frame_into(&mut expected, b);
        }
        crate::framing::frame_into(&mut expected, &small);
        assert_eq!(
            *out.lock().unwrap(),
            expected,
            "vectored={vectored}: bytes from the large burst leaked into the small one"
        );
    }

    #[tokio::test]
    async fn write_loop_reuses_buffers_without_leaking_a_stale_tail() {
        write_loop_burst_reuse(false).await; // non-vectored: the coalescing `batch` buffer
        write_loop_burst_reuse(true).await; // vectored: the `bodies` gather
    }
}
