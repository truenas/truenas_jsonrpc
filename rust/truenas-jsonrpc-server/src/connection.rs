//! Per-connection handling: the `$/negotiate` → bound-dispatch state machine, the async I/O
//! pump, and the raw-fd transfer takeover (port of `connection.py`).
//!
//! Inbound bytes accumulate in a buffer fed by the cancel-safe [`AsyncReadExt::read_buf`];
//! complete length-prefixed frames are extracted from it. The loop `select!`s between reading
//! more bytes and receiving a completed dispatch outcome — because `read_buf` is cancel-safe,
//! choosing the outcome branch never drops buffered bytes. Dispatch is **pipelined**: each
//! bound message is spawned and its [`Dispatched`] returns over a channel, so a
//! `$/cancelRequest` is read while a long handler runs.
//!
//! All outbound bytes (replies + pub/sub notifications pushed through the session's
//! [`Outbound`]) go through one channel drained by a writer task; the `WriteHalf` sits behind
//! a mutex so a transfer can gate it. A [`Dispatched::Transfer`] triggers [`run_transfer`],
//! which holds that mutex (no notification interleaves the raw stream), runs the
//! `$/transferReady` → (`$/transferGo`) handshake, hands the blocking fd to the handler's
//! `transfer` callback on a blocking worker, then writes the final response.

use std::os::fd::RawFd;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{json, Value};
use tokio::io::{split, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio::io::AsyncRead;
use truenas_jsonrpc::{
    Dispatched, ErrorCode, JsonRpcProtocol, Outbound, Session, Transfer, TransferDirection,
};

use crate::negotiate::{NegotiateParams, NegotiateResult, NEGOTIATE_METHOD};
use crate::peer::{set_blocking, Peer, Transport};
use crate::server::ServerShared;
use crate::transfer::ConnFileTransfer;

const VERSION: &str = "2.0";
const TRANSFER_GO_METHOD: &str = "$/transferGo";
const HEADER: usize = 4;

/// The per-connection [`Outbound`]: pub/sub + `$/progress` messages the core pushes are
/// enqueued (non-blocking) onto the connection's writer channel. Replaces Python's
/// poll-and-route drain threads — the core is push-based, so the session's sink *is* the
/// connection's queue.
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

/// Drain the outbound channel, writing each payload in order under the shared write mutex (so
/// a transfer in progress, which holds that mutex, pauses notifications), until it closes.
async fn write_loop<IO: AsyncWrite + Unpin>(
    writer: Arc<Mutex<WriteHalf<IO>>>,
    mut rx: UnboundedReceiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        let mut w = writer.lock().await;
        if write_framed(&mut *w, &payload).await.is_err() {
            break;
        }
    }
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
    let (outcome_tx, mut outcome_rx) = unbounded_channel::<Dispatched>();
    let mut bound: Option<BoundConn<S>> = None;
    let mut acc = BytesMut::with_capacity(8 * 1024);

    'conn: loop {
        // Process every whole frame already buffered before awaiting more bytes.
        loop {
            match take_frame(&mut acc, shared.limit) {
                Ok(Some(msg)) => match &bound {
                    // BOUND: pipeline the dispatch; its outcome returns over `outcome_tx`.
                    Some((proto, session)) => {
                        let proto = proto.clone();
                        let session = session.clone();
                        let outcome_tx = outcome_tx.clone();
                        tokio::spawn(async move {
                            let _ = outcome_tx.send(proto.dispatch(&msg, &session).await);
                        });
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
            Some(outcome) = outcome_rx.recv() => match outcome {
                Dispatched::Reply(bytes) => {
                    let _ = out_tx.send(bytes);
                }
                Dispatched::Nothing => {}
                // A transfer takes over the connection, handled inline: the main loop is
                // paused for the handshake + blocking handoff. `reader`/`acc` are free here.
                Dispatched::Transfer(t) => {
                    run_transfer(t, &mut reader, &mut acc, &writer, transfer_fd, &peer, shared.limit).await;
                }
            },
        }
    }

    if let Some((proto, session)) = &bound {
        proto.close_session(session);
    }
    drop(out_tx);
    drop(outcome_tx);
    let _ = writer_task.await;
}

/// Drive the raw-fd transfer: gate the writer, run the `$/transferReady` (+ `$/transferGo` for
/// a download) handshake, hand the blocking fd to the `transfer` callback, then write the
/// final response. Mirrors Python's `_run_transfer`.
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
    let result = NegotiateResult {
        protocol: params.protocol,
        server: shared.name.clone(),
        available: shared.protocol_names(),
    };
    let reply = success_envelope(rid, &result);
    Ok((proto, session, reply))
}

fn success_envelope<T: Serialize>(id: Option<&str>, result: &T) -> Vec<u8> {
    serde_json::to_vec(&json!({ "jsonrpc": VERSION, "result": result, "id": id }))
        .expect("encoding a negotiate reply cannot fail")
}

pub(crate) fn error_envelope(id: Option<&str>, code: i32, message: &str, data: Option<Value>) -> Vec<u8> {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    serde_json::to_vec(&json!({ "jsonrpc": VERSION, "error": error, "id": id }))
        .expect("encoding an error envelope cannot fail")
}
