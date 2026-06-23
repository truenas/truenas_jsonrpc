//! Per-connection handling: the `$/negotiate` → bound-dispatch state machine and the
//! async I/O pump (port of `connection.py`, minus the raw-fd transfer takeover, which lands
//! in a later phase).
//!
//! The read loop **pipelines**: each bound message's `dispatch` is spawned and the loop keeps
//! reading, so a `$/cancelRequest` can be processed while a long handler runs. All outbound
//! bytes — dispatch replies plus pub/sub notifications pushed in through the session's
//! [`Outbound`] — funnel through one per-connection unbounded channel drained by a writer
//! task, so there is a single ordered writer and backpressure is awaited on the runtime.

use std::sync::Arc;

use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{json, Value};
use tokio::io::{split, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use truenas_jsonrpc::{Dispatched, ErrorCode, JsonRpcProtocol, Outbound, Session};

use crate::framing::{self, FrameError};
use crate::negotiate::{NegotiateParams, NegotiateResult, NEGOTIATE_METHOD};
use crate::peer::Peer;
use crate::server::ServerShared;

const VERSION: &str = "2.0";

/// The per-connection [`Outbound`]: pub/sub + `$/progress` messages the core pushes are
/// enqueued (non-blocking) onto the connection's writer channel. Replaces Python's
/// poll-and-route drain threads — the core is push-based, so the session's sink *is* the
/// connection's queue.
struct ConnOutbound {
    tx: UnboundedSender<Vec<u8>>,
}

impl Outbound for ConnOutbound {
    fn send(&self, message: Vec<u8>) {
        // Unbounded + non-blocking: only fails if the connection (receiver) is gone.
        let _ = self.tx.send(message);
    }
}

/// Drain the outbound channel, framing and writing each payload in order until the channel
/// closes (the connection is shutting down and every sender — the loop plus any in-flight
/// dispatch task — has dropped its handle).
async fn write_loop<W: AsyncWrite + Unpin>(mut w: W, mut rx: UnboundedReceiver<Vec<u8>>) {
    while let Some(payload) = rx.recv().await {
        if w.write_all(&framing::frame(&payload)).await.is_err() {
            break;
        }
        if w.flush().await.is_err() {
            break;
        }
    }
}

/// Serve one accepted connection to completion: negotiate a protocol, then pump dispatch.
pub(crate) async fn serve<S, IO>(stream: IO, peer: Peer, shared: Arc<ServerShared<S>>)
where
    S: Send + Sync + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = split(stream);
    let (out_tx, out_rx) = unbounded_channel::<Vec<u8>>();
    let writer_task = tokio::spawn(write_loop(writer, out_rx));

    let outbound: Arc<dyn Outbound> = Arc::new(ConnOutbound { tx: out_tx.clone() });
    let mut bound: Option<BoundConn<S>> = None;

    loop {
        let msg = match framing::read_message(&mut reader, shared.limit).await {
            Ok(Some(m)) => m,
            Ok(None) => break, // clean EOF
            Err(FrameError::TooLarge { len, limit }) => {
                let _ = out_tx.send(error_envelope(
                    None,
                    ErrorCode::InvalidRequest.code(),
                    "Message too large",
                    Some(json!(format!("frame of {len} bytes exceeds limit of {limit}"))),
                ));
                break;
            }
            Err(FrameError::Io(_)) => break,
        };

        match &bound {
            // BOUND: pipeline the dispatch so the read loop keeps going (cancel-while-busy).
            Some((proto, session)) => {
                let proto = proto.clone();
                let session = session.clone();
                let out_tx = out_tx.clone();
                tokio::spawn(async move {
                    match proto.dispatch(&msg, &session).await {
                        Dispatched::Reply(bytes) => {
                            let _ = out_tx.send(bytes);
                        }
                        Dispatched::Nothing => {}
                        // Raw-fd transfer takeover is a later phase; until then the server
                        // can't drive the handshake, so refuse rather than hang the wire.
                        Dispatched::Transfer(t) => {
                            let _ = out_tx.send(error_envelope(
                                Some(t.request_id()),
                                ErrorCode::RequestFailed.code(),
                                "Request failed",
                                Some(json!("raw-fd transfer is not yet supported by this server")),
                            ));
                        }
                    }
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
        }
    }

    if let Some((proto, session)) = &bound {
        proto.close_session(session);
    }
    // Drop our sender; the writer finishes once every in-flight dispatch task has also
    // dropped its clone (so queued replies still flush before close).
    drop(out_tx);
    let _ = writer_task.await;
}

/// A permissive view of an inbound envelope, enough to drive `$/negotiate`.
#[derive(serde::Deserialize)]
struct Envelope {
    jsonrpc: Option<String>,
    method: Option<String>,
    id: Option<Value>,
    params: Option<Box<RawValue>>,
}

/// A bound connection: the negotiated protocol and its session.
type BoundConn<S> = (Arc<JsonRpcProtocol<S>>, Arc<Session<S>>);

/// A successful `$/negotiate`: the bound protocol, its new session, and the reply bytes.
type Bound<S> = (Arc<JsonRpcProtocol<S>>, Arc<Session<S>>, Vec<u8>);

/// Handle one `$/negotiate` message: validate, bind a named protocol, create the session, and
/// return `(protocol, session, reply-bytes)`; on any failure return the error reply bytes.
fn handle_negotiate<S>(
    msg: &[u8],
    peer: &Peer,
    shared: &ServerShared<S>,
    outbound: &Arc<dyn Outbound>,
) -> Result<Bound<S>, Vec<u8>>
where
    S: Send + Sync + 'static,
{
    let env: Envelope = serde_json::from_slice(msg)
        .map_err(|e| error_envelope(None, ErrorCode::InvalidJson.code(), "Parse error", Some(json!(e.to_string()))))?;
    let rid = env.id.as_ref().and_then(Value::as_str);

    if env.method.as_deref() != Some(NEGOTIATE_METHOD) {
        return Err(error_envelope(
            rid,
            ErrorCode::SessionNotEstablished.code(),
            "negotiate a protocol first",
            None,
        ));
    }
    // `$/negotiate` requires jsonrpc "2.0" and a string id (it always replies).
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

fn error_envelope(id: Option<&str>, code: i32, message: &str, data: Option<Value>) -> Vec<u8> {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    serde_json::to_vec(&json!({ "jsonrpc": VERSION, "error": error, "id": id }))
        .expect("encoding an error envelope cannot fail")
}
