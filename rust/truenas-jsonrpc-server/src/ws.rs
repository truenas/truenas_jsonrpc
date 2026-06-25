//! WebSocket transport (the opt-in `websocket` feature) — JSON-RPC framed as WebSocket
//! messages (`ws://`), via `tokio-tungstenite`. Mirrors Python's optional `websockets` extra.
//!
//! Each inbound WebSocket message is one JSON-RPC frame; replies/notifications are sent as text
//! messages. The negotiate + dispatch logic is shared with the byte-stream pump
//! ([`connection::handle_negotiate`] / [`connection::conn_outbound`]). Raw-fd transfer is
//! **refused** on a WebSocket connection — the library owns the wire, so there's no plaintext
//! fd to hand off.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::mpsc::unbounded_channel;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use truenas_jsonrpc::{Dispatched, ErrorCode};

use crate::connection::{self, BoundConn};
use crate::peer::Peer;
use crate::server::{JsonRpcServer, ServerShared};

impl<S: Send + Sync + 'static> JsonRpcServer<S> {
    /// Accept WebSocket connections on a bound TCP `listener` until an accept error occurs. A
    /// failed WebSocket handshake drops just that connection.
    pub async fn serve_websocket_listener(&self, listener: TcpListener) -> std::io::Result<()> {
        self.require_network_auth()?;
        loop {
            let (tcp, addr) = listener.accept().await?;
            let _ = tcp.set_nodelay(true);
            let shared = self.shared.clone();
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                serve_ws(ws, Peer::tcp(addr), shared).await;
            });
        }
    }

    /// Bind a TCP `addr` and serve WebSocket on it (bind + accept loop). Runs forever on the
    /// happy path — spawn it to run alongside other transports.
    pub async fn serve_websocket(&self, addr: impl ToSocketAddrs) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve_websocket_listener(listener).await
    }
}

#[cfg(feature = "tls")]
impl<S: Send + Sync + 'static> JsonRpcServer<S> {
    /// Accept WebSocket-over-TLS (`wss://`) connections on a bound TCP `listener` until an
    /// accept error occurs. The TLS handshake is **userspace** (the WebSocket library owns the
    /// stream, so kTLS doesn't apply); raw-fd transfer is refused on these connections. The
    /// [`TlsConfig`](crate::TlsConfig)'s mode is ignored here — always userspace.
    pub async fn serve_wss_listener(
        &self,
        listener: TcpListener,
        tls: crate::tls::TlsConfig,
    ) -> std::io::Result<()> {
        self.require_network_auth()?;
        let acceptor = tls.acceptor();
        loop {
            let (tcp, addr) = listener.accept().await?;
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let shared = self.shared.clone();
            tokio::spawn(async move {
                let Some(tls_stream) = crate::tls::userspace_accept(&acceptor, tcp).await else {
                    return;
                };
                // Surface the verified client cert + channel binding before the WS handshake consumes the stream.
                let (cert, binding) = crate::tls::tls_facts(tls_stream.ssl());
                let Ok(ws) = tokio_tungstenite::accept_async(tls_stream).await else { return };
                serve_ws(ws, crate::tls::tls_peer(addr, cert, binding), shared).await;
            });
        }
    }

    /// Bind a TCP `addr` and serve `wss://` on it (bind + accept loop). Runs forever on the
    /// happy path — spawn it to run alongside other transports.
    pub async fn serve_wss(
        &self,
        addr: impl ToSocketAddrs,
        tls: crate::tls::TlsConfig,
    ) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve_wss_listener(listener, tls).await
    }
}

/// Serve one WebSocket connection: negotiate, then pump dispatch. Each message is a JSON-RPC
/// frame; replies + pub/sub notifications go out as text messages. Dispatch is pipelined (each
/// frame spawned), so `$/cancelRequest` is read while a handler runs.
async fn serve_ws<S, IO>(ws: WebSocketStream<IO>, peer: Peer, shared: Arc<ServerShared<S>>)
where
    S: Send + Sync + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = ws.split();
    let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();

    // Writer task: each queued JSON frame goes out as one WebSocket text message.
    let writer = tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            let msg = match String::from_utf8(payload) {
                Ok(text) => Message::Text(text),
                Err(e) => Message::Binary(e.into_bytes()),
            };
            if sink.send(msg).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let outbound = connection::conn_outbound(out_tx.clone());
    let mut bound: Option<BoundConn<S>> = None;

    while let Some(msg) = stream.next().await {
        let frame: Vec<u8> = match msg {
            Ok(Message::Text(t)) => t.into_bytes(),
            Ok(Message::Binary(b)) => b,
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue, // ping/pong/frame — tungstenite answers pings itself
        };
        match &bound {
            Some((proto, session)) => {
                let proto = proto.clone();
                let session = session.clone();
                let out_tx = out_tx.clone();
                tokio::spawn(async move {
                    match proto.dispatch(&frame, &session).await {
                        Dispatched::Reply(bytes) => {
                            let _ = out_tx.send(bytes);
                        }
                        Dispatched::Nothing => {}
                        Dispatched::Transfer(t) => {
                            let _ = out_tx.send(connection::error_envelope(
                                Some(t.request_id()),
                                ErrorCode::RequestFailed.code(),
                                "Request failed",
                                Some(json!("raw-fd transfer is not supported over WebSocket")),
                            ));
                        }
                        Dispatched::Passthrough(takeover) => {
                            // No raw fd to hand off under WebSocket framing; refuse (the takeover is
                            // dropped uncommitted, so the session stays unauthenticated).
                            let _ = out_tx.send(connection::error_envelope(
                                takeover.request_id(),
                                ErrorCode::RequestFailed.code(),
                                "Request failed",
                                Some(json!("passthrough authentication is not supported over WebSocket")),
                            ));
                        }
                    }
                });
            }
            None => match connection::handle_negotiate(&frame, &peer, &shared, &outbound) {
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
    drop(out_tx);
    let _ = writer.await;
}
