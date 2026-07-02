//! WebSocket client transport (the opt-in `websocket` feature), over `tokio-tungstenite` — the mirror
//! of the server's `ws` module. Each JSON-RPC frame is carried as **one WebSocket message** (the wire
//! has no length prefix; WebSocket message boundaries delimit frames), so the transport is
//! message-oriented rather than a byte stream.
//!
//! The engine, however, is written against a byte stream + length-prefix [`Framing`](crate::Framing).
//! [`WsRead`] / [`WsWrite`] bridge the two: on read, each inbound message is handed to the engine with
//! a **locally synthesized** 4-byte length prefix (so `take_frame` sees a well-formed frame); on
//! write, the engine's length-prefixed bytes are split back into frames and each frame body is sent as
//! one message. The length prefix is a purely local convention between the adapter and the engine — it
//! never appears on the WebSocket wire, so this interoperates with the server's message-per-frame `ws`.
//!
//! WebSocket owns the wire (framing lives in the library), so there is no plaintext fd to lend: a
//! raw-fd transfer is refused on these connections (`transfer_fd` is `None`).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

use crate::transport::{connect_tcp, BoxRead, BoxWrite};

/// The 4-byte big-endian length prefix the engine's [`LengthPrefix`](crate::LengthPrefix) framing uses.
const HEADER: usize = 4;

type BoxedSink = Pin<Box<dyn Sink<Message, Error = WsError> + Send>>;
type BoxedStream = Pin<Box<dyn Stream<Item = Result<Message, WsError>> + Send>>;

/// Connect plain `ws://addr{path}` over TCP; returns the engine's read/write halves.
pub(crate) async fn connect_ws(
    addr: &str,
    path: &str,
    tcp_keepalive: Option<std::time::Duration>,
) -> io::Result<(BoxRead, BoxWrite)> {
    let tcp = connect_tcp(addr, tcp_keepalive).await?;
    let (ws, _resp) =
        tokio_tungstenite::client_async(format!("ws://{addr}{path}"), tcp).await.map_err(ws_io)?;
    Ok(split_ws(ws))
}

/// Connect a WebSocket over the AF_UNIX socket at `path` — the `nginx → ws-over-unix → app` path. A
/// unix socket has no host, so the handshake uses a nominal `ws://localhost/` request line.
pub(crate) async fn connect_ws_unix(path: &std::path::Path) -> io::Result<(BoxRead, BoxWrite)> {
    let unix = tokio::net::UnixStream::connect(path).await?;
    let (ws, _resp) =
        tokio_tungstenite::client_async("ws://localhost/", unix).await.map_err(ws_io)?;
    Ok(split_ws(ws))
}

/// Connect `wss://` — a **userspace** TLS handshake (the WebSocket library owns the stream, so kTLS's
/// detached fd doesn't apply), then the WebSocket handshake over it. The `Host` header uses
/// `server_name` (the certificate hostname).
#[cfg(feature = "tls")]
pub(crate) async fn connect_wss(
    tls: &crate::tls::ClientTls,
    addr: &str,
    server_name: &str,
    path: &str,
    tcp_keepalive: Option<std::time::Duration>,
) -> io::Result<(BoxRead, BoxWrite, Option<Vec<u8>>)> {
    let tcp = connect_tcp(addr, tcp_keepalive).await?;
    let (tls_stream, binding) = crate::tls::userspace_connect(tls, server_name, tcp).await?;
    let (ws, _resp) = tokio_tungstenite::client_async(format!("wss://{server_name}{path}"), tls_stream)
        .await
        .map_err(ws_io)?;
    let (r, w) = split_ws(ws);
    Ok((r, w, binding))
}

/// Split a handshaked WebSocket into the engine's boxed read/write halves.
fn split_ws<S>(ws: WebSocketStream<S>) -> (BoxRead, BoxWrite)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    let read = WsRead { stream: Box::pin(stream), pending: Vec::new(), pos: 0 };
    let write = WsWrite { sink: Box::pin(sink), inbuf: Vec::new(), staged: None };
    (Box::new(read), Box::new(write))
}

/// [`AsyncRead`] over the inbound message stream: each message is delivered to the engine framed with a
/// locally synthesized length prefix.
struct WsRead {
    stream: BoxedStream,
    // The current `[len][body]` bytes being handed to the engine, and how far we've copied.
    pending: Vec<u8>,
    pos: usize,
}

impl AsyncRead for WsRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        loop {
            if me.pos < me.pending.len() {
                let n = std::cmp::min(buf.remaining(), me.pending.len() - me.pos);
                buf.put_slice(&me.pending[me.pos..me.pos + n]);
                me.pos += n;
                return Poll::Ready(Ok(()));
            }
            match me.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Text(t)))) => {
                    me.pending = framed(t.into_bytes());
                    me.pos = 0;
                }
                Poll::Ready(Some(Ok(Message::Binary(b)))) => {
                    me.pending = framed(b);
                    me.pos = 0;
                }
                // Close / stream end / error → EOF (Ready with the buffer unfilled = 0 bytes read).
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(Some(Err(_)))
                | Poll::Ready(None) => return Poll::Ready(Ok(())),
                // Ping / Pong / raw frame — not application data; poll again.
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// [`AsyncWrite`] over the outbound message sink: the engine's length-prefixed bytes are split back
/// into frames and each frame body is sent as one WebSocket message.
struct WsWrite {
    sink: BoxedSink,
    // Length-prefixed bytes from the engine not yet turned into messages.
    inbuf: Vec<u8>,
    // A message extracted but not yet accepted by the sink (it returned `Pending`).
    staged: Option<Message>,
}

impl WsWrite {
    /// Feed as many complete frames as the sink accepts. `Pending` means the sink is full (its waker is
    /// registered); `Ready(Ok)` means we've caught up to a frame boundary.
    fn pump(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.staged.is_none() {
                if self.inbuf.len() < HEADER {
                    return Poll::Ready(Ok(()));
                }
                let len = u32::from_be_bytes([self.inbuf[0], self.inbuf[1], self.inbuf[2], self.inbuf[3]])
                    as usize;
                if self.inbuf.len() < HEADER + len {
                    return Poll::Ready(Ok(()));
                }
                let body = self.inbuf[HEADER..HEADER + len].to_vec();
                self.inbuf.drain(0..HEADER + len);
                self.staged = Some(message_for(body));
            }
            match self.sink.as_mut().poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let msg = self.staged.take().expect("staged set above");
                    self.sink.as_mut().start_send(msg).map_err(ws_io)?;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(ws_io(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        me.inbuf.extend_from_slice(data);
        // `data` is buffered regardless; a `Pending` pump completes on the next `poll_flush`.
        match me.pump(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(data.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        match me.pump(cx) {
            Poll::Ready(Ok(())) => match me.sink.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(ws_io(e))),
                Poll::Pending => Poll::Pending,
            },
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        match me.pump(cx) {
            Poll::Ready(Ok(())) => match me.sink.as_mut().poll_close(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(ws_io(e))),
                Poll::Pending => Poll::Pending,
            },
            other => other,
        }
    }
}

/// Prepend the engine's 4-byte length prefix to a message body.
fn framed(body: Vec<u8>) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER + body.len());
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(&body);
    v
}

/// One outbound WebSocket message for a frame body — text for UTF-8 JSON, binary otherwise (the XDR
/// sub-wire); the server accepts either. Mirrors the server's `ws` writer.
fn message_for(body: Vec<u8>) -> Message {
    match String::from_utf8(body) {
        Ok(text) => Message::Text(text),
        Err(e) => Message::Binary(e.into_bytes()),
    }
}

fn ws_io(e: WsError) -> io::Error {
    io::Error::other(e)
}
