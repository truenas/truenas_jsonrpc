//! Byte-stream transports (AF_UNIX + TCP). The concrete stream is split into owned read/write halves
//! at connect time, each boxed as a trait object — so the engine is generic over the *protocol*, not
//! the transport. TLS / WebSocket arrive behind features later (mirroring the server).

use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

use crate::config::Endpoint;

/// The owned read half of a connection (boxed so any transport fits one type).
pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
/// The owned write half of a connection.
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// Connect `endpoint` and return its split read/write halves **plus the raw socket fd**. The fd is
/// retained (the split halves keep it open) so a raw-fd transfer can pause the reader and hand the
/// blocking fd to a handler; it is plaintext here (no userspace TLS yet). `tcp_keepalive` (TCP only)
/// arms `SO_KEEPALIVE` with that idle time, so a crashed/partitioned peer is detected in bounded time
/// **regardless of how long any call runs** — the liveness signal we rely on instead of a per-call
/// duration scavenger. AF_UNIX needs none: local peer death surfaces as EOF on the next read.
pub async fn connect_endpoint(
    endpoint: &Endpoint,
    tcp_keepalive: Option<Duration>,
) -> std::io::Result<(BoxRead, BoxWrite, RawFd)> {
    match endpoint {
        Endpoint::Unix(path) => {
            let stream = UnixStream::connect(path).await?;
            let fd = stream.as_raw_fd();
            let (r, w) = stream.into_split();
            Ok((Box::new(r), Box::new(w), fd))
        }
        Endpoint::Tcp(addr) => {
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            if let Some(idle) = tcp_keepalive {
                let _ = SockRef::from(&stream).set_tcp_keepalive(&TcpKeepalive::new().with_time(idle));
            }
            let fd = stream.as_raw_fd();
            let (r, w) = stream.into_split();
            Ok((Box::new(r), Box::new(w), fd))
        }
    }
}
