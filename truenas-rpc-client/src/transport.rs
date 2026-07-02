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

/// Connect `endpoint` and return its split read/write halves plus an **optional** raw socket fd. The
/// fd — present only when the transport carries a **plaintext byte stream** the connection keeps open
/// (AF_UNIX / plain TCP) — is what a raw-fd transfer pauses the reader and lends to a blocking
/// handler. It is `None` for transports where no plaintext fd is exposed (userspace TLS carries
/// ciphertext; WebSocket's wire is owned by its library), so a `transfer` over them is refused — this
/// mirrors the reference client's per-channel `transfer_target`. `tcp_keepalive` (TCP only) arms
/// `SO_KEEPALIVE` with that idle time, so a crashed/partitioned peer is detected in bounded time
/// **regardless of how long any call runs** — the liveness signal we rely on instead of a per-call
/// duration scavenger. AF_UNIX needs none: local peer death surfaces as EOF on the next read.
pub async fn connect_endpoint(
    endpoint: &Endpoint,
    tcp_keepalive: Option<Duration>,
) -> std::io::Result<(BoxRead, BoxWrite, Option<RawFd>)> {
    match endpoint {
        Endpoint::Unix(path) => {
            let stream = UnixStream::connect(path).await?;
            let fd = stream.as_raw_fd();
            let (r, w) = stream.into_split();
            Ok((Box::new(r), Box::new(w), Some(fd)))
        }
        Endpoint::Tcp(addr) => {
            let stream = connect_tcp(addr, tcp_keepalive).await?;
            let fd = stream.as_raw_fd();
            let (r, w) = stream.into_split();
            Ok((Box::new(r), Box::new(w), Some(fd)))
        }
        // Direct kTLS: handshake in userspace (a socket BIO + a `getsockopt` kTLS probe — both
        // blocking, so off the reactor), then run the whole connection over the raw kernel-encrypted
        // fd. Plaintext to us → transfer-capable, so `Some(fd)`.
        #[cfg(feature = "tls")]
        Endpoint::Tls { addr, server_name, tls } => {
            let std_tcp = connect_tcp(addr, tcp_keepalive).await?.into_std()?;
            let tls = tls.clone();
            let server_name = server_name.clone();
            let std_tcp =
                tokio::task::spawn_blocking(move || crate::tls::ktls_connect(&tls, &server_name, std_tcp))
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))??;
            std_tcp.set_nonblocking(true)?;
            let fd = std_tcp.as_raw_fd();
            let (r, w) = TcpStream::from_std(std_tcp)?.into_split();
            Ok((Box::new(r), Box::new(w), Some(fd)))
        }
    }
}

/// Connect a TCP stream with `TCP_NODELAY` and optional keep-alive — the shared prelude for plain TCP
/// and (behind features) the TLS / WebSocket transports that layer over a TCP connection.
pub(crate) async fn connect_tcp(
    addr: &str,
    tcp_keepalive: Option<Duration>,
) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    if let Some(idle) = tcp_keepalive {
        let _ = SockRef::from(&stream).set_tcp_keepalive(&TcpKeepalive::new().with_time(idle));
    }
    Ok(stream)
}
