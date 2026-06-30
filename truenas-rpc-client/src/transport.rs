//! Byte-stream transports (AF_UNIX + TCP). The concrete stream is split into owned read/write halves
//! at connect time, each boxed as a trait object — so the engine is generic over the *protocol*, not
//! the transport. TLS / WebSocket arrive behind features later (mirroring the server).

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

use crate::config::Endpoint;

/// The owned read half of a connection (boxed so any transport fits one type).
pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
/// The owned write half of a connection.
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// Connect `endpoint` and return its split read/write halves.
pub async fn connect_endpoint(endpoint: &Endpoint) -> std::io::Result<(BoxRead, BoxWrite)> {
    match endpoint {
        Endpoint::Unix(path) => {
            let (r, w) = UnixStream::connect(path).await?.into_split();
            Ok((Box::new(r), Box::new(w)))
        }
        Endpoint::Tcp(addr) => {
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            let (r, w) = stream.into_split();
            Ok((Box::new(r), Box::new(w)))
        }
    }
}
