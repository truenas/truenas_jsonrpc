//! [`BrokerServer`] — the daemon side of passthrough ("authentication as a daemon"): accept
//! hand-offs on an AF_UNIX listener, run a handler over each passed client fd + context, and
//! return its verdict. The handler is where an embedder runs its own authentication (e.g. the same
//! [`AuthStack`](crate::AuthStack) in a server role) over the fd it receives; this type owns only
//! the accept loop + framing.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};

use super::context::{BrokerContext, BrokerVerdict};
use super::protocol;

/// An authentication broker over AF_UNIX. `handler` receives each passed-through client connection
/// (as an [`OwnedFd`] it may read/write to conduct a handshake) and its [`BrokerContext`], and
/// returns the [`BrokerVerdict`].
pub struct BrokerServer<H> {
    handler: H,
}

impl<H: Fn(BrokerContext, OwnedFd) -> BrokerVerdict> BrokerServer<H> {
    /// Build a broker over an authentication `handler`.
    pub fn new(handler: H) -> Self {
        Self { handler }
    }

    /// Serve a single accepted broker connection: receive the fd + context, run the handler, and
    /// write back the verdict. Blocking.
    pub fn serve_conn(&self, conn: &UnixStream) -> io::Result<()> {
        let (fd, ctx) = protocol::recv_request(conn)?;
        let verdict = (self.handler)(ctx, fd);
        protocol::respond(conn, &verdict)
    }

    /// Accept and serve hand-offs on `listener` until an accept error, each on the calling thread.
    /// A malformed hand-off drops just that connection; the loop keeps serving.
    pub fn serve(&self, listener: &UnixListener) -> io::Result<()> {
        for conn in listener.incoming() {
            let _ = self.serve_conn(&conn?);
        }
        Ok(())
    }
}
