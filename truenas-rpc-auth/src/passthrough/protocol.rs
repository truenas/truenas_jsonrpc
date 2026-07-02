//! The broker socket wire: a 4-byte big-endian length prefix framing a JSON body (the rest of the
//! stack's framing), with the client connection's fd passed (`SCM_RIGHTS`) alongside the *request*
//! frame's length prefix — so a single `recvmsg` on the broker captures both the fd and the frame
//! length, and the body follows as an ordinary stream read.

use std::io::{self, Read, Write};
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use truenas_rpc_server::scm;

use super::context::{BrokerContext, BrokerVerdict};

const HEADER: usize = 4;

fn frame_len(body: &[u8]) -> io::Result<[u8; HEADER]> {
    u32::try_from(body.len())
        .map(u32::to_be_bytes)
        .map_err(|_| io::Error::other("broker frame too large"))
}

/// Forwarder (server) side: send the auth request — the client connection's `client_fd`
/// (`SCM_RIGHTS`) plus the serialized `ctx` — then read back the broker's verdict. Blocking.
pub(crate) fn request(
    broker: &UnixStream,
    client_fd: RawFd,
    ctx: &BrokerContext,
) -> io::Result<BrokerVerdict> {
    let body = serde_json::to_vec(ctx)?;
    // The fd rides the 4-byte length prefix (one recvmsg captures both); the body then streams.
    scm::send_with_fd(broker, &frame_len(&body)?, client_fd)?;
    let mut sock: &UnixStream = broker;
    sock.write_all(&body)?;
    let resp = read_framed(&mut sock)?;
    Ok(serde_json::from_slice(&resp)?)
}

/// Broker side: receive one auth request — the passed client fd plus the context.
pub(crate) fn recv_request(conn: &UnixStream) -> io::Result<(OwnedFd, BrokerContext)> {
    let (header, fd) = scm::recv_with_fd(conn, HEADER)?;
    let fd = fd.ok_or_else(|| io::Error::other("broker request carried no fd"))?;
    if header.len() != HEADER {
        return Err(io::Error::other("short broker frame header"));
    }
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let mut body = vec![0u8; len];
    let mut r: &UnixStream = conn;
    r.read_exact(&mut body)?;
    Ok((fd, serde_json::from_slice(&body)?))
}

/// Broker side: send the verdict back to the forwarder.
pub(crate) fn respond(conn: &UnixStream, verdict: &BrokerVerdict) -> io::Result<()> {
    let body = serde_json::to_vec(verdict)?;
    let mut w: &UnixStream = conn;
    w.write_all(&frame_len(&body)?)?;
    w.write_all(&body)?;
    Ok(())
}

/// Read one length-prefixed frame from a `&UnixStream` (which implements [`Read`]).
fn read_framed(r: &mut &UnixStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; HEADER];
    r.read_exact(&mut hdr)?;
    let len = u32::from_be_bytes(hdr) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}
