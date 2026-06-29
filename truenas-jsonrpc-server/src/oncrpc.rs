//! A second [`ProtocolEngine`](crate::engine::ProtocolEngine): a minimal **ONC RPC** service
//! (RFC 5531 — "RPC: Remote Procedure Call Protocol Specification Version 2", the canonical
//! XDR record-marking RPC), served over the *same* per-connection seam as the default JSON-RPC
//! engine. It exists to prove the boundary is genuinely protocol-agnostic — a **peer** wire, not a
//! reframing of JSON-RPC. The wire format is validated against FreeBSD's in-tree ONC RPC
//! (`include/rpc/rpc_msg.h`, `include/rpc/auth.h`, `lib/libc/xdr/xdr_rec.c`, `lib/libc/rpc`).
//!
//! It shares exactly two things with the rest of the crate: the **Codec** (layer 3, `truenas-xdr`)
//! and the per-connection seam. Everything else is its own stack:
//!   * **Framing (layer 2):** RFC 5531 §11 *record marking* — a message is one record of one or
//!     more fragments, each a 4-byte header (high bit = last-fragment, low 31 bits = fragment
//!     length) over that many bytes. (The JSON-RPC engine frames with a plain 4-byte length prefix;
//!     this is a deliberately *different* framing, so the seam can't be silently coupled to one.)
//!   * **Envelope (layer 4):** the ONC RPC `rpc_msg` call/reply union; the server accepts the
//!     `AUTH_NONE` and `AUTH_SYS` credential flavors and rejects others with `AUTH_REJECTEDCRED`.
//!   * **Dispatch (layer 5):** its own tiny program — a `NULL` probe plus one demo procedure —
//!     routed on `(program, version, procedure)`, independent of the JSON-RPC method registry.
//!
//! The engine consumes almost nothing from its [`ConnContext`](crate::engine::ConnContext): only the
//! inbound size limit (it ignores the peer and the raw-fd transfer channel). That narrowness is why
//! the seam hands every engine a small protocol-neutral context rather than the JSON-RPC server
//! substrate. Routing a binary wire to the *registered* handlers would need a procedure-level
//! dispatch entry the core does not yet expose; that is left for later rather than built
//! speculatively here.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use truenas_xdr::{from_bytes, from_bytes_with, to_bytes, Strictness, VarOpaque};

use crate::engine::{ConnContext, ProtocolEngine};

use std::future::Future;
use std::pin::Pin;

// --- ONC RPC message constants (RFC 5531 §9) --------------------------------

/// The only RPC version this engine speaks.
const RPC_VERSION: u32 = 2;
/// `msg_type` discriminants.
const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
/// `reply_stat` discriminants.
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;
/// `reject_stat` discriminants.
const REJECT_RPC_MISMATCH: u32 = 0;
const REJECT_AUTH_ERROR: u32 = 1;
/// `accept_stat` discriminants.
const ACCEPT_SUCCESS: u32 = 0;
const ACCEPT_PROG_UNAVAIL: u32 = 1;
const ACCEPT_PROG_MISMATCH: u32 = 2;
const ACCEPT_PROC_UNAVAIL: u32 = 3;
const ACCEPT_GARBAGE_ARGS: u32 = 4;
/// `auth_flavor`: this demo accepts `AUTH_NONE` and `AUTH_SYS` (whose uid/gid it does not use) and
/// rejects other flavors — mirroring FreeBSD's `_authenticate` (`lib/libc/rpc/svc_auth.c`). Replies
/// always carry an `AUTH_NONE` verifier (as a real server does for these flavors).
const AUTH_NONE: u32 = 0;
const AUTH_SYS: u32 = 1;
/// `auth_stat::AUTH_REJECTEDCRED` — the reason returned for an unsupported credential flavor.
const AUTH_REJECTEDCRED: u32 = 2;

// --- The demo program -------------------------------------------------------

/// The demo program number, in RFC 5531's user-defined range (`0x2000_0000..=0x3FFF_FFFF`).
const PROG: u32 = 0x2000_0001;
/// The demo program version.
const VERS: u32 = 1;
/// Procedure 0 is, by ONC RPC convention, the no-op `NULL` probe (empty args, empty result).
const PROC_NULL: u32 = 0;
/// The demo procedure: two `i32` arguments, an `i64` sum result.
const PROC_ADD: u32 = 1;

// --- Record marking (RFC 5531 §11) ------------------------------------------

/// Fragment-header high bit: set on the last fragment of a record.
const RM_LAST: u32 = 0x8000_0000;
/// Fragment-header low 31 bits: the fragment's data length.
const RM_LEN_MASK: u32 = 0x7FFF_FFFF;
/// The fragment header is one XDR unit.
const RM_HEADER: usize = 4;

/// Frame `payload` as a single last-fragment record. `payload.len()` is bounded by the inbound
/// limit (≪ 2³¹), so the length never collides with [`RM_LAST`].
fn rm_frame(payload: &[u8]) -> Vec<u8> {
    let header = RM_LAST | payload.len() as u32;
    let mut out = Vec::with_capacity(RM_HEADER + payload.len());
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Pull more bytes into `acc`. `Some(0)` on EOF, `Some(n)` on data, `None` on a read error.
async fn read_more<R: AsyncRead + Unpin>(stream: &mut R, acc: &mut BytesMut) -> Option<usize> {
    match stream.read_buf(acc).await {
        Ok(n) => Some(n),
        Err(_) => None,
    }
}

/// Read one complete record, reassembling fragments until the last-fragment bit. Returns `None`
/// on a clean EOF between records, a read error, a truncated record, or a record whose reassembled
/// length would exceed `limit`.
async fn read_record<R: AsyncRead + Unpin>(
    stream: &mut R,
    acc: &mut BytesMut,
    limit: usize,
) -> Option<Bytes> {
    let mut record = BytesMut::new();
    loop {
        while acc.len() < RM_HEADER {
            // EOF here is clean only when nothing is buffered and no fragment has been read yet;
            // either way there is no usable record, so close.
            if read_more(stream, acc).await? == 0 {
                return None;
            }
        }
        let header = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]);
        // A zero header (length 0, not last-fragment) is malformed — FreeBSD's set_input_fragment
        // (lib/libc/xdr/xdr_rec.c) rejects it outright rather than spin on empty fragments.
        if header == 0 {
            return None;
        }
        let last = header & RM_LAST != 0;
        let frag_len = (header & RM_LEN_MASK) as usize;
        if record.len().saturating_add(frag_len) > limit {
            return None;
        }
        while acc.len() < RM_HEADER + frag_len {
            if read_more(stream, acc).await? == 0 {
                return None; // truncated mid-fragment
            }
        }
        let _ = acc.split_to(RM_HEADER); // drop the fragment header
        let frag = acc.split_to(frag_len);
        record.extend_from_slice(&frag);
        if last {
            return Some(record.freeze());
        }
    }
}

/// Record-mark `payload` and write it (with a flush).
async fn write_record<W: AsyncWrite + Unpin>(stream: &mut W, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(&rm_frame(payload)).await?;
    stream.flush().await
}

// --- The ONC RPC call/reply envelope ----------------------------------------

/// The fixed prefix of an `rpc_msg` CALL with two `opaque_auth`s (cred, verf), decoded as a tuple
/// exactly as it lies on the wire; the procedure arguments are the trailing bytes.
type CallPrefix = (u32, u32, u32, u32, u32, u32, u32, VarOpaque, u32, VarOpaque);

/// A parsed call: the fields this engine routes on, plus the undecoded argument bytes.
struct Call<'a> {
    xid: u32,
    mtype: u32,
    rpcvers: u32,
    prog: u32,
    vers: u32,
    procedure: u32,
    cred_flavor: u32,
    args: &'a [u8],
}

/// Parse an `rpc_msg` CALL prefix. `None` if the fixed prefix can't be decoded — without an `xid`
/// there is nothing to reply to, so the caller closes the connection.
fn parse_call(wire: &[u8]) -> Option<Call<'_>> {
    let (p, args) = from_bytes_with::<CallPrefix>(wire, Strictness::Lenient).ok()?;
    // p = (xid, mtype, rpcvers, prog, vers, proc, cred.flavor, cred.body, verf.flavor, verf.body).
    // The credential/verifier bodies are not used by this demo's accepted flavors.
    Some(Call {
        xid: p.0,
        mtype: p.1,
        rpcvers: p.2,
        prog: p.3,
        vers: p.4,
        procedure: p.5,
        cred_flavor: p.6,
        args,
    })
}

/// Build an `accepted_reply` with the `AUTH_NONE` verifier: `xid · REPLY · MSG_ACCEPTED ·
/// verf(AUTH_NONE, empty) · accept_stat · results`.
fn reply_accepted(xid: u32, accept_stat: u32, results: &[u8]) -> Vec<u8> {
    let env = (xid, MSG_REPLY, MSG_ACCEPTED, AUTH_NONE, VarOpaque(Vec::new()), accept_stat);
    let mut out = to_bytes(&env).expect("accepted-reply envelope encodes");
    out.extend_from_slice(results);
    out
}

/// Build a `PROG_MISMATCH` accepted reply, carrying the supported `[low, high]` version range.
fn reply_prog_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    let env =
        (xid, MSG_REPLY, MSG_ACCEPTED, AUTH_NONE, VarOpaque(Vec::new()), ACCEPT_PROG_MISMATCH, low, high);
    to_bytes(&env).expect("prog-mismatch reply encodes")
}

/// Build a `MSG_DENIED` / `RPC_MISMATCH` reply, carrying the supported `[low, high]` RPC versions.
fn reply_rpc_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    let env = (xid, MSG_REPLY, MSG_DENIED, REJECT_RPC_MISMATCH, low, high);
    to_bytes(&env).expect("rpc-mismatch reply encodes")
}

/// Build a `MSG_DENIED` / `AUTH_ERROR` reply carrying the `auth_stat` reason.
fn reply_auth_error(xid: u32, why: u32) -> Vec<u8> {
    let env = (xid, MSG_REPLY, MSG_DENIED, REJECT_AUTH_ERROR, why);
    to_bytes(&env).expect("auth-error reply encodes")
}

/// Route a well-formed call to the demo program and build its reply.
fn route(xid: u32, prog: u32, vers: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
    if prog != PROG {
        return reply_accepted(xid, ACCEPT_PROG_UNAVAIL, &[]);
    }
    if vers != VERS {
        return reply_prog_mismatch(xid, VERS, VERS);
    }
    match procedure {
        PROC_NULL => reply_accepted(xid, ACCEPT_SUCCESS, &[]),
        PROC_ADD => match from_bytes::<(i32, i32)>(args) {
            Ok((a, b)) => {
                let sum = i64::from(a) + i64::from(b);
                reply_accepted(xid, ACCEPT_SUCCESS, &to_bytes(&sum).expect("i64 result encodes"))
            }
            Err(_) => reply_accepted(xid, ACCEPT_GARBAGE_ARGS, &[]),
        },
        _ => reply_accepted(xid, ACCEPT_PROC_UNAVAIL, &[]),
    }
}

/// Turn one inbound record into its reply bytes (pre-framing). `None` when there is no valid call
/// to answer — an undecodable prefix, or a non-CALL message a server should never receive — which
/// closes the connection.
fn handle_record(wire: &[u8]) -> Option<Vec<u8>> {
    let call = parse_call(wire)?;
    if call.mtype != MSG_CALL {
        return None;
    }
    if call.rpcvers != RPC_VERSION {
        return Some(reply_rpc_mismatch(call.xid, RPC_VERSION, RPC_VERSION));
    }
    // Authentication precedes program/version matching (cf. FreeBSD svc_getreq_common): accept the
    // AUTH_NONE / AUTH_SYS flavors, reject others with AUTH_REJECTEDCRED.
    if call.cred_flavor != AUTH_NONE && call.cred_flavor != AUTH_SYS {
        return Some(reply_auth_error(call.xid, AUTH_REJECTEDCRED));
    }
    Some(route(call.xid, call.prog, call.vers, call.procedure, call.args))
}

/// The per-connection loop: read a record, answer it, write the reply, repeat until the peer
/// closes or sends something unanswerable. Sequential by design — this reference engine adds no
/// pipelining or server-initiated push (those are the JSON-RPC engine's concern, not the seam's).
async fn serve_oncrpc<IO: AsyncRead + AsyncWrite + Unpin + Send>(mut stream: IO, limit: usize) {
    let mut acc = BytesMut::with_capacity(8 * 1024);
    while let Some(record) = read_record(&mut stream, &mut acc, limit).await {
        let Some(reply) = handle_record(&record) else { break };
        if write_record(&mut stream, &reply).await.is_err() {
            break;
        }
    }
}

/// The ONC RPC engine. Stateless: every connection runs the same demo program.
pub(crate) struct OncRpcEngine;

impl ProtocolEngine for OncRpcEngine {
    fn serve<'a>(&'a self, ctx: ConnContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        // This engine routes on its own program table and authenticates with AUTH_NONE, so the peer
        // identity and the raw-fd transfer channel go unused; only the inbound size limit is drawn
        // from the connection context.
        Box::pin(serve_oncrpc(ctx.stream, ctx.limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a record-marked `rpc_msg` CALL for the demo program with `AUTH_NONE` creds.
    fn call(xid: u32, prog: u32, vers: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
        let prefix: CallPrefix = (
            xid,
            MSG_CALL,
            RPC_VERSION,
            prog,
            vers,
            procedure,
            AUTH_NONE,
            VarOpaque(Vec::new()),
            AUTH_NONE,
            VarOpaque(Vec::new()),
        );
        let mut msg = to_bytes(&prefix).unwrap();
        msg.extend_from_slice(args);
        rm_frame(&msg)
    }

    /// Decode a reply record into `(reply_stat, status, body)` where `status` is the accept- or
    /// reject-stat and `body` is whatever trails it.
    fn parse_reply(record: &[u8]) -> (u32, u32, Vec<u8>) {
        // xid, mtype(REPLY), reply_stat, then the stat-specific tail.
        let ((_xid, mtype, reply_stat), rest) =
            from_bytes_with::<(u32, u32, u32)>(record, Strictness::Lenient).unwrap();
        assert_eq!(mtype, MSG_REPLY);
        if reply_stat == MSG_ACCEPTED {
            // verf(flavor, body) then accept_stat then the body.
            let ((_flavor, _verf, accept_stat), body) =
                from_bytes_with::<(u32, VarOpaque, u32)>(rest, Strictness::Lenient).unwrap();
            (reply_stat, accept_stat, body.to_vec())
        } else {
            let (reject_stat, body) =
                from_bytes_with::<u32>(rest, Strictness::Lenient).unwrap();
            (reply_stat, reject_stat, body.to_vec())
        }
    }

    #[test]
    fn rm_frame_sets_last_fragment_and_length() {
        assert_eq!(rm_frame(b"hi"), vec![0x80, 0, 0, 2, b'h', b'i']);
        assert_eq!(rm_frame(b""), vec![0x80, 0, 0, 0]);
    }

    #[tokio::test]
    async fn reads_a_multi_fragment_record() {
        // "hello" split across a non-last 3-byte fragment and a last 2-byte fragment.
        let mut wire = Vec::new();
        wire.extend_from_slice(&3u32.to_be_bytes()); // not last
        wire.extend_from_slice(b"hel");
        wire.extend_from_slice(&(RM_LAST | 2).to_be_bytes()); // last
        wire.extend_from_slice(b"lo");
        let mut r: &[u8] = &wire;
        let mut acc = BytesMut::new();
        let rec = read_record(&mut r, &mut acc, 4096).await.unwrap();
        assert_eq!(&rec[..], b"hello");
    }

    #[tokio::test]
    async fn oversized_record_is_refused() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(RM_LAST | 16).to_be_bytes());
        wire.extend_from_slice(&[0u8; 16]);
        let mut r: &[u8] = &wire;
        let mut acc = BytesMut::new();
        assert!(read_record(&mut r, &mut acc, 8).await.is_none());
    }

    #[tokio::test]
    async fn clean_eof_between_records_returns_none() {
        let mut r: &[u8] = &[];
        let mut acc = BytesMut::new();
        assert!(read_record(&mut r, &mut acc, 8).await.is_none());
    }

    #[tokio::test]
    async fn null_probe_succeeds() {
        let reply = handle_record(&strip_rm(&call(7, PROG, VERS, PROC_NULL, &[]))).unwrap();
        let (reply_stat, accept_stat, body) = parse_reply(&reply);
        assert_eq!((reply_stat, accept_stat), (MSG_ACCEPTED, ACCEPT_SUCCESS));
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn add_returns_the_sum() {
        let args = to_bytes(&(2i32, 40i32)).unwrap();
        let reply = handle_record(&strip_rm(&call(9, PROG, VERS, PROC_ADD, &args))).unwrap();
        let (_, accept_stat, body) = parse_reply(&reply);
        assert_eq!(accept_stat, ACCEPT_SUCCESS);
        assert_eq!(from_bytes::<i64>(&body).unwrap(), 42);
    }

    #[test]
    fn unknown_procedure_program_and_version_are_reported() {
        let strip = |v: Vec<u8>| strip_rm(&v);
        // Unknown procedure → PROC_UNAVAIL.
        let (_, stat, _) = parse_reply(&handle_record(&strip(call(1, PROG, VERS, 999, &[]))).unwrap());
        assert_eq!(stat, ACCEPT_PROC_UNAVAIL);
        // Unknown program → PROG_UNAVAIL.
        let (_, stat, _) = parse_reply(&handle_record(&strip(call(1, 0xDEAD, VERS, PROC_NULL, &[]))).unwrap());
        assert_eq!(stat, ACCEPT_PROG_UNAVAIL);
        // Wrong version → PROG_MISMATCH with the supported range.
        let (_, stat, body) =
            parse_reply(&handle_record(&strip(call(1, PROG, 99, PROC_NULL, &[]))).unwrap());
        assert_eq!(stat, ACCEPT_PROG_MISMATCH);
        assert_eq!(from_bytes::<(u32, u32)>(&body).unwrap(), (VERS, VERS));
    }

    #[test]
    fn malformed_add_args_are_garbage_args() {
        // PROC_ADD wants two i32 (8 bytes); supply 4 → the typed decode underruns.
        let (_, stat, _) =
            parse_reply(&handle_record(&strip_rm(&call(1, PROG, VERS, PROC_ADD, &[0, 0, 0, 1]))).unwrap());
        assert_eq!(stat, ACCEPT_GARBAGE_ARGS);
    }

    #[test]
    fn wrong_rpc_version_is_denied() {
        // Hand-build a CALL with rpcvers = 1.
        let prefix: CallPrefix = (
            5, MSG_CALL, 1, PROG, VERS, PROC_NULL, AUTH_NONE, VarOpaque(Vec::new()), AUTH_NONE,
            VarOpaque(Vec::new()),
        );
        let (reply_stat, reject_stat, body) =
            parse_reply(&handle_record(&to_bytes(&prefix).unwrap()).unwrap());
        assert_eq!((reply_stat, reject_stat), (MSG_DENIED, REJECT_RPC_MISMATCH));
        assert_eq!(from_bytes::<(u32, u32)>(&body).unwrap(), (RPC_VERSION, RPC_VERSION));
    }

    #[test]
    fn unsupported_auth_flavor_is_denied() {
        // AUTH_DH (3) credentials are rejected: MSG_DENIED / AUTH_ERROR / AUTH_REJECTEDCRED.
        let prefix: CallPrefix = (
            1, MSG_CALL, RPC_VERSION, PROG, VERS, PROC_NULL, 3, VarOpaque(Vec::new()), AUTH_NONE,
            VarOpaque(Vec::new()),
        );
        let (reply_stat, reject_stat, body) =
            parse_reply(&handle_record(&to_bytes(&prefix).unwrap()).unwrap());
        assert_eq!((reply_stat, reject_stat), (MSG_DENIED, REJECT_AUTH_ERROR));
        assert_eq!(from_bytes::<u32>(&body).unwrap(), AUTH_REJECTEDCRED);
    }

    #[test]
    fn auth_sys_credentials_are_accepted() {
        // AUTH_SYS (1) is accepted (its uid/gid is unused) — the NULL probe still succeeds.
        let prefix: CallPrefix = (
            1, MSG_CALL, RPC_VERSION, PROG, VERS, PROC_NULL, AUTH_SYS, VarOpaque(vec![0, 0, 0, 0]),
            AUTH_NONE, VarOpaque(Vec::new()),
        );
        let (_, accept_stat, _) = parse_reply(&handle_record(&to_bytes(&prefix).unwrap()).unwrap());
        assert_eq!(accept_stat, ACCEPT_SUCCESS);
    }

    #[tokio::test]
    async fn zero_fragment_header_is_rejected() {
        // header == 0 (length 0, not last-fragment) is malformed → the record read closes.
        let mut r: &[u8] = &[0, 0, 0, 0];
        let mut acc = BytesMut::new();
        assert!(read_record(&mut r, &mut acc, 4096).await.is_none());
    }

    #[test]
    fn a_reply_message_is_not_answered() {
        // mtype = REPLY: a server must not answer it (closes the connection → None).
        let prefix: CallPrefix = (
            1, MSG_REPLY, RPC_VERSION, PROG, VERS, PROC_NULL, AUTH_NONE, VarOpaque(Vec::new()),
            AUTH_NONE, VarOpaque(Vec::new()),
        );
        assert!(handle_record(&to_bytes(&prefix).unwrap()).is_none());
        // A truncated prefix has no xid to reply to → also closes.
        assert!(handle_record(&[0, 0, 0, 1]).is_none());
    }

    #[tokio::test]
    async fn serve_loop_answers_over_a_duplex_stream() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(serve_oncrpc(server, 4 * 1024 * 1024));

        // NULL probe, then ADD, then close — replies come back framed and in order.
        client.write_all(&call(1, PROG, VERS, PROC_NULL, &[])).await.unwrap();
        let mut acc = BytesMut::new();
        let (_, accept_stat, _) = parse_reply(&read_record(&mut client, &mut acc, 1 << 20).await.unwrap());
        assert_eq!(accept_stat, ACCEPT_SUCCESS);

        let args = to_bytes(&(20i32, 22i32)).unwrap();
        client.write_all(&call(2, PROG, VERS, PROC_ADD, &args)).await.unwrap();
        let (_, accept_stat, body) = parse_reply(&read_record(&mut client, &mut acc, 1 << 20).await.unwrap());
        assert_eq!(accept_stat, ACCEPT_SUCCESS);
        assert_eq!(from_bytes::<i64>(&body).unwrap(), 42);

        drop(client); // EOF → the serve loop exits cleanly.
        task.await.unwrap();
    }

    /// Strip the record marking from a single-fragment record, exposing the `rpc_msg` for the pure
    /// `handle_record` path.
    fn strip_rm(framed: &[u8]) -> Vec<u8> {
        framed[RM_HEADER..].to_vec()
    }
}
