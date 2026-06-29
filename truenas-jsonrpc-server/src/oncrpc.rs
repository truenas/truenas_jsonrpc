//! A second [`ProtocolEngine`](crate::engine::ProtocolEngine): a minimal **ONC RPC** service
//! (RFC 5531 — "RPC: Remote Procedure Call Protocol Specification Version 2", the canonical
//! XDR record-marking RPC), served over the *same* per-connection seam as the default JSON-RPC
//! engine. It exists to prove the boundary is genuinely protocol-agnostic — a **peer** wire, not a
//! reframing of JSON-RPC. The wire format is validated against FreeBSD's in-tree ONC RPC
//! (`include/rpc/rpc_msg.h`, `include/rpc/auth.h`, `lib/libc/xdr/xdr_rec.c`, `lib/libc/rpc`).
//!
//! It shares two things with the rest of the crate: the **Codec** (layer 3, `truenas-xdr`) and the
//! per-connection seam — plus, now, the **op-table**. Everything else is its own stack:
//!   * **Framing (layer 2):** RFC 5531 §11 *record marking* — a message is one record of one or
//!     more fragments, each a 4-byte header (high bit = last-fragment, low 31 bits = fragment
//!     length) over that many bytes. (The JSON-RPC engine frames with a plain 4-byte length prefix;
//!     this is a deliberately *different* framing, so the seam can't be silently coupled to one.)
//!   * **Envelope (layer 4):** the ONC RPC `rpc_msg` call/reply union; the server accepts the
//!     `AUTH_NONE` and `AUTH_SYS` credential flavors and rejects others with `AUTH_REJECTEDCRED`.
//!   * **Dispatch (layer 5):** routed on `(program, version, procedure)` — a `NULL` probe
//!     (procedure 0), and every other procedure number dispatched to the **registered** method whose
//!     XDR proc-id equals it, via [`Service::run_proc`]. So a method registered once
//!     (with `.xdr(proc_id)`) is served over *both* the JSON-RPC wire and this one — one service,
//!     two wires — differing only in framing and envelope.
//!
//! The engine takes only the byte stream + size limit from its [`ConnContext`](crate::engine::ConnContext)
//! (auth is the ONC RPC credential flavor, not the connection peer); the op-table it serves is the
//! [`Service`] inside the bound [`OncRpcProtocol`] it captures at construction. ONC RPC has no
//! `$/sessionSetup` handshake
//! and this engine adds no server-push, so it serves a session with no server state and a no-op
//! outbound — methods gated behind session setup are not reachable over this wire.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use truenas_jsonrpc::{ErrorCode, JsonRpcError, NullOutbound, Service};
use truenas_xdr::{from_bytes_with, to_bytes, Strictness, VarOpaque};

use crate::engine::{ConnContext, ProtocolEngine};

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
const ACCEPT_SYSTEM_ERR: u32 = 5;
/// `auth_flavor`: this demo accepts `AUTH_NONE` and `AUTH_SYS` (whose uid/gid it does not use) and
/// rejects other flavors — mirroring FreeBSD's `_authenticate` (`lib/libc/rpc/svc_auth.c`). Replies
/// always carry an `AUTH_NONE` verifier (as a real server does for these flavors).
const AUTH_NONE: u32 = 0;
const AUTH_SYS: u32 = 1;
/// `auth_stat::AUTH_REJECTEDCRED` — the reason returned for an unsupported credential flavor.
const AUTH_REJECTEDCRED: u32 = 2;

// --- The demo program -------------------------------------------------------

/// The default program number, in RFC 5531's user-defined range (`0x2000_0000..=0x3FFF_FFFF`). The
/// program/version an engine answers to are configurable per listener — see
/// [`OncRpcConfig`](crate::OncRpcConfig); these are the defaults.
pub(crate) const DEFAULT_PROGRAM: u32 = 0x2000_0001;
/// The default program version.
pub(crate) const DEFAULT_VERSION: u32 = 1;
/// Procedure 0 is, by ONC RPC convention, the no-op `NULL` probe (empty args, empty result).
const PROC_NULL: u32 = 0;

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

// --- Dispatch ---------------------------------------------------------------

/// What an inbound record resolves to *before* any registered-method dispatch — computed purely,
/// with no protocol or session.
enum Action<'a> {
    /// Close the connection: an undecodable prefix, or a non-CALL message a server must not answer.
    Close,
    /// A complete reply (an error, or the `NULL` probe) — write it as-is.
    Reply(Vec<u8>),
    /// Route `procedure` (a registered method's XDR proc-id) with `args` to the bound protocol.
    Dispatch { xid: u32, procedure: u32, args: &'a [u8] },
}

/// Validate an inbound record and decide what to do with it. Mirrors FreeBSD's order
/// (`svc_getreq_common`): parse → reject a non-CALL → check `rpcvers` → authenticate → match
/// program/version → the `NULL` probe; any other procedure becomes a [`Action::Dispatch`].
fn precheck(wire: &[u8], program: u32, version: u32) -> Action<'_> {
    let Some(call) = parse_call(wire) else { return Action::Close };
    if call.mtype != MSG_CALL {
        return Action::Close;
    }
    if call.rpcvers != RPC_VERSION {
        return Action::Reply(reply_rpc_mismatch(call.xid, RPC_VERSION, RPC_VERSION));
    }
    // Authentication precedes program/version matching: accept AUTH_NONE / AUTH_SYS, reject others.
    if call.cred_flavor != AUTH_NONE && call.cred_flavor != AUTH_SYS {
        return Action::Reply(reply_auth_error(call.xid, AUTH_REJECTEDCRED));
    }
    if call.prog != program {
        return Action::Reply(reply_accepted(call.xid, ACCEPT_PROG_UNAVAIL, &[]));
    }
    if call.vers != version {
        return Action::Reply(reply_prog_mismatch(call.xid, version, version));
    }
    if call.procedure == PROC_NULL {
        return Action::Reply(reply_accepted(call.xid, ACCEPT_SUCCESS, &[]));
    }
    Action::Dispatch { xid: call.xid, procedure: call.procedure, args: call.args }
}

/// Map a dispatch error onto the closest ONC RPC `accept_stat`. The accepted-reply status set is
/// coarse (a program normally encodes richer errors in its own result union), so the JSON-RPC error
/// detail is necessarily flattened.
fn accept_stat_for(e: &JsonRpcError) -> u32 {
    match e.code {
        c if c == ErrorCode::MethodNotFound.code() => ACCEPT_PROC_UNAVAIL,
        c if c == ErrorCode::InvalidParams.code() => ACCEPT_GARBAGE_ARGS,
        _ => ACCEPT_SYSTEM_ERR,
    }
}

/// The dispatch core's **ONC RPC wire-view** (RFC 5531): a [`Service`] op-table projected onto an
/// ONC RPC `(program, version)`. The peer of [`JsonRpcProtocol`](truenas_jsonrpc::JsonRpcProtocol)
/// for the record-marking binary wire — it owns no methods of its own, serving the *same* registered
/// methods by their XDR proc-ids (one service, two wires). Where `JsonRpcProtocol` lives in the
/// transport-free core and is adapted to the seam by [`JsonRpcEngine`](crate::engine), this view
/// lives in the server crate, so it *is* its own [`ProtocolEngine`] — bind it to a listener directly.
pub(crate) struct OncRpcProtocol<S> {
    service: Arc<Service<S>>,
    program: u32,
    version: u32,
}

impl<S: Send + Sync + 'static> OncRpcProtocol<S> {
    /// Project a [`Service`] op-table onto the ONC RPC `program` / `version` this view answers to.
    pub(crate) fn new(service: Arc<Service<S>>, program: u32, version: u32) -> Self {
        OncRpcProtocol { service, program, version }
    }

    /// The per-connection loop: read a record, answer it, write the reply, repeat until the peer
    /// closes or sends something unanswerable. Each non-`NULL` procedure is dispatched to the
    /// service's method whose XDR proc-id equals it. Sequential by design — this reference engine
    /// adds no pipelining or server-initiated push.
    async fn serve_connection<IO>(&self, mut stream: IO, limit: usize)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // One session per connection: no server state, no outbound (this wire has no session setup
        // and no server-push). Closed at end of connection.
        let session = self.service.new_session(None, Arc::new(NullOutbound));
        let mut acc = BytesMut::with_capacity(8 * 1024);
        while let Some(record) = read_record(&mut stream, &mut acc, limit).await {
            let reply = match precheck(&record, self.program, self.version) {
                Action::Close => break,
                Action::Reply(bytes) => bytes,
                // The ONC RPC procedure number IS the registered method's XDR proc-id; on success
                // the result bytes are the method's XDR-encoded result, wrapped in the accepted reply.
                Action::Dispatch { xid, procedure, args } => {
                    match self.service.run_proc(procedure, None, args, &session).await {
                        Ok(result) => reply_accepted(xid, ACCEPT_SUCCESS, &result),
                        Err(e) => reply_accepted(xid, accept_stat_for(&e), &[]),
                    }
                }
            };
            if write_record(&mut stream, &reply).await.is_err() {
                break;
            }
        }
        self.service.close_session(&session);
    }
}

impl<S: Send + Sync + 'static> ProtocolEngine for OncRpcProtocol<S> {
    fn serve<'a>(&'a self, ctx: ConnContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(self.serve_connection(ctx.stream, ctx.limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use truenas_jsonrpc::{JsonRpcMethod, JsonRpcProtocol, MethodDef, RequestCtx};
    use truenas_xdr::from_bytes;

    #[derive(Deserialize, Serialize)]
    struct AddArgs {
        a: i64,
        b: i64,
    }
    #[derive(Deserialize, Serialize)]
    struct AddResult {
        sum: i64,
    }

    /// A protocol whose `math.add` is registered on XDR proc-id 1001.
    fn add_proto() -> Arc<JsonRpcProtocol<()>> {
        Arc::new(
            JsonRpcProtocol::<()>::builder("demo", "1")
                .method(JsonRpcMethod::new(
                    MethodDef::new("math.add").xdr(1001),
                    |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
                ))
                .unwrap()
                .build(),
        )
    }

    /// Build an `rpc_msg` CALL (no record marking) with the given fields.
    fn msg(xid: u32, rpcvers: u32, prog: u32, vers: u32, procedure: u32, cred: u32, args: &[u8]) -> Vec<u8> {
        let prefix: CallPrefix = (
            xid, MSG_CALL, rpcvers, prog, vers, procedure, cred, VarOpaque(Vec::new()), AUTH_NONE,
            VarOpaque(Vec::new()),
        );
        let mut m = to_bytes(&prefix).unwrap();
        m.extend_from_slice(args);
        m
    }

    /// Decode a reply record into `(reply_stat, status, body)` where `status` is the accept- or
    /// reject-stat and `body` is whatever trails it.
    fn parse_reply(record: &[u8]) -> (u32, u32, Vec<u8>) {
        let ((_xid, mtype, reply_stat), rest) =
            from_bytes_with::<(u32, u32, u32)>(record, Strictness::Lenient).unwrap();
        assert_eq!(mtype, MSG_REPLY);
        if reply_stat == MSG_ACCEPTED {
            let ((_flavor, _verf, accept_stat), body) =
                from_bytes_with::<(u32, VarOpaque, u32)>(rest, Strictness::Lenient).unwrap();
            (reply_stat, accept_stat, body.to_vec())
        } else {
            let (reject_stat, body) = from_bytes_with::<u32>(rest, Strictness::Lenient).unwrap();
            (reply_stat, reject_stat, body.to_vec())
        }
    }

    /// The reply bytes of an [`Action::Reply`] (panics otherwise).
    fn reply_of(action: Action) -> Vec<u8> {
        match action {
            Action::Reply(b) => b,
            _ => panic!("expected Action::Reply"),
        }
    }

    // The default program/version most tests run against.
    const PROG: u32 = DEFAULT_PROGRAM;
    const VERS: u32 = DEFAULT_VERSION;

    /// `precheck` against the default program/version.
    fn pre(wire: &[u8]) -> Action<'_> {
        precheck(wire, PROG, VERS)
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
    async fn zero_fragment_header_is_rejected() {
        // header == 0 (length 0, not last-fragment) is malformed → the record read closes.
        let mut r: &[u8] = &[0, 0, 0, 0];
        let mut acc = BytesMut::new();
        assert!(read_record(&mut r, &mut acc, 4096).await.is_none());
    }

    #[test]
    fn null_probe_succeeds() {
        let (rs, stat, body) = parse_reply(&reply_of(pre(&msg(7, RPC_VERSION, PROG, VERS, PROC_NULL, AUTH_NONE, &[]))));
        assert_eq!((rs, stat), (MSG_ACCEPTED, ACCEPT_SUCCESS));
        assert!(body.is_empty());
    }

    #[test]
    fn wrong_program_and_version_are_reported() {
        // Unknown program → PROG_UNAVAIL.
        let (_, stat, _) = parse_reply(&reply_of(pre(&msg(1, RPC_VERSION, 0xDEAD, VERS, PROC_NULL, AUTH_NONE, &[]))));
        assert_eq!(stat, ACCEPT_PROG_UNAVAIL);
        // Wrong version → PROG_MISMATCH with the supported range.
        let (_, stat, body) = parse_reply(&reply_of(pre(&msg(1, RPC_VERSION, PROG, 99, PROC_NULL, AUTH_NONE, &[]))));
        assert_eq!(stat, ACCEPT_PROG_MISMATCH);
        assert_eq!(from_bytes::<(u32, u32)>(&body).unwrap(), (VERS, VERS));
    }

    #[test]
    fn configured_program_and_version_are_honored() {
        // An engine on a custom program/version: a call to the *default* program is now
        // PROG_UNAVAIL, and a call to the custom program/version dispatches.
        let (prog, vers) = (0x2000_0099, 7);
        let (_, stat, _) = parse_reply(&reply_of(precheck(
            &msg(1, RPC_VERSION, PROG, VERS, 1001, AUTH_NONE, &[]),
            prog,
            vers,
        )));
        assert_eq!(stat, ACCEPT_PROG_UNAVAIL);
        assert!(matches!(
            precheck(&msg(1, RPC_VERSION, prog, vers, 1001, AUTH_NONE, &[1, 2]), prog, vers),
            Action::Dispatch { procedure: 1001, .. }
        ));
    }

    #[test]
    fn wrong_rpc_version_is_denied() {
        let (rs, reject, body) = parse_reply(&reply_of(pre(&msg(5, 1, PROG, VERS, PROC_NULL, AUTH_NONE, &[]))));
        assert_eq!((rs, reject), (MSG_DENIED, REJECT_RPC_MISMATCH));
        assert_eq!(from_bytes::<(u32, u32)>(&body).unwrap(), (RPC_VERSION, RPC_VERSION));
    }

    #[test]
    fn unsupported_auth_flavor_is_denied() {
        // AUTH_DH (3) credentials → MSG_DENIED / AUTH_ERROR / AUTH_REJECTEDCRED.
        let (rs, reject, body) = parse_reply(&reply_of(pre(&msg(1, RPC_VERSION, PROG, VERS, PROC_NULL, 3, &[]))));
        assert_eq!((rs, reject), (MSG_DENIED, REJECT_AUTH_ERROR));
        assert_eq!(from_bytes::<u32>(&body).unwrap(), AUTH_REJECTEDCRED);
    }

    #[test]
    fn auth_sys_credentials_are_accepted() {
        // AUTH_SYS (1) is accepted — the NULL probe still succeeds.
        let (_, stat, _) = parse_reply(&reply_of(pre(&msg(1, RPC_VERSION, PROG, VERS, PROC_NULL, AUTH_SYS, &[]))));
        assert_eq!(stat, ACCEPT_SUCCESS);
    }

    #[test]
    fn non_call_and_truncated_close_the_connection() {
        // A REPLY message: a server must not answer it.
        let prefix: CallPrefix = (
            1, MSG_REPLY, RPC_VERSION, PROG, VERS, PROC_NULL, AUTH_NONE, VarOpaque(Vec::new()),
            AUTH_NONE, VarOpaque(Vec::new()),
        );
        assert!(matches!(pre(&to_bytes(&prefix).unwrap()), Action::Close));
        // A truncated prefix has no xid to reply to → also closes.
        assert!(matches!(pre(&[0, 0, 0, 1]), Action::Close));
    }

    #[test]
    fn registered_procedure_becomes_a_dispatch() {
        // A non-NULL procedure resolves to a dispatch carrying the proc-id + raw args.
        match pre(&msg(1, RPC_VERSION, PROG, VERS, 1001, AUTH_NONE, &[1, 2, 3, 4])) {
            Action::Dispatch { xid, procedure, args } => {
                assert_eq!((xid, procedure), (1, 1001));
                assert_eq!(args, &[1, 2, 3, 4]);
            }
            _ => panic!("expected Action::Dispatch"),
        }
    }

    #[test]
    fn error_codes_map_to_accept_stats() {
        assert_eq!(accept_stat_for(&JsonRpcError::method_not_found("x")), ACCEPT_PROC_UNAVAIL);
        assert_eq!(accept_stat_for(&JsonRpcError::new(ErrorCode::InvalidParams, "x")), ACCEPT_GARBAGE_ARGS);
        assert_eq!(accept_stat_for(&JsonRpcError::request_failed("x")), ACCEPT_SYSTEM_ERR);
    }

    #[tokio::test]
    async fn serve_loop_dispatches_a_registered_method() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let proto = Arc::new(OncRpcProtocol::new(add_proto().service().clone(), PROG, VERS));
        let task = tokio::spawn(async move { proto.serve_connection(server, 4 * 1024 * 1024).await });
        let mut acc = BytesMut::new();

        // NULL probe (self-contained) → SUCCESS, empty.
        client.write_all(&rm_frame(&msg(1, RPC_VERSION, PROG, VERS, PROC_NULL, AUTH_NONE, &[]))).await.unwrap();
        let (_, stat, body) = parse_reply(&read_record(&mut client, &mut acc, 1 << 20).await.unwrap());
        assert_eq!((stat, body.len()), (ACCEPT_SUCCESS, 0));

        // procedure 1001 → the registered math.add(20, 22) → 42.
        let args = to_bytes(&AddArgs { a: 20, b: 22 }).unwrap();
        client.write_all(&rm_frame(&msg(2, RPC_VERSION, PROG, VERS, 1001, AUTH_NONE, &args))).await.unwrap();
        let (_, stat, body) = parse_reply(&read_record(&mut client, &mut acc, 1 << 20).await.unwrap());
        assert_eq!(stat, ACCEPT_SUCCESS);
        assert_eq!(from_bytes::<AddResult>(&body).unwrap().sum, 42);

        // An unregistered procedure → PROC_UNAVAIL (the method-not-found maps through).
        client.write_all(&rm_frame(&msg(3, RPC_VERSION, PROG, VERS, 9999, AUTH_NONE, &[]))).await.unwrap();
        let (_, stat, _) = parse_reply(&read_record(&mut client, &mut acc, 1 << 20).await.unwrap());
        assert_eq!(stat, ACCEPT_PROC_UNAVAIL);

        drop(client);
        task.await.unwrap();
    }
}
