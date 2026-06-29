//! End-to-end ONC RPC (RFC 5531) over a real AF_UNIX socket, through the public
//! [`serve_oncrpc_unix_listener`](truenas_jsonrpc_server::JsonRpcServer::serve_oncrpc_unix_listener)
//! — proving the per-connection `ProtocolEngine` seam carries a peer **binary** wire (record-marking
//! framed, XDR-encoded) alongside JSON-RPC, selected per listener. A hand-rolled client speaks the
//! wire directly: the `NULL` probe (procedure 0) and the demo `add` (procedure 1).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use truenas_jsonrpc_server::{JsonRpcServer, UnixConfig};
use truenas_xdr::{from_bytes, from_bytes_with, to_bytes, Strictness, VarOpaque};

const PROG: u32 = 0x2000_0001;
const VERS: u32 = 1;
const PROC_NULL: u32 = 0;
const PROC_ADD: u32 = 1;
const RM_LAST: u32 = 0x8000_0000;

/// Record-mark a single-fragment payload (RFC 5531 §11).
fn rm_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (RM_LAST | payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// Build a record-marked ONC RPC CALL (AUTH_NONE cred + verf) for the demo program.
fn call(xid: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
    // xid, mtype=CALL(0), rpcvers=2, prog, vers, proc, cred(AUTH_NONE, empty), verf(AUTH_NONE, empty)
    let prefix = (
        xid, 0u32, 2u32, PROG, VERS, procedure, 0u32, VarOpaque(Vec::new()), 0u32,
        VarOpaque(Vec::new()),
    );
    let mut msg = to_bytes(&prefix).unwrap();
    msg.extend_from_slice(args);
    rm_frame(&msg)
}

/// Read one record-marked reply, returning `(accept_stat, result_bytes)`.
async fn read_reply(stream: &mut UnixStream) -> (u32, Vec<u8>) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let len = (u32::from_be_bytes(header) & !RM_LAST) as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await.unwrap();
    // xid, mtype(REPLY), reply_stat(MSG_ACCEPTED), verf(flavor, body), accept_stat, then results.
    let ((_xid, _mtype, _reply_stat, _vflavor, _vbody, accept_stat), results) =
        from_bytes_with::<(u32, u32, u32, u32, VarOpaque, u32)>(&msg, Strictness::Lenient).unwrap();
    (accept_stat, results.to_vec())
}

#[tokio::test]
async fn oncrpc_null_and_add_over_unix() {
    let path = std::env::temp_dir().join(format!("tnrpc-{}-oncrpc.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    // The ONC RPC engine routes on its own program table, so the server needs no registered
    // JSON-RPC protocol — this proves the engine is a peer wire, not a JSON-RPC reframing.
    let srv = JsonRpcServer::<()>::builder("oncrpc-demo").build();
    let listener = JsonRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let task = tokio::spawn(async move { srv.serve_oncrpc_unix_listener(listener).await });

    let mut client = UnixStream::connect(&path).await.unwrap();

    // NULL probe → SUCCESS with an empty result.
    client.write_all(&call(1, PROC_NULL, &[])).await.unwrap();
    let (accept_stat, body) = read_reply(&mut client).await;
    assert_eq!(accept_stat, 0); // ACCEPT_SUCCESS
    assert!(body.is_empty());

    // add(20, 22) → SUCCESS with the i64 sum.
    let args = to_bytes(&(20i32, 22i32)).unwrap();
    client.write_all(&call(2, PROC_ADD, &args)).await.unwrap();
    let (accept_stat, body) = read_reply(&mut client).await;
    assert_eq!(accept_stat, 0);
    assert_eq!(from_bytes::<i64>(&body).unwrap(), 42);

    task.abort();
    let _ = std::fs::remove_file(&path);
}
