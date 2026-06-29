//! End-to-end: a registered `math.add` served over **ONC RPC** (RFC 5531) through
//! [`serve_oncrpc_unix_listener`](truenas_rpc_server::TruenasRpcServer::serve_oncrpc_unix_listener).
//! The same method is reachable over the JSON-RPC transports too — one service, two wires — but here
//! a hand-rolled ONC RPC client (record marking + `rpc_msg`, AUTH_NONE) drives the binary wire: the
//! `NULL` probe (procedure 0) and `math.add` via its XDR proc-id (1001).

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use truenas_rpc::{JsonRpcError, RpcMethod, JsonRpcProtocol, MethodDef, RequestCtx};
use truenas_rpc_server::{TruenasRpcServer, OncRpcConfig, UnixConfig};
use truenas_xdr::{from_bytes, from_bytes_with, to_bytes, Strictness, VarOpaque};

const PROG: u32 = 0x2000_0001;
const VERS: u32 = 1;
const RM_LAST: u32 = 0x8000_0000;

#[derive(Deserialize, Serialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Deserialize, Serialize)]
struct AddResult {
    sum: i64,
}

/// The protocol whose `math.add` (XDR proc-id 1001) the server serves over both wires.
fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add").xdr(1001),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build()
}

/// Record-mark a single-fragment payload (RFC 5531 §11).
fn rm_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (RM_LAST | payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// Build a record-marked ONC RPC CALL (AUTH_NONE) for `procedure` with XDR-encoded `args`.
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
async fn registered_method_served_over_oncrpc() {
    let path = std::env::temp_dir().join(format!("tnrpc-{}-oncrpc.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = TruenasRpcServer::<()>::builder("dual-wire").protocol("demo", proto()).build();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let task =
        tokio::spawn(async move { srv.serve_oncrpc_unix_listener(listener, OncRpcConfig::new("demo")).await });

    let mut client = UnixStream::connect(&path).await.unwrap();

    // NULL probe (procedure 0) → accepted, success, empty result.
    client.write_all(&call(1, 0, &[])).await.unwrap();
    let (accept_stat, body) = read_reply(&mut client).await;
    assert_eq!(accept_stat, 0); // ACCEPT_SUCCESS
    assert!(body.is_empty());

    // The *registered* math.add(20, 22), reached by its XDR proc-id 1001 → 42.
    let args = to_bytes(&AddArgs { a: 20, b: 22 }).unwrap();
    client.write_all(&call(2, 1001, &args)).await.unwrap();
    let (accept_stat, body) = read_reply(&mut client).await;
    assert_eq!(accept_stat, 0);
    assert_eq!(from_bytes::<AddResult>(&body).unwrap().sum, 42);

    task.abort();
    let _ = std::fs::remove_file(&path);
}
