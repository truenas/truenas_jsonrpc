//! Example: **one service, two wires.** A single registered method (`math.add`) is served over
//! *both* the default JSON-RPC engine and the ONC RPC engine (RFC 5531), on two Unix sockets of one
//! server. A client calls it over each wire and gets the same answer — the wires differ only in
//! framing and envelope; the handler is registered once.
//!
//!   - **JSON-RPC:** 4-byte length-prefixed JSON; `$/negotiate` then the method call.
//!   - **ONC RPC:** RFC 5531 record marking + `rpc_msg` (AUTH_NONE); the method's XDR proc-id (1001)
//!     *is* the ONC RPC procedure number. The wire is validated against FreeBSD's in-tree ONC RPC
//!     (`include/rpc/rpc_msg.h`, `lib/libc/xdr/xdr_rec.c`).
//!
//! Run: `cargo run -p truenas-rpc-server --example oncrpc_server`

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcMethod};
use truenas_rpc_server::{framing, JsonRpc, OncRpc, TruenasRpcServer, UnixConfig};
use truenas_xdr::{from_bytes, from_bytes_with, to_bytes, Strictness, VarOpaque};

// The ONC RPC demo program (matches the engine).
const PROG: u32 = 0x2000_0001;
const VERS: u32 = 1;
const ADD_PROC: u32 = 1001; // math.add's XDR proc-id == its ONC RPC procedure number.
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

/// The one service: `math.add`, registered once with an XDR proc-id so it is reachable over both
/// wires.
fn demo() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("demo", "1")
        .method(RpcMethod::new(
            MethodDef::new("math.add").xdr(ADD_PROC),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build()
}

// --- JSON-RPC client -------------------------------------------------------

async fn json_call(stream: &mut UnixStream, req: Value) -> Value {
    let bytes = serde_json::to_vec(&req).unwrap();
    stream.write_all(&framing::frame(&bytes)).await.unwrap();
    let reply = framing::read_message(stream, framing::DEFAULT_LIMIT)
        .await
        .unwrap()
        .unwrap();
    serde_json::from_slice(&reply).unwrap()
}

async fn add_over_json_rpc(path: &std::path::Path) -> i64 {
    let mut s = UnixStream::connect(path).await.unwrap();
    json_call(
        &mut s,
        json!({"jsonrpc":"2.0","id":"neg","method":"$/negotiate","params":{"protocol":"demo"}}),
    )
    .await;
    let add = json_call(
        &mut s,
        json!({"jsonrpc":"2.0","id":"00000000-0000-0000-0000-000000000001","method":"math.add","params":{"a":20,"b":22}}),
    )
    .await;
    add["result"]["sum"].as_i64().unwrap()
}

// --- ONC RPC client --------------------------------------------------------

fn rm_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (RM_LAST | payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// A record-marked ONC RPC CALL (AUTH_NONE) for `procedure` with XDR-encoded `args`.
fn onc_call(xid: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
    let prefix = (
        xid,
        0u32,
        2u32,
        PROG,
        VERS,
        procedure,
        0u32,
        VarOpaque(Vec::new()),
        0u32,
        VarOpaque(Vec::new()),
    );
    let mut msg = to_bytes(&prefix).unwrap();
    msg.extend_from_slice(args);
    rm_frame(&msg)
}

async fn add_over_oncrpc(path: &std::path::Path) -> i64 {
    let mut s = UnixStream::connect(path).await.unwrap();
    let args = to_bytes(&AddArgs { a: 20, b: 22 }).unwrap();
    s.write_all(&onc_call(1, ADD_PROC, &args)).await.unwrap();
    // Read the record-marked reply: skip the rm header, then the accepted-reply prefix → results.
    let mut header = [0u8; 4];
    s.read_exact(&mut header).await.unwrap();
    let len = (u32::from_be_bytes(header) & !RM_LAST) as usize;
    let mut msg = vec![0u8; len];
    s.read_exact(&mut msg).await.unwrap();
    let ((_xid, _mtype, _reply_stat, _vf, _vb, accept_stat), results) =
        from_bytes_with::<(u32, u32, u32, u32, VarOpaque, u32)>(&msg, Strictness::Lenient).unwrap();
    assert_eq!(
        accept_stat, 0,
        "ONC RPC call should be accepted + successful"
    );
    from_bytes::<AddResult>(results).unwrap().sum
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    let json_path = std::env::temp_dir().join(format!("dualwire-{}-json.sock", std::process::id()));
    let onc_path =
        std::env::temp_dir().join(format!("dualwire-{}-oncrpc.sock", std::process::id()));
    let _ = std::fs::remove_file(&json_path);
    let _ = std::fs::remove_file(&onc_path);

    // One server, one registered protocol — served on two listeners with two engines.
    let server = TruenasRpcServer::<()>::builder("dual-wire")
        .protocol("demo", demo())
        .build();
    let json_listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&json_path))?;
    let onc_listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&onc_path))?;

    let json_srv = server.clone();
    let json_task =
        tokio::spawn(async move { json_srv.serve_unix_listener(json_listener, JsonRpc).await });
    let onc_srv = server.clone();
    let onc_task = tokio::spawn(async move {
        onc_srv
            .serve_unix_listener(onc_listener, OncRpc::protocol("demo"))
            .await
    });

    // Call the same method over each wire.
    let json_sum = add_over_json_rpc(&json_path).await;
    let onc_sum = add_over_oncrpc(&onc_path).await;

    println!("math.add(20, 22) over JSON-RPC -> {json_sum}");
    println!("math.add(20, 22) over ONC RPC  -> {onc_sum}");
    println!(
        "one registered method, two wires: {}",
        if json_sum == onc_sum {
            "consistent"
        } else {
            "MISMATCH"
        }
    );

    json_task.abort();
    onc_task.abort();
    let _ = std::fs::remove_file(&json_path);
    let _ = std::fs::remove_file(&onc_path);
    Ok(())
}
