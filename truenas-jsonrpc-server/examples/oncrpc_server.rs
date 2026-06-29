//! Example: a faithful **ONC RPC** (Sun RPC, RFC 5531) server — the reference *second* engine —
//! with an in-process client that speaks the real wire, so the example runs to completion.
//!
//! ONC RPC is the canonical XDR record-marking RPC. This demo's wire is validated against FreeBSD's
//! in-tree implementation: the message layout is `include/rpc/rpc_msg.h`, the auth flavors are
//! `include/rpc/auth.h`, and the record marking is `lib/libc/xdr/xdr_rec.c`. The demo program —
//! number `0x2000_0001`, in RFC 5531's user-defined range `0x2000_0000..=0x3fff_ffff` — exposes:
//!   - procedure 0: `NULL`, the conventional no-op probe (`void -> void`)
//!   - procedure 1: `add(int32, int32) -> int64`
//!
//! The wire, bottom to top:
//!   - **Transport (1):** an AF_UNIX stream.
//!   - **Framing (2):** RFC 5531 §11 *record marking* — a 4-byte big-endian fragment header whose
//!     high bit marks the last fragment and whose low 31 bits hold the fragment length, then that
//!     many bytes. (FreeBSD `xdr_rec.c`: `LAST_FRAG = 1u << 31`.)
//!   - **Codec (3):** XDR (RFC 4506) — big-endian, 4-byte aligned (`truenas-xdr`).
//!   - **Envelope (4):** the ONC RPC `rpc_msg` CALL/REPLY union:
//!     ```text
//!     CALL  = xid, mtype=0(CALL), rpcvers=2, prog, vers, proc, cred:opaque_auth, verf:opaque_auth, args
//!     REPLY = xid, mtype=1(REPLY), reply_stat,
//!               MSG_ACCEPTED(0) -> verf:opaque_auth, accept_stat, [results | versions | void]
//!               MSG_DENIED(1)   -> ...
//!     opaque_auth = (flavor:u32, body:opaque<400>);  AUTH_NONE = (0, empty)
//!     ```
//!
//! Run: `cargo run -p truenas-jsonrpc-server --example oncrpc_server`

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use truenas_jsonrpc_server::{JsonRpcServer, UnixConfig};
use truenas_xdr::{from_bytes, from_bytes_with, to_bytes, Strictness, VarOpaque};

// The demo program (must match the built-in engine).
const PROG: u32 = 0x2000_0001;
const VERS: u32 = 1;
const PROC_NULL: u32 = 0;
const PROC_ADD: u32 = 1;

// ONC RPC message constants (FreeBSD include/rpc/rpc_msg.h, include/rpc/auth.h).
const MSG_CALL: u32 = 0;
const RPC_VERSION: u32 = 2;
const AUTH_NONE: u32 = 0;
const MSG_ACCEPTED: u32 = 0;
const ACCEPT_SUCCESS: u32 = 0;

// Record marking (FreeBSD lib/libc/xdr/xdr_rec.c): the last-fragment bit.
const RM_LAST: u32 = 0x8000_0000;

/// Wrap `payload` as a single last-fragment record: `[4-byte header][payload]`, where
/// `header = LAST_FRAG | length`.
fn rm_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (RM_LAST | payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// Build a record-marked `rpc_msg` CALL for the demo program with `AUTH_NONE` credentials.
fn call(xid: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
    // The CALL prefix, field-for-field as it lies on the wire; `cred` and `verf` are both
    // AUTH_NONE = (flavor 0, empty body). The procedure arguments follow.
    let prefix = (
        xid,
        MSG_CALL,
        RPC_VERSION,
        PROG,
        VERS,
        procedure,
        AUTH_NONE,
        VarOpaque(Vec::new()), // cred
        AUTH_NONE,
        VarOpaque(Vec::new()), // verf
    );
    let mut msg = to_bytes(&prefix).unwrap();
    msg.extend_from_slice(args);
    rm_frame(&msg)
}

/// Read one record-marked reply and return the accepted-reply result bytes. Asserts the reply is
/// accepted + successful (this demo only issues calls that succeed).
async fn read_result(stream: &mut UnixStream) -> Vec<u8> {
    // The server emits single-fragment replies, so one 4-byte header precedes the message.
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let len = (u32::from_be_bytes(header) & !RM_LAST) as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await.unwrap();
    // REPLY: xid, mtype, reply_stat, then accepted_reply = verf(flavor, body), accept_stat, results.
    let ((_xid, _mtype, reply_stat, _verf_flavor, _verf_body, accept_stat), results) =
        from_bytes_with::<(u32, u32, u32, u32, VarOpaque, u32)>(&msg, Strictness::Lenient).unwrap();
    assert_eq!(
        (reply_stat, accept_stat),
        (MSG_ACCEPTED, ACCEPT_SUCCESS),
        "expected an accepted, successful reply"
    );
    results.to_vec()
}

/// Render bytes as space-separated hex — to show the binary wire concretely.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    let path = std::env::temp_dir().join(format!("oncrpc-example-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path); // bind fails if the path already exists

    // 1. Build a server and serve the built-in ONC RPC engine on a Unix socket in the background.
    //    The wire protocol is bound to the listener (per-listener engine selection); this server
    //    registers no JSON-RPC protocols — the ONC RPC engine routes on its own program table.
    let server = JsonRpcServer::<()>::builder("oncrpc-example").build();
    let listener = JsonRpcServer::<()>::bind_unix(&UnixConfig::new(&path))?;
    let server_task =
        tokio::spawn(async move { server.serve_oncrpc_unix_listener(listener).await });

    // 2. A client that speaks the real ONC RPC wire.
    let mut client = UnixStream::connect(&path).await?;

    // Procedure 0: the NULL probe — void args, void result (the standard "are you there?" call).
    // Print its raw bytes so the record marking + rpc_msg envelope are visible on the wire.
    let null_call = call(1, PROC_NULL, &[]);
    println!("NULL call wire bytes  -> {}", hex(&null_call));
    client.write_all(&null_call).await?;
    let null_result = read_result(&mut client).await;
    println!("NULL probe (proc 0)   -> accepted, success, {}-byte result", null_result.len());

    // Procedure 1: add(20, 22). The args are two XDR int32; the result is one XDR int64.
    let args = to_bytes(&(20i32, 22i32)).unwrap();
    client.write_all(&call(2, PROC_ADD, &args)).await?;
    let sum: i64 = from_bytes(&read_result(&mut client).await).unwrap();
    println!("add(20, 22) (proc 1)  -> {sum}");

    server_task.abort();
    let _ = std::fs::remove_file(&path);
    Ok(())
}
