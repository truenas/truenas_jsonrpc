//! End-to-end raw-fd **transfer** over a real Unix socket: the server negotiates, runs the
//! `$/transferReady` (+ `$/transferGo`) handshake, hands the blocking fd to the `transfer`
//! callback, and writes the final response — exercising the connection takeover, the writer
//! gate, and the blocking byte-stream helpers. (SCM_RIGHTS fd passing is a later sub-phase.)

use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use truenas_jsonrpc::{
    FileTransfer, JsonRpcError, JsonRpcFdPassMethod, JsonRpcFdTransferMethod, JsonRpcProtocol,
    MethodDef, RequestCtx, TransferDirection,
};
use truenas_jsonrpc_server::{framing, FileTransferExt, JsonRpcServer, UnixConfig};

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const N: usize = 4096;

#[derive(Deserialize)]
struct Args {
    n: usize,
}
#[derive(Serialize)]
struct DownloadReady {
    size: usize,
}
#[derive(Serialize)]
struct DownloadDone {
    sent: usize,
}
#[derive(Serialize)]
struct UploadReady {}
#[derive(Serialize)]
struct UploadDone {
    received: usize,
    sum: u64,
}
#[derive(Serialize)]
struct FdDone {
    content: String,
}

/// Byte `i` of the test stream.
fn pattern_byte(i: usize) -> u8 {
    (i % 251) as u8
}

fn server() -> JsonRpcServer<()> {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        // download: the server produces `n` bytes of the pattern over the fd.
        .fd_transfer_method(JsonRpcFdTransferMethod::<Args, DownloadReady, DownloadDone, _, _>::new(
            MethodDef::new("x.download"),
            TransferDirection::Download,
            |a: &Args, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(DownloadReady { size: a.n }),
            |a: Args, ft: &dyn FileTransfer| {
                let buf: Vec<u8> = (0..a.n).map(pattern_byte).collect();
                ft.write_all(&buf).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                Ok(DownloadDone { sent: a.n })
            },
        ))
        .unwrap()
        // upload: the server consumes `n` bytes from the fd and reports a checksum.
        .fd_transfer_method(JsonRpcFdTransferMethod::<Args, UploadReady, UploadDone, _, _>::new(
            MethodDef::new("x.upload"),
            TransferDirection::Upload,
            |_a: &Args, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(UploadReady {}),
            |a: Args, ft: &dyn FileTransfer| {
                let mut buf = vec![0u8; a.n];
                let got = ft.read_exact(&mut buf).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                let sum: u64 = buf[..got].iter().map(|&b| u64::from(b)).sum();
                Ok(UploadDone { received: got, sum })
            },
        ))
        .unwrap()
        // fd-pass upload: the client passes an fd; the server reads the file it points to.
        .fd_pass_method(JsonRpcFdPassMethod::<Args, UploadReady, FdDone, _, _>::new(
            MethodDef::new("x.recvfd"),
            TransferDirection::Upload,
            |_a: &Args, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(UploadReady {}),
            |_a: Args, ft: &dyn FileTransfer| {
                let fds = ft.recv_fds(1).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                let passed = fds
                    .into_iter()
                    .next()
                    .ok_or_else(|| JsonRpcError::request_failed("no fd received"))?;
                let mut content = String::new();
                std::fs::File::from(passed)
                    .read_to_string(&mut content)
                    .map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                Ok(FdDone { content })
            },
        ))
        .unwrap()
        .build();
    JsonRpcServer::<()>::builder("xfer-server").protocol("main", proto).build()
}

/// Send one fd to `sock` via `SCM_RIGHTS` (the client side of fd passing).
fn send_one_fd(sock: RawFd, fd: RawFd) {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixAddr};
    let fds = [fd];
    let iov = [std::io::IoSlice::new(&[0u8])];
    let cmsgs = [ControlMessage::ScmRights(&fds)];
    sendmsg::<UnixAddr>(sock, &iov, &cmsgs, MsgFlags::empty(), None).unwrap();
}

fn unique(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tnrpc-xfer-{}-{}.sock", std::process::id(), tag))
}

async fn send_framed(c: &mut UnixStream, v: &Value) {
    c.write_all(&framing::frame(&serde_json::to_vec(v).unwrap())).await.unwrap();
}

async fn read_framed(c: &mut UnixStream) -> Value {
    let msg = framing::read_message(c, framing::DEFAULT_LIMIT).await.unwrap().unwrap();
    serde_json::from_slice(&msg).unwrap()
}

async fn negotiate(c: &mut UnixStream) {
    send_framed(c, &json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}})).await;
    assert_eq!(read_framed(c).await["result"]["protocol"], "main");
}

/// Bind, spawn the accept loop, connect a client.
async fn connect(tag: &str) -> (UnixStream, std::path::PathBuf, tokio::task::JoinHandle<std::io::Result<()>>) {
    let path = unique(tag);
    let _ = std::fs::remove_file(&path);
    let srv = server();
    let listener = JsonRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_unix_listener(listener).await })
    };
    let client = UnixStream::connect(&path).await.unwrap();
    (client, path, task)
}

#[tokio::test]
async fn download_streams_then_final_response() {
    let (mut c, path, task) = connect("dl").await;
    negotiate(&mut c).await;

    send_framed(&mut c, &json!({"jsonrpc":"2.0","method":"x.download","id":UUID,"params":{"n":N}})).await;
    let ready = read_framed(&mut c).await;
    assert_eq!(ready["method"], "$/transferReady");
    assert_eq!(ready["params"]["id"], UUID);
    assert_eq!(ready["params"]["direction"], "download");
    assert_eq!(ready["params"]["result"]["size"], N);

    // Client signals it has paused its reader, then reads the raw stream.
    send_framed(&mut c, &json!({"jsonrpc":"2.0","method":"$/transferGo"})).await;
    let mut buf = vec![0u8; N];
    c.read_exact(&mut buf).await.unwrap();
    assert!(buf.iter().enumerate().all(|(i, &b)| b == pattern_byte(i)), "stream pattern mismatch");

    // Normal JSON-RPC resumes: the final response follows the raw stream.
    let fin = read_framed(&mut c).await;
    assert_eq!(fin["result"]["sent"], N);
    assert_eq!(fin["id"], UUID);

    task.abort();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn upload_consumes_stream_then_final_response() {
    let (mut c, path, task) = connect("ul").await;
    negotiate(&mut c).await;

    send_framed(&mut c, &json!({"jsonrpc":"2.0","method":"x.upload","id":UUID,"params":{"n":N}})).await;
    let ready = read_framed(&mut c).await;
    assert_eq!(ready["params"]["direction"], "upload");

    // After ready, the client streams the raw bytes the server consumes.
    let buf: Vec<u8> = (0..N).map(pattern_byte).collect();
    c.write_all(&buf).await.unwrap();

    let fin = read_framed(&mut c).await;
    assert_eq!(fin["result"]["received"], N);
    let expected: u64 = (0..N).map(|i| u64::from(pattern_byte(i))).sum();
    assert_eq!(fin["result"]["sum"], expected);
    assert_eq!(fin["id"], UUID);

    task.abort();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn fd_pass_upload_passes_a_descriptor() {
    let (mut c, path, task) = connect("fd").await;
    negotiate(&mut c).await;

    send_framed(&mut c, &json!({"jsonrpc":"2.0","method":"x.recvfd","id":UUID,"params":{"n":0}})).await;
    let ready = read_framed(&mut c).await;
    assert_eq!(ready["params"]["direction"], "upload");

    // A pipe holding a known payload; pass its read end to the server via SCM_RIGHTS.
    let (r, w) = nix::unistd::pipe().unwrap();
    nix::unistd::write(&w, b"hello-fd-pass").unwrap();
    drop(w); // close the write end so the server's read sees EOF after the payload
    send_one_fd(c.as_raw_fd(), r.as_raw_fd());
    drop(r); // the kernel dup'd it for the peer; our copy is no longer needed

    let fin = read_framed(&mut c).await;
    assert_eq!(fin["result"]["content"], "hello-fd-pass");
    assert_eq!(fin["id"], UUID);

    task.abort();
    let _ = std::fs::remove_file(&path);
}
