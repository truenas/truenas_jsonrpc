//! End-to-end raw-fd **transfer** from the client engine against a live `TruenasRpcServer`:
//! [`Client::transfer`] sends the request, does the `$/transferReady` (+ `$/transferGo`) handshake,
//! **parks the reader**, hands the blocking fd to a callback, then resumes and returns the server's
//! final reply. The callbacks drive the stream **zero-copy** (like the Python client): a download
//! `splice`s the socket into a file, an upload `sendfile`s a file into the socket — the payload never
//! enters the process. `N` exceeds a socket buffer, so the partial loops and backpressure are real.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use truenas_rpc::{
    FileTransfer, JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcFdTransferMethod,
    TransferDirection,
};
use truenas_rpc_client::{ClientConfig, Endpoint, JsonRpcClient, JsonRpcMethod};
use truenas_rpc_server::{FileTransferExt, JsonRpc, TruenasRpcServer, UnixConfig};

const N: usize = 1_000_000;

fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

#[derive(Deserialize, Serialize)]
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

/// A protocol with a `download` (server produces) and an `upload` (server consumes) transfer method.
fn transfer_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("xfer", "1")
        .fd_transfer_method(RpcFdTransferMethod::<Args, DownloadReady, DownloadDone, _, _>::new(
            MethodDef::new("x.download"),
            TransferDirection::Download,
            |a: &Args, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(DownloadReady { size: a.n }),
            |a: Args, ft: &dyn FileTransfer| {
                let buf: Vec<u8> = (0..a.n).map(pattern).collect();
                ft.write_all(&buf).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                Ok(DownloadDone { sent: a.n })
            },
        ))
        .unwrap()
        .fd_transfer_method(RpcFdTransferMethod::<Args, UploadReady, UploadDone, _, _>::new(
            MethodDef::new("x.upload"),
            TransferDirection::Upload,
            |_a: &Args, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(UploadReady {}),
            |a: Args, ft: &dyn FileTransfer| {
                let mut buf = vec![0u8; a.n];
                let got =
                    ft.read_exact(&mut buf).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                let sum: u64 = buf[..got].iter().map(|&b| u64::from(b)).sum();
                Ok(UploadDone { received: got, sum })
            },
        ))
        .unwrap()
        .build()
}

async fn serve(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("tnrpc-xfer-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv =
        TruenasRpcServer::<()>::builder("xfer-server").protocol("xfer", transfer_proto()).build();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    tokio::spawn(async move { srv.serve_unix_listener(listener, JsonRpc).await });
    path
}

#[tokio::test]
async fn download_splices_the_stream_into_a_file() {
    let path = serve("dl").await;
    let (client, _neg, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "xfer", ClientConfig::default())
            .await
            .unwrap();

    let out = std::env::temp_dir().join(format!("tnrpc-xfer-dl-out-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&out);
    let out_cb = out.clone();
    let params = serde_json::to_vec(&Args { n: N }).unwrap();
    let reply = client
        .transfer(&JsonRpcMethod::Name("x.download".to_string()), &params, move |ht| {
            // Zero-copy: `splice` the stream straight into a file — bytes never enter the process.
            let file = std::fs::File::create(&out_cb)?;
            let got = ht.recvfile(&file, N)?;
            if got != N {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short download"));
            }
            Ok(())
        })
        .await
        .unwrap();

    let data = std::fs::read(&out).unwrap();
    assert_eq!(data.len(), N);
    assert!(data.iter().enumerate().all(|(i, &b)| b == pattern(i)), "download stream is byte-exact");
    let done: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(done["sent"], N, "the server's final reply follows the stream");

    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn upload_sendfiles_a_file_into_the_stream() {
    let path = serve("ul").await;
    let (client, _neg, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "xfer", ClientConfig::default())
            .await
            .unwrap();

    // A source file of N pattern bytes to sendfile from.
    let src = std::env::temp_dir().join(format!("tnrpc-xfer-ul-src-{}.dat", std::process::id()));
    std::fs::write(&src, (0..N).map(pattern).collect::<Vec<u8>>()).unwrap();
    let src_cb = src.clone();

    let params = serde_json::to_vec(&Args { n: N }).unwrap();
    let reply = client
        .transfer(&JsonRpcMethod::Name("x.upload".to_string()), &params, move |ht| {
            // Zero-copy: `sendfile` straight from the file into the stream.
            let file = std::fs::File::open(&src_cb)?;
            let sent = ht.sendfile(&file, N)?;
            if sent != N {
                return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "short upload"));
            }
            Ok(())
        })
        .await
        .unwrap();

    let done: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(done["received"], N);
    let expected: u64 = (0..N).map(|i| u64::from(pattern(i))).sum();
    assert_eq!(done["sum"].as_u64().unwrap(), expected);

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&path);
}
