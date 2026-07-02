//! SCM_RIGHTS fd passing end-to-end (the `fd-passing` feature): the client passes a descriptor to an
//! upload fd-pass method (the server reads through it), and receives a descriptor from a download
//! fd-pass method (the client reads through it). AF_UNIX only.
//!
//! Run with: `cargo test -p truenas-rpc-client --features fd-passing`
#![cfg(feature = "fd-passing")]

use std::io::Read;
use std::os::fd::AsRawFd;

use serde::{Deserialize, Serialize};
use truenas_rpc::{
    FileTransfer, JsonRpcError, JsonRpcProtocol, MethodDef, RequestCtx, RpcFdPassMethod,
    TransferDirection,
};
use truenas_rpc_client::{ClientConfig, Endpoint, JsonRpcClient, JsonRpcMethod};
use truenas_rpc_server::{FileTransferExt, JsonRpc, TruenasRpcServer, UnixConfig};

#[derive(Deserialize, Serialize)]
struct Args {
    n: usize,
}
#[derive(Serialize)]
struct Ready {}
#[derive(Deserialize, Serialize)]
struct RecvDone {
    content: String,
}
#[derive(Deserialize, Serialize)]
struct SendDone {
    sent: bool,
}

fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("fd", "1")
        // Upload fd-pass: the client passes a descriptor; the server reads its content.
        .fd_pass_method(RpcFdPassMethod::<Args, Ready, RecvDone, _, _>::new(
            MethodDef::new("x.recvfd"),
            TransferDirection::Upload,
            |_a: &Args, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(Ready {}),
            |_a: Args, ft: &dyn FileTransfer| {
                let fds = ft.recv_fds(1).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                let fd = fds
                    .into_iter()
                    .next()
                    .ok_or_else(|| JsonRpcError::request_failed("no fd received"))?;
                let mut content = String::new();
                std::fs::File::from(fd)
                    .read_to_string(&mut content)
                    .map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                Ok(RecvDone { content })
            },
        ))
        .unwrap()
        // Download fd-pass: the server hands the client a descriptor holding known content.
        .fd_pass_method(RpcFdPassMethod::<Args, Ready, SendDone, _, _>::new(
            MethodDef::new("x.sendfd"),
            TransferDirection::Download,
            |_a: &Args, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(Ready {}),
            |_a: Args, ft: &dyn FileTransfer| {
                let path = std::env::temp_dir().join(format!("tnrpc-fd-srv-{}.dat", std::process::id()));
                std::fs::write(&path, b"server-sent-fd")
                    .map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                let file = std::fs::File::open(&path)
                    .map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                ft.send_fds(&[file.as_raw_fd()])
                    .map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
                let _ = std::fs::remove_file(&path);
                Ok(SendDone { sent: true })
            },
        ))
        .unwrap()
        .build()
}

async fn connect(tag: &str) -> (std::path::PathBuf, JsonRpcClient) {
    let path = std::env::temp_dir().join(format!("tnrpc-fdpass-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = TruenasRpcServer::<()>::builder("fd-server").protocol("fd", proto()).build();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    tokio::spawn(async move { srv.serve_unix_listener(listener, JsonRpc).await });
    let (client, _neg, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "fd", ClientConfig::default())
            .await
            .unwrap();
    (path, client)
}

#[tokio::test]
async fn send_fds_passes_a_descriptor_to_the_server() {
    let (path, client) = connect("send").await;

    // A file the server will read through the passed descriptor.
    let src = std::env::temp_dir().join(format!("tnrpc-fd-cli-{}.dat", std::process::id()));
    std::fs::write(&src, b"client-sent-fd").unwrap();
    let file = std::fs::File::open(&src).unwrap();

    let params = serde_json::to_vec(&Args { n: 0 }).unwrap();
    let reply = client
        .send_fds(&JsonRpcMethod::Name("x.recvfd".into()), &params, &[file.as_raw_fd()])
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<RecvDone>(&reply).unwrap().content, "client-sent-fd");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn recv_fds_receives_a_descriptor_from_the_server() {
    let (path, client) = connect("recv").await;

    let params = serde_json::to_vec(&Args { n: 0 }).unwrap();
    let (reply, fds) =
        client.recv_fds(&JsonRpcMethod::Name("x.sendfd".into()), &params, 1).await.unwrap();
    assert!(serde_json::from_slice::<SendDone>(&reply).unwrap().sent);
    assert_eq!(fds.len(), 1);

    // Read the received descriptor → the content the server wrote.
    let mut content = String::new();
    std::fs::File::from(fds.into_iter().next().unwrap()).read_to_string(&mut content).unwrap();
    assert_eq!(content, "server-sent-fd");

    let _ = std::fs::remove_file(&path);
}
