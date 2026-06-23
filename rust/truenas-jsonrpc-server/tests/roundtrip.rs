//! End-to-end server round-trip over real sockets (AF_UNIX + TCP): a client frames
//! `$/negotiate` then a method call, and gets back the negotiate result + the typed reply —
//! exercising framing, the negotiate state machine, session creation, and the dispatch pump.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use truenas_jsonrpc::{JsonRpcError, JsonRpcMethod, JsonRpcProtocol, MethodDef, RequestCtx};
use truenas_jsonrpc_server::{framing, JsonRpcServer, UnixConfig};

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

#[derive(Deserialize)]
struct AddArgs {
    a: i64,
    b: i64,
}
#[derive(Serialize)]
struct AddResult {
    sum: i64,
}

fn server() -> JsonRpcServer<()> {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("math.add"),
            |a: AddArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(AddResult { sum: a.a + a.b }),
        ))
        .unwrap()
        .build();
    JsonRpcServer::<()>::builder("test-server").protocol("main", proto).build()
}

/// Frame `req`, write it, and read + parse the one framed reply.
async fn call<S>(stream: &mut S, req: Value) -> Value
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = serde_json::to_vec(&req).unwrap();
    stream.write_all(&framing::frame(&bytes)).await.unwrap();
    let reply = framing::read_message(stream, framing::DEFAULT_LIMIT).await.unwrap().unwrap();
    serde_json::from_slice(&reply).unwrap()
}

/// The happy path shared by both transports: negotiate `main`, then `math.add`.
async fn negotiate_then_add<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let neg = call(
        stream,
        json!({"jsonrpc":"2.0","method":"$/negotiate","id":"neg","params":{"protocol":"main"}}),
    )
    .await;
    assert_eq!(neg["result"]["protocol"], "main");
    assert_eq!(neg["result"]["server"], "test-server");
    assert_eq!(neg["result"]["available"], json!(["main"]));
    assert_eq!(neg["id"], "neg");

    let add = call(
        stream,
        json!({"jsonrpc":"2.0","method":"math.add","id":UUID,"params":{"a":2,"b":40}}),
    )
    .await;
    assert_eq!(add["result"]["sum"], 42);
    assert_eq!(add["id"], UUID);
}

#[tokio::test]
async fn unix_round_trip() {
    let path = std::env::temp_dir().join(format!("tnrpc-{}-unix.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = server();
    let listener = JsonRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_unix_listener(listener).await })
    };

    let mut client = UnixStream::connect(&path).await.unwrap();
    negotiate_then_add(&mut client).await;

    task.abort();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn tcp_round_trip() {
    let srv = server();
    let (listener, addr) = JsonRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_tcp_listener(listener).await })
    };

    let mut client = TcpStream::connect(addr).await.unwrap();
    negotiate_then_add(&mut client).await;

    task.abort();
}

#[tokio::test]
async fn negotiate_errors() {
    let srv = server();
    let (listener, addr) = JsonRpcServer::<()>::bind_tcp("127.0.0.1:0").await.unwrap();
    let task = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve_tcp_listener(listener).await })
    };

    // A method call before `$/negotiate` → "negotiate a protocol first".
    let mut c = TcpStream::connect(addr).await.unwrap();
    let r = call(&mut c, json!({"jsonrpc":"2.0","method":"math.add","id":UUID,"params":{"a":1,"b":2}})).await;
    assert_eq!(r["error"]["code"], -32002); // SESSION_NOT_ESTABLISHED
    assert_eq!(r["id"], UUID);

    // An unknown protocol → REQUEST_FAILED, reporting the available names.
    let mut c = TcpStream::connect(addr).await.unwrap();
    let r = call(&mut c, json!({"jsonrpc":"2.0","method":"$/negotiate","id":"x","params":{"protocol":"nope"}})).await;
    assert_eq!(r["error"]["code"], -32803); // REQUEST_FAILED
    assert_eq!(r["error"]["data"]["available"], json!(["main"]));

    task.abort();
}
