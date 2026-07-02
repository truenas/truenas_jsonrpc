//! End-to-end demo: a consumer crate that generates server bindings from `json-idl/demo.json`
//! and dispatches through the live `truenas-rpc` core — proving the generated code
//! compiles against the core and works over both the JSON and XDR wires. Also serves as the
//! reference for the documented consumer layout (`json-idl/` + build.rs → include! → impl
//! `Handlers` → register → dispatch).

// The generated server bindings (structs + `Handlers` trait + `register`). Wrapped in a
// module so any leading inner attributes are well-formed and clippy is silenced on generated
// code, then re-exported at the crate root.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod generated {
    // The shared `$defs` structs, then the server (`Handlers` + `register`) and the typed client
    // (`DemoClient`) — both reference the one set of types.
    include!(concat!(env!("OUT_DIR"), "/types_gen.rs"));
    include!(concat!(env!("OUT_DIR"), "/server_gen.rs"));
    include!(concat!(env!("OUT_DIR"), "/client_gen.rs"));
}
pub use generated::*;

// Proof that a **standalone** client compiles from just the shared types + client bindings (no server
// module): the `DemoClient` methods resolve the `$defs` structs from `types_gen.rs` alone. If the
// client re-emitted no types, this would fail to compile.
#[allow(clippy::all, clippy::pedantic, missing_docs, dead_code)]
mod standalone_client {
    include!(concat!(env!("OUT_DIR"), "/types_gen.rs"));
    include!(concat!(env!("OUT_DIR"), "/client_gen.rs"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use serde_json::{json, Value};
    use truenas_rpc::{
        tnfilter, CompiledFilters, CompiledOptions, Dispatched, Filtered, JsonRpcError,
        JsonRpcProtocol, NullOutbound, RequestCtx, Session,
    };
    // The buffered stream helpers (`write_all`/`read_exact`) for the transfer handlers live on the
    // server-side ext trait; the demo drives raw-fd transfers only from its test harness.
    use truenas_rpc_server::FileTransferExt;

    const RID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

    /// Hand-written handlers — one method per non-subscription/non-python RPC. A missing or
    /// mistyped method here is a compile error (the point of the generated `Handlers` trait).
    struct DemoHandlers;

    impl Handlers<()> for DemoHandlers {
        fn greet(&self, req: GreetArgs, _cx: &RequestCtx<()>) -> Result<GreetResult, JsonRpcError> {
            Ok(GreetResult { message: format!("hi {}", req.name) })
        }
        fn login(&self, req: LoginArgs, _cx: &RequestCtx<()>) -> Result<LoginResult, JsonRpcError> {
            // `password` is a `Secret<String>` (deref to read); `token` is `Secret<String>`.
            Ok(LoginResult { token: format!("tok-{}", &*req.password).into(), ok: !req.user.is_empty() })
        }
        async fn add(&self, req: AddArgs, _cx: RequestCtx<()>) -> Result<AddResult, JsonRpcError> {
            Ok(AddResult { sum: req.a + req.b })
        }
        fn query(
            &self,
            _req: QueryArgs,
            _cx: &RequestCtx<()>,
            f: &CompiledFilters,
            o: &CompiledOptions,
        ) -> Result<Filtered<Item>, JsonRpcError> {
            // Typed rows: `tnfilter` filters via a Value view but returns the typed `Item`s,
            // so the result can be encoded to either the JSON or the XDR wire.
            let items = vec![
                Item { id: 1, name: "a".into() },
                Item { id: 2, name: "b".into() },
                Item { id: 3, name: "a".into() },
            ];
            Ok(tnfilter(items, f, o)?)
        }
        fn download_ready(
            &self,
            req: &TransferArgs,
            _cx: &RequestCtx<()>,
        ) -> Result<DownloadReady, JsonRpcError> {
            // The typed `$/transferReady` interim: how many bytes the client should expect.
            Ok(DownloadReady { size: req.n })
        }
        fn download(
            &self,
            req: TransferArgs,
            ft: &dyn truenas_rpc::FileTransfer,
        ) -> Result<DownloadDone, JsonRpcError> {
            // Server produces the stream: write `n` pattern bytes onto the lent connection fd.
            let buf: Vec<u8> = (0..req.n as usize).map(|i| (i % 251) as u8).collect();
            ft.write_all(&buf).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
            Ok(DownloadDone { sent: req.n })
        }
        fn upload_ready(
            &self,
            _req: &TransferArgs,
            _cx: &RequestCtx<()>,
        ) -> Result<Value, JsonRpcError> {
            // No typed interim declared in the IDL → a free-form `serde_json::Value`.
            Ok(json!({}))
        }
        fn upload(
            &self,
            req: TransferArgs,
            ft: &dyn truenas_rpc::FileTransfer,
        ) -> Result<UploadDone, JsonRpcError> {
            // Client produces the stream: read `n` bytes off the lent connection fd.
            let mut buf = vec![0u8; req.n as usize];
            let got =
                ft.read_exact(&mut buf).map_err(|e| JsonRpcError::request_failed(e.to_string()))?;
            Ok(UploadDone { received: got as i64 })
        }
    }

    fn proto() -> JsonRpcProtocol<()> {
        register(JsonRpcProtocol::<()>::builder("demo", "1.0.0"), Arc::new(DemoHandlers))
            .expect("register")
            .build()
    }

    fn session(p: &JsonRpcProtocol<()>) -> Arc<Session<()>> {
        p.new_session(Some(()), Arc::new(NullOutbound))
    }

    async fn json_call(p: &JsonRpcProtocol<()>, method: &str, params: Value) -> Value {
        let wire = json!({"jsonrpc": "2.0", "method": method, "id": RID, "params": params});
        let s = session(p);
        match p.dispatch(wire.to_string().as_bytes(), &s).await {
            Dispatched::Reply(b) => serde_json::from_slice(&b).unwrap(),
            Dispatched::Nothing => panic!("expected a reply"),
            Dispatched::Transfer(_) | Dispatched::Passthrough(_) | Dispatched::Sessions { .. } => {
                // `json_call` is only used for plain/secret/filterable methods; the transfer
                // methods are driven over a real socket in `generated_client_transfers_*`.
                unreachable!("json_call is not used for transfer / passthrough / sessions methods")
            }
        }
    }

    #[tokio::test]
    async fn plain_method_dispatches() {
        let v = json_call(&proto(), "greet", json!({"name": "world"})).await;
        assert_eq!(v["result"]["message"], "hi world");
    }

    #[tokio::test]
    async fn secret_fields_round_trip() {
        // `password` decodes from a JSON string into `Secret<String>`; `token` (also Secret)
        // serializes transparently back to a JSON string.
        let v = json_call(&proto(), "login", json!({"user": "u", "password": "pw"})).await;
        assert_eq!(v["result"]["ok"], true);
        assert_eq!(v["result"]["token"], "tok-pw");
    }

    #[tokio::test]
    async fn filterable_method_applies_the_query() {
        let v = json_call(&proto(), "items.query", json!({"query-filters": [["name", "=", "a"]]})).await;
        let rows = v["result"].as_array().unwrap();
        assert_eq!(rows.len(), 2); // id 1 and 3
        assert_eq!(rows[0]["id"], 1);
        assert_eq!(rows[1]["id"], 3);
    }

    #[tokio::test]
    async fn generated_client_over_a_live_server() {
        // The full pipeline: json-idl → generated server (`register`) served over `JsonRpc`, and the
        // json-idl → generated `DemoClient` driving it over a real AF_UNIX socket via the client engine.
        use truenas_rpc_client::{ClientConfig, Endpoint, JsonRpcClient, QueryResult};
        use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

        let path = std::env::temp_dir().join(format!("demo-e2e-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let server = TruenasRpcServer::<()>::builder("demo").protocol("demo", proto()).build();
        let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
        let task = tokio::spawn(async move { server.serve_unix_listener(listener, JsonRpc).await });

        let (jc, negotiated, _notifs) =
            JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "demo", ClientConfig::default())
                .await
                .unwrap();
        assert_eq!(negotiated.protocol, "demo");
        let client = DemoClient::new(jc);

        // Plain typed call, then the dual-wire `add`, then a secret round-trip.
        assert_eq!(client.greet(GreetArgs { name: "world".into() }).await.unwrap().message, "hi world");
        assert_eq!(client.add(AddArgs { a: 20, b: 22 }).await.unwrap().sum, 42);
        let login =
            client.login(LoginArgs { user: "u".into(), password: "pw".to_string().into() }).await.unwrap();
        assert!(login.ok);

        // The filterable query: no filter → all three rows.
        match client.query(QueryArgs {}, None, None).await.unwrap() {
            QueryResult::Rows(rows) => assert_eq!(rows.len(), 3),
            other => panic!("expected rows, got {other:?}"),
        }

        task.abort();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn generated_client_transfers_over_a_live_server() {
        // The generated `DemoClient::download` / `::upload` drive raw-fd transfers end-to-end against
        // the generated `register()` (which wires `fd_transfer_method`) over a live AF_UNIX socket —
        // the callback is handed a blocking `TransferHandle` for the self-delimiting bulk stream.
        use truenas_rpc_client::{ClientConfig, Endpoint, JsonRpcClient};
        use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

        // Larger than a socket buffer so the stream's partial read/write loops are exercised.
        const N: usize = 256 * 1024;

        let path = std::env::temp_dir().join(format!("demo-xfer-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let server = TruenasRpcServer::<()>::builder("demo").protocol("demo", proto()).build();
        let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
        let task = tokio::spawn(async move { server.serve_unix_listener(listener, JsonRpc).await });

        let (jc, _neg, _notifs) =
            JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "demo", ClientConfig::default())
                .await
                .unwrap();
        let client = DemoClient::new(jc);

        // Download: the server streams N pattern bytes; the callback reads and verifies them.
        let done = client
            .download(TransferArgs { n: N as i64 }, move |ht| {
                let mut buf = vec![0u8; N];
                ht.read_exact(&mut buf)?;
                if buf.iter().enumerate().any(|(i, &b)| b != (i % 251) as u8) {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt download"));
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(done.sent, N as i64, "the server's final reply follows the stream");

        // Upload: the callback streams N pattern bytes; the server reports how many it read.
        let done = client
            .upload(TransferArgs { n: N as i64 }, move |ht| {
                let buf: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
                ht.write_all(&buf)
            })
            .await
            .unwrap();
        assert_eq!(done.received, N as i64);

        task.abort();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn add_dispatches_over_json_and_xdr() {
        let p = proto();

        // JSON wire.
        let v = json_call(&p, "add", json!({"a": 2, "b": 3})).await;
        assert_eq!(v["result"]["sum"], 5);

        // XDR binary wire — the same generated `add` method, addressed by its proc-id (1001).
        let id = [0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00];
        let params = truenas_xdr::to_bytes(&AddArgs { a: 2, b: 3 }).unwrap();
        let request = truenas_xdr::frame::build_request(1001, Some(id), &params).unwrap();
        let s = session(&p);
        let reply = p.dispatch(&request, &s).await.into_bytes().unwrap();
        let parsed = truenas_xdr::frame::parse_reply(&reply).unwrap();
        assert_eq!(parsed.status, truenas_xdr::frame::STATUS_OK);
        let result: AddResult = truenas_xdr::from_bytes(parsed.body).unwrap();
        assert_eq!(result.sum, 5);
    }
}
