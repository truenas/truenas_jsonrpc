//! Raw-fd transfer **seam** (Phase 1): a transfer method authorizes + negotiates in the
//! dispatch core — emitting a `$/transferReady` envelope — and yields a [`Dispatched::Transfer`]
//! directive whose `complete` runs the `transfer` callback over a [`FileTransfer`]. Exercised
//! end-to-end through the public API with a **fake** fd; no sockets (the server crate owns the
//! real fd handoff).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_rpc::{
    AuditOutcome,
    Dispatched, FileTransfer, JsonRpcError, RpcFdPassMethod, RpcFdTransferMethod,
    JsonRpcProtocol, RequestInfo, MethodDef, NullOutbound, RequestCtx, Roles, Session,
    TransferDirection,
};

const RID: &str = "123e4567-e89b-12d3-a456-426614174000";

#[derive(Deserialize)]
struct SendArgs {
    dataset: String,
}
#[derive(Serialize, Deserialize)]
struct ReadyInfo {
    size: i64,
}
#[derive(Serialize, Deserialize)]
struct Done {
    ok: bool,
}

/// Stand-in for the connection's fd — the core never touches it; a `transfer` callback may
/// read it via [`FileTransfer::as_raw_fd`]. The real fd-backed impl lives in the server crate.
struct FakeFt(i32);
impl FileTransfer for FakeFt {
    fn as_raw_fd(&self) -> i32 {
        self.0
    }
}

fn session(p: &JsonRpcProtocol<()>) -> Arc<Session<()>> {
    p.new_session(Some(()), Arc::new(NullOutbound))
}

fn request(params: Value, id: Option<&str>) -> Vec<u8> {
    let mut req = json!({"jsonrpc": "2.0", "method": "zfs.send", "params": params});
    if let Some(id) = id {
        req["id"] = json!(id);
    }
    req.to_string().into_bytes()
}

/// A download transfer method with neither authz nor audit (the `need_snapshot = false` path).
fn download_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("t", "1")
        .fd_transfer_method(RpcFdTransferMethod::<SendArgs, ReadyInfo, Done, _, _>::new(
            MethodDef::new("zfs.send"),
            TransferDirection::Download,
            |a: &SendArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(ReadyInfo { size: a.dataset.len() as i64 })
            },
            |a: SendArgs, ft: &dyn FileTransfer| {
                assert_eq!(ft.as_raw_fd(), -1);
                Ok::<_, JsonRpcError>(Done { ok: !a.dataset.is_empty() })
            },
        ))
        .unwrap()
        .build()
}

#[tokio::test]
async fn download_round_trip() {
    let p = download_proto();
    let s = session(&p);
    let Dispatched::Transfer(t) =
        p.dispatch(&request(json!({"dataset": "tank/x"}), Some(RID)), &s).await
    else {
        panic!("expected a transfer directive");
    };
    assert_eq!(t.request_id(), RID);
    assert_eq!(t.direction(), TransferDirection::Download);
    assert!(!t.is_fd_pass());
    assert!(format!("{t:?}").contains("Transfer"));
    // The `$/transferReady` envelope carries the interim `negotiate` result verbatim.
    let ready: Value = serde_json::from_slice(t.ready_bytes()).unwrap();
    assert_eq!(ready["jsonrpc"], "2.0");
    assert_eq!(ready["method"], "$/transferReady");
    assert_eq!(ready["params"]["id"], RID);
    assert_eq!(ready["params"]["direction"], "download");
    assert_eq!(ready["params"]["result"]["size"], 6); // "tank/x".len()
    // `complete` runs the transfer callback → the final success response.
    let reply: Value = serde_json::from_slice(&t.complete(&FakeFt(-1))).unwrap();
    assert_eq!(reply["id"], RID);
    assert_eq!(reply["result"]["ok"], true);
}

#[tokio::test]
async fn upload_fd_pass_directive() {
    let p = JsonRpcProtocol::<()>::builder("t", "1")
        .fd_pass_method(RpcFdPassMethod::<SendArgs, ReadyInfo, Done, _, _>::new(
            MethodDef::new("zfs.send"),
            TransferDirection::Upload,
            |_a: &SendArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(ReadyInfo { size: 0 }),
            |_a: SendArgs, _ft: &dyn FileTransfer| Ok::<_, JsonRpcError>(Done { ok: true }),
        ))
        .unwrap()
        .build();
    let s = session(&p);
    let Dispatched::Transfer(t) =
        p.dispatch(&request(json!({"dataset": "d"}), Some(RID)), &s).await
    else {
        panic!("expected a transfer directive");
    };
    assert_eq!(t.direction(), TransferDirection::Upload);
    assert!(t.is_fd_pass()); // SCM_RIGHTS → AF_UNIX-only (enforced by the server)
    let ready: Value = serde_json::from_slice(t.ready_bytes()).unwrap();
    assert_eq!(ready["params"]["direction"], "upload");
    let reply: Value = serde_json::from_slice(&t.complete(&FakeFt(7))).unwrap();
    assert_eq!(reply["result"]["ok"], true);
}

#[tokio::test]
async fn notification_is_invalid_request() {
    // A transfer has a multi-step reply, so it can't be a notification (no id).
    let p = download_proto();
    let s = session(&p);
    let reply = p
        .dispatch(&request(json!({"dataset": "x"}), None), &s)
        .await
        .into_bytes()
        .expect("a transfer notification still gets an error reply");
    let v: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(v["error"]["code"], -32600); // INVALID_REQUEST
}

#[tokio::test]
async fn bad_params_are_invalid_params() {
    // `dataset` must be a string → typed decode fails before authz/negotiate.
    let p = download_proto();
    let s = session(&p);
    let reply = p
        .dispatch(&request(json!({"dataset": 123}), Some(RID)), &s)
        .await
        .into_bytes()
        .unwrap();
    let v: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(v["error"]["code"], -32602); // INVALID_PARAMS
}

/// Build an audited download method whose callbacks are supplied by the caller, plus a sink
/// that counts audit entries.
fn audited_proto<NF, TF>(negotiate: NF, transfer: TF) -> (JsonRpcProtocol<()>, Arc<AtomicUsize>)
where
    NF: Fn(&SendArgs, &RequestCtx<()>) -> Result<ReadyInfo, JsonRpcError> + Send + Sync + 'static,
    TF: Fn(SendArgs, &dyn FileTransfer) -> Result<Done, JsonRpcError> + Send + Sync + 'static,
{
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let p = JsonRpcProtocol::<()>::builder("t", "1")
        .fd_transfer_method(RpcFdTransferMethod::<SendArgs, ReadyInfo, Done, _, _>::new(
            MethodDef::new("zfs.send").audit(),
            TransferDirection::Download,
            negotiate,
            transfer,
        ))
        .unwrap()
        .audit_sink(move |_r: &RequestInfo, _outcome: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
            h.fetch_add(1, Ordering::SeqCst);
        })
        .build();
    (p, hits)
}

#[tokio::test]
async fn negotiate_refusal_is_audited() {
    let (p, hits) = audited_proto(
        |_a, _cx| Err::<ReadyInfo, _>(JsonRpcError::request_failed("nope")),
        |_a, _ft| Ok::<_, JsonRpcError>(Done { ok: true }),
    );
    let s = session(&p);
    let reply =
        p.dispatch(&request(json!({"dataset": "x"}), Some(RID)), &s).await.into_bytes().unwrap();
    let v: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(v["error"]["code"], -32803); // REQUEST_FAILED
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the refusal is audited");
}

#[tokio::test]
async fn authz_denial_is_audited() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let p = JsonRpcProtocol::<()>::builder("t", "1")
        .roles(Roles::new(["AUTH"]))
        .fd_transfer_method(RpcFdTransferMethod::<SendArgs, ReadyInfo, Done, _, _>::new(
            MethodDef::new("zfs.send").audit().roles(["AUTH"]),
            TransferDirection::Download,
            |_a: &SendArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(ReadyInfo { size: 0 }),
            |_a: SendArgs, _ft: &dyn FileTransfer| Ok::<_, JsonRpcError>(Done { ok: true }),
        ))
        .unwrap()
        .audit_sink(move |_r: &RequestInfo, _outcome: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
            h.fetch_add(1, Ordering::SeqCst);
        })
        .build();
    let s = session(&p);
    let reply =
        p.dispatch(&request(json!({"dataset": "x"}), Some(RID)), &s).await.into_bytes().unwrap();
    let v: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(v["error"]["code"], -32000); // NOT_AUTHORIZED
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the denial is audited");
}

#[tokio::test]
async fn denial_and_refusal_without_audit() {
    // Non-audited transfer methods: the denial / negotiate-refusal paths skip the audit block.
    // (a) authorization denial, not audited.
    let p = JsonRpcProtocol::<()>::builder("t", "1")
        .roles(Roles::new(["AUTH"]))
        .fd_transfer_method(RpcFdTransferMethod::<SendArgs, ReadyInfo, Done, _, _>::new(
            MethodDef::new("zfs.send").roles(["AUTH"]),
            TransferDirection::Download,
            |_a: &SendArgs, _cx: &RequestCtx<()>| Ok::<_, JsonRpcError>(ReadyInfo { size: 0 }),
            |_a: SendArgs, _ft: &dyn FileTransfer| Ok::<_, JsonRpcError>(Done { ok: true }),
        ))
        .unwrap()
        .build();
    let s = session(&p);
    let v: Value = serde_json::from_slice(
        &p.dispatch(&request(json!({"dataset": "x"}), Some(RID)), &s).await.into_bytes().unwrap(),
    )
    .unwrap();
    assert_eq!(v["error"]["code"], -32000); // NOT_AUTHORIZED

    // (b) negotiate refusal, not audited.
    let p = JsonRpcProtocol::<()>::builder("t", "1")
        .fd_transfer_method(RpcFdTransferMethod::<SendArgs, ReadyInfo, Done, _, _>::new(
            MethodDef::new("zfs.send"),
            TransferDirection::Download,
            |_a: &SendArgs, _cx: &RequestCtx<()>| {
                Err::<ReadyInfo, _>(JsonRpcError::request_failed("nope"))
            },
            |_a: SendArgs, _ft: &dyn FileTransfer| Ok::<_, JsonRpcError>(Done { ok: true }),
        ))
        .unwrap()
        .build();
    let s = session(&p);
    let v: Value = serde_json::from_slice(
        &p.dispatch(&request(json!({"dataset": "x"}), Some(RID)), &s).await.into_bytes().unwrap(),
    )
    .unwrap();
    assert_eq!(v["error"]["code"], -32803); // REQUEST_FAILED
}

#[tokio::test]
async fn transfer_success_and_failure_are_audited() {
    // The transfer callback fails iff the dataset is "fail".
    let (p, hits) = audited_proto(
        |_a, _cx| Ok::<_, JsonRpcError>(ReadyInfo { size: 1 }),
        |a, _ft| {
            if a.dataset == "fail" {
                Err(JsonRpcError::request_failed("boom"))
            } else {
                Ok(Done { ok: true })
            }
        },
    );
    let s = session(&p);

    // Success: `complete` runs the transfer callback and audits the final response.
    let Dispatched::Transfer(t) =
        p.dispatch(&request(json!({"dataset": "ok"}), Some(RID)), &s).await
    else {
        panic!("expected a transfer directive");
    };
    let ok: Value = serde_json::from_slice(&t.complete(&FakeFt(-1))).unwrap();
    assert_eq!(ok["result"]["ok"], true);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Failure: the callback error becomes the final error envelope, also audited.
    let Dispatched::Transfer(t) =
        p.dispatch(&request(json!({"dataset": "fail"}), Some(RID)), &s).await
    else {
        panic!("expected a transfer directive");
    };
    let err: Value = serde_json::from_slice(&t.complete(&FakeFt(-1))).unwrap();
    assert_eq!(err["error"]["code"], -32803); // REQUEST_FAILED
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}
