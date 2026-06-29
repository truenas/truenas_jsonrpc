//! End-to-end XDR binary-wire dispatch through `JsonRpcProtocol::dispatch`. The happy
//! paths are validated **byte-for-byte** against the committed `xdr_add` /
//! `xdr_unknown_proc` golden frames; the rest exercise the gate / authz / error /
//! registration branches.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_rpc::{
    AuditOutcome,
    AsyncJsonRpcMethod, Dispatched, JsonRpcError, JsonRpcMethod, JsonRpcProtocol, JsonRpcRequest,
    MethodDef, NullOutbound, RequestCtx, Roles, Session, SessionLifecycle,
};
use truenas_xdr::frame::{self, build_request};
use truenas_xdr::to_bytes;

const TEST_ID: [u8; 16] = [
    0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00,
];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[derive(Serialize, Deserialize)]
struct AddArgs {
    a: i32,
    b: i32,
}
#[derive(Serialize, Deserialize)]
struct AddResult {
    sum: i64,
    label: String,
}
#[derive(Serialize, Deserialize)]
struct MapResult {
    m: BTreeMap<String, i32>, // XDR has no map → encoding this fails
}

/// A protocol whose `xdr.add` (proc 1001) sums its args — the conformance method.
fn add_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.add").xdr(1001),
            |a: AddArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .build()
}

async fn dispatch(proto: &JsonRpcProtocol<()>, wire: &[u8]) -> Dispatched {
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    proto.dispatch(wire, &s).await
}

#[tokio::test]
async fn add_dispatch_matches_golden() {
    let request = unhex(
        "5458445200000001000003e900000001123e4567e89b12d3a4564266141740000000000200000003",
    );
    let golden_reply = unhex(
        "545844520000000100000001123e4567e89b12d3a456426614174000000000000000000000000005000000026f6b0000",
    );
    let reply = dispatch(&add_proto(), &request).await.into_bytes().unwrap();
    assert_eq!(reply, golden_reply, "xdr.add dispatch reply");
}

#[tokio::test]
async fn run_proc_routes_to_registered_methods() {
    // The engine-facing op-table entry ([`Service::run_proc`]): a method registered with `.xdr(1001)`
    // is reachable by proc-id + raw XDR params, returning the XDR-encoded result bytes (no TXDR frame
    // envelope). This is what lets a non-TXDR binary engine serve the same registered methods. Both
    // dispatch models (sync on the blocking pool, async inline) are exercised; the result is identical.
    let args = to_bytes(&AddArgs { a: 2, b: 40 }).unwrap();
    for proto in [add_proto(), add_proto_async()] {
        let session = proto.new_session(Some(()), Arc::new(NullOutbound));
        let bytes = proto.service().run_proc(1001, None, &args, &session).await.unwrap();
        assert_eq!(truenas_xdr::from_bytes::<AddResult>(&bytes).unwrap().sum, 42);
    }
}

#[tokio::test]
async fn run_proc_surfaces_errors() {
    let args = to_bytes(&AddArgs { a: 0, b: 0 }).unwrap();
    let proto = add_proto();
    let session = proto.new_session(Some(()), Arc::new(NullOutbound));

    // Unknown proc-id → METHOD_NOT_FOUND, for the caller to map onto its own status.
    let nf = proto.service().run_proc(9999, None, &args, &session).await.unwrap_err();
    assert_eq!(nf.code, -32601);

    // A panicking sync handler over `run_proc` surfaces INTERNAL_ERROR (the spawn_blocking
    // worker unwinds) — parity with the framed XDR path.
    let boom = JsonRpcProtocol::<()>::builder("c", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.boom").xdr(2001),
            |_a: AddArgs, _cx: &RequestCtx<()>| -> Result<AddResult, JsonRpcError> { panic!("boom") },
        ))
        .unwrap()
        .build();
    let bsession = boom.new_session(Some(()), Arc::new(NullOutbound));
    let panicked = boom.service().run_proc(2001, None, &args, &bsession).await.unwrap_err();
    assert_eq!(panicked.code, -32603);
}

#[tokio::test]
async fn unknown_proc_matches_golden() {
    let request = unhex("54584452000000010000270f00000001123e4567e89b12d3a456426614174000");
    let golden_reply = unhex(
        "545844520000000100000001123e4567e89b12d3a45642661417400000000001ffff80a70000002c7b22636f6465223a2d33323630312c226d657373616765223a224d6574686f64206e6f7420666f756e64227d",
    );
    let reply = dispatch(&add_proto(), &request).await.into_bytes().unwrap();
    assert_eq!(reply, golden_reply, "unknown-proc error frame");
}

#[tokio::test]
async fn truncated_frame_replies_with_idless_error() {
    // Magic only — the envelope can't be read → an id-less error frame.
    let reply = dispatch(&add_proto(), &[0x54, 0x58, 0x44, 0x52]).await.into_bytes().unwrap();
    let parsed = frame::parse_reply(&reply).unwrap();
    assert_eq!(parsed.status, frame::STATUS_ERR);
    assert_eq!(parsed.rid, None);
}

#[tokio::test]
async fn notification_without_id_is_suppressed() {
    let request = build_request(1001, None, &to_bytes(&AddArgs { a: 1, b: 2 }).unwrap()).unwrap();
    assert!(matches!(dispatch(&add_proto(), &request).await, Dispatched::Nothing));
}

#[tokio::test]
async fn closed_session_is_rejected() {
    let proto = add_proto();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    proto.close_session(&s);
    let request = build_request(1001, Some(TEST_ID), &to_bytes(&AddArgs { a: 1, b: 2 }).unwrap()).unwrap();
    let reply = proto.dispatch(&request, &s).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32002); // SESSION_NOT_ESTABLISHED
}

#[tokio::test]
async fn session_gate_blocks_before_established() {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.add").xdr(1001),
            |a: AddArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .session_setup(MethodDef::new("$setup"), |_a: AddArgs, _s: &Session<()>| {
            Ok::<_, JsonRpcError>((SessionLifecycle::Established, AddResult { sum: 0, label: String::new() }))
        })
        .build();
    let request = build_request(1001, Some(TEST_ID), &to_bytes(&AddArgs { a: 1, b: 2 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32002);
}

#[tokio::test]
async fn authorizer_denial_is_rejected() {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .roles(Roles::new(["AUTH"]))
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.add").xdr(1001).roles(["AUTH"]),
            |a: AddArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .build();
    let request = build_request(1001, Some(TEST_ID), &to_bytes(&AddArgs { a: 1, b: 2 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32000); // NOT_AUTHORIZED (required role not granted)
}

#[tokio::test]
async fn handler_error_carries_data_in_the_detail() {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.fail").xdr(2004),
            |_a: AddArgs, _cx: &RequestCtx<()>| {
                Err::<AddResult, _>(JsonRpcError::request_failed("nope").with_data(json!({"why": 1})))
            },
        ))
        .unwrap()
        .build();
    let request = build_request(2004, Some(TEST_ID), &to_bytes(&AddArgs { a: 0, b: 0 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, detail) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32803); // REQUEST_FAILED
    let obj: serde_json::Value = serde_json::from_slice(&detail).unwrap();
    assert_eq!(obj["data"]["why"], 1); // the error object carries `data`
}

#[tokio::test]
async fn malformed_params_are_invalid_params() {
    // proc 1001 expects two i32 (8 bytes); supply only 4 → the typed XDR decode underruns.
    let request = build_request(1001, Some(TEST_ID), &[0, 0, 0, 2]).unwrap();
    let reply = dispatch(&add_proto(), &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32602); // INVALID_PARAMS
}

#[tokio::test]
async fn unencodable_result_is_internal_error() {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.map").xdr(2003),
            |_a: AddArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(MapResult { m: BTreeMap::from([("k".to_string(), 1)]) })
            },
        ))
        .unwrap()
        .build();
    let request = build_request(2003, Some(TEST_ID), &to_bytes(&AddArgs { a: 0, b: 0 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32603); // INTERNAL_ERROR (XDR can't encode a map)
}

#[tokio::test]
async fn handler_panic_is_internal_error() {
    // The body runs on the blocking pool (`spawn_blocking`); a panicking handler unwinds that
    // worker, and the dispatch replies INTERNAL_ERROR — parity with the JSON sync path.
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.boom").xdr(2005),
            |_a: AddArgs, _cx: &RequestCtx<()>| -> Result<AddResult, JsonRpcError> {
                panic!("xdr kaboom")
            },
        ))
        .unwrap()
        .build();
    let request = build_request(2005, Some(TEST_ID), &to_bytes(&AddArgs { a: 0, b: 0 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32603); // INTERNAL_ERROR (handler panicked)
}

#[tokio::test]
async fn audited_xdr_call_emits_redacted_audit_record() {
    // An audited XDR method: the typed params are reflected to JSON for the audit sink (the result
    // is not — the record carries the structured outcome, not the payload)
    // (XDR is non-self-describing), with the `secret_fields` redacted — parity with the JSON wire.
    let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.secret").xdr(2010).audit_message("did the secret thing").secret_fields(["a"]),
            |a: AddArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .audit_sink(move |req: &JsonRpcRequest, _outcome: AuditOutcome<'_>, _s: &Session<()>, msg: Option<&str>| {
            *cap.lock().unwrap() = Some(json!({ "params": req.params, "msg": msg }));
        })
        .build();
    let request = build_request(2010, Some(TEST_ID), &to_bytes(&AddArgs { a: 2, b: 40 }).unwrap()).unwrap();
    // The wire reply is the ordinary XDR success frame (audit is off the wire path).
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    assert_eq!(frame::parse_reply(&reply).unwrap().status, frame::STATUS_OK);
    let rec = captured.lock().unwrap().take().expect("the audit sink fired");
    assert_eq!(rec["params"]["a"], "********"); // secret field redacted in the reflected params
    assert_eq!(rec["params"]["b"], 40); //          the rest reflected from the typed XDR struct
    assert_eq!(rec["msg"], "did the secret thing");
}

#[tokio::test]
#[allow(clippy::type_complexity)] // (Value, Option<i32>) capture
async fn audited_xdr_denial_is_audited() {
    // A denied XDR call is still audited (like the JSON wire) — and because the params are
    // typed-decoded *before* authorization, the audit record carries them even on denial.
    let captured: Arc<Mutex<Option<(Value, Option<i32>)>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .roles(Roles::new(["AUTH"]))
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.guarded").xdr(2011).audit().roles(["AUTH"]),
            |a: AddArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .audit_sink(move |req: &JsonRpcRequest, outcome: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
            *cap.lock().unwrap() = Some((req.params.clone(), outcome.error().map(|e| e.code)));
        })
        .build();
    let request = build_request(2011, Some(TEST_ID), &to_bytes(&AddArgs { a: 1, b: 2 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32000); // NOT_AUTHORIZED on the wire (required role not granted)
    let (params, err_code) = captured.lock().unwrap().take().expect("the denial was audited");
    assert_eq!(params["a"], 1); // params reflected even on denial (decode precedes authz)
    assert_eq!(err_code, Some(-32000));
}

#[tokio::test]
async fn python_method_is_not_on_the_xdr_wire() {
    // A python method registered with an xdr_id replies method-not-found over XDR (its body
    // runs via the PyO3 bridge, not the binary codec). (Filterable methods, by contrast, DO
    // work over XDR now — see the xdr_filter_* conformance tests in tests/xdr_filter.rs.)
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .python_method(MethodDef::new("xdr.py").xdr(2002))
        .unwrap()
        .build();
    let request = build_request(2002, Some(TEST_ID), &to_bytes(&AddArgs { a: 0, b: 0 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32601); // METHOD_NOT_FOUND
}

// --- async methods over the XDR wire ----------------------------------------
//
// An async method with an `xdr_id` is dispatched **inline** (no `spawn_blocking` hop) — the
// binary-wire peer of the JSON async path. The wire is oblivious to the dispatch model, so an
// async method's reply is byte-identical to the sync golden; the rest exercise the async
// pipeline's decode / authz / audit / error branches (mirrors of the sync cases above).

/// An async `xdr.add` (proc 1001), same signature as [`add_proto`]'s sync conformance method.
fn add_proto_async() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("conf", "1")
        .async_method(AsyncJsonRpcMethod::new(
            MethodDef::new("xdr.add").xdr(1001),
            |a: AddArgs, _cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .build()
}

#[tokio::test]
async fn async_add_dispatch_matches_sync_golden() {
    // The same request + golden as `add_dispatch_matches_golden`: an inline-dispatched async
    // method produces the byte-identical XDR reply — only the server-side scheduling differs.
    let request = unhex(
        "5458445200000001000003e900000001123e4567e89b12d3a4564266141740000000000200000003",
    );
    let golden_reply = unhex(
        "545844520000000100000001123e4567e89b12d3a456426614174000000000000000000000000005000000026f6b0000",
    );
    let reply = dispatch(&add_proto_async(), &request).await.into_bytes().unwrap();
    assert_eq!(reply, golden_reply, "async xdr.add reply matches the sync golden");
}

#[tokio::test]
async fn async_malformed_params_are_invalid_params() {
    // proc 1001 expects two i32 (8 bytes); supply only 4 → the async XDR decode underruns,
    // returning before authz/audit.
    let request = build_request(1001, Some(TEST_ID), &[0, 0, 0, 2]).unwrap();
    let reply = dispatch(&add_proto_async(), &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32602); // INVALID_PARAMS
}

#[tokio::test]
async fn async_handler_error_is_request_failed() {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .async_method(AsyncJsonRpcMethod::new(
            MethodDef::new("xdr.afail").xdr(2012),
            |_a: AddArgs, _cx: RequestCtx<()>| async move {
                Err::<AddResult, _>(JsonRpcError::request_failed("nope"))
            },
        ))
        .unwrap()
        .build();
    let request = build_request(2012, Some(TEST_ID), &to_bytes(&AddArgs { a: 0, b: 0 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32803); // REQUEST_FAILED
}

#[tokio::test]
async fn async_unencodable_result_is_internal_error() {
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .async_method(AsyncJsonRpcMethod::new(
            MethodDef::new("xdr.amap").xdr(2013),
            |_a: AddArgs, _cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(MapResult { m: BTreeMap::from([("k".to_string(), 1)]) })
            },
        ))
        .unwrap()
        .build();
    let request = build_request(2013, Some(TEST_ID), &to_bytes(&AddArgs { a: 0, b: 0 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32603); // INTERNAL_ERROR (XDR can't encode a map)
}

#[tokio::test]
async fn async_audited_xdr_call_emits_redacted_audit_record() {
    // Audit parity on the async path: the typed params reflect to JSON for the sink (not the result
    // — the record carries the structured outcome)
    // (with `secret_fields` redacted), and the audit record's id is the lazily-formatted UUID.
    let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .async_method(AsyncJsonRpcMethod::new(
            MethodDef::new("xdr.secret").xdr(2010).audit_message("did the secret thing").secret_fields(["a"]),
            |a: AddArgs, _cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .audit_sink(move |req: &JsonRpcRequest, _outcome: AuditOutcome<'_>, _s: &Session<()>, msg: Option<&str>| {
            *cap.lock().unwrap() = Some(json!({ "params": req.params, "msg": msg }));
        })
        .build();
    let request = build_request(2010, Some(TEST_ID), &to_bytes(&AddArgs { a: 2, b: 40 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    assert_eq!(frame::parse_reply(&reply).unwrap().status, frame::STATUS_OK);
    let rec = captured.lock().unwrap().take().expect("the audit sink fired");
    assert_eq!(rec["params"]["a"], "********"); // secret field redacted
    assert_eq!(rec["params"]["b"], 40);
    assert_eq!(rec["msg"], "did the secret thing");
}

#[tokio::test]
#[allow(clippy::type_complexity)] // (Value, Option<i32>) capture
async fn async_audited_denial_is_audited() {
    // A denied async XDR call: NOT_AUTHORIZED on the wire, and still audited (params reflected
    // even on denial, since decode precedes authz) — exercises the audit error-envelope branch.
    let captured: Arc<Mutex<Option<(Value, Option<i32>)>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .roles(Roles::new(["AUTH"]))
        .async_method(AsyncJsonRpcMethod::new(
            MethodDef::new("xdr.guarded").xdr(2011).audit().roles(["AUTH"]),
            |a: AddArgs, _cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .audit_sink(move |req: &JsonRpcRequest, outcome: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
            *cap.lock().unwrap() = Some((req.params.clone(), outcome.error().map(|e| e.code)));
        })
        .build();
    let request = build_request(2011, Some(TEST_ID), &to_bytes(&AddArgs { a: 1, b: 2 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32000); // NOT_AUTHORIZED on the wire (required role not granted)
    let (params, err_code) = captured.lock().unwrap().take().expect("the denial was audited");
    assert_eq!(params["a"], 1); // params reflected even on denial (decode precedes authz)
    assert_eq!(err_code, Some(-32000));
}

#[tokio::test]
async fn xdr_handler_reads_lazy_request_id() {
    // The handler reads `cx.id()` — on the XDR wire this lazily formats the raw 16 id bytes to the
    // canonical UUID string (the hot path never calls it, so it's never formatted).
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.whoami").xdr(2030),
            |_a: AddArgs, cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(AddResult { sum: 0, label: cx.id().unwrap_or("none").into() })
            },
        ))
        .unwrap()
        .build();
    let request = build_request(2030, Some(TEST_ID), &to_bytes(&AddArgs { a: 0, b: 0 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let result: AddResult = truenas_xdr::from_bytes(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(result.label, "123e4567-e89b-12d3-a456-426614174000"); // TEST_ID, formatted lazily
}

#[test]
fn registration_rejects_reserved_and_duplicate_proc_ids() {
    let h = |a: AddArgs, _cx: &RequestCtx<()>| {
        Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
    };
    // Reserved band (<= 1000).
    assert!(JsonRpcProtocol::<()>::builder("c", "1")
        .method(JsonRpcMethod::new(MethodDef::new("x").xdr(500), h))
        .is_err());
    // Duplicate proc-id.
    let dup = JsonRpcProtocol::<()>::builder("c", "1")
        .method(JsonRpcMethod::new(MethodDef::new("a").xdr(1001), h))
        .unwrap()
        .method(JsonRpcMethod::new(MethodDef::new("b").xdr(1001), h));
    assert!(dup.is_err());
}
