//! End-to-end XDR binary-wire dispatch through `JsonRpcProtocol::dispatch`. The happy
//! paths are validated **byte-for-byte** against the cross-language `xdr_add` /
//! `xdr_unknown_proc` golden frames (`truenas_jsonrpc/zig/conformance/golden.json`); the
//! rest exercise the gate / authz / error / registration branches.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_jsonrpc::{
    AuthorizationResponse, Dispatched, JsonRpcError, JsonRpcMethod, JsonRpcProtocol, JsonRpcRequest,
    MethodDef, NullOutbound, RequestCtx, Session, SessionLifecycle,
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
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.add").xdr(1001),
            |a: AddArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .authorizer(|_r: &_, _s: &Session<()>, _t| AuthorizationResponse::deny("no"))
        .build();
    let request = build_request(1001, Some(TEST_ID), &to_bytes(&AddArgs { a: 1, b: 2 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32000); // NOT_AUTHORIZED
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
    // An audited XDR method: the typed params + result are reflected to JSON for the audit sink
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
        .audit_sink(move |req: &JsonRpcRequest, resp: &Value, _s: &Session<()>, msg: Option<&str>| {
            *cap.lock().unwrap() = Some(json!({ "params": req.params, "resp": resp, "msg": msg }));
        })
        .build();
    let request = build_request(2010, Some(TEST_ID), &to_bytes(&AddArgs { a: 2, b: 40 }).unwrap()).unwrap();
    // The wire reply is the ordinary XDR success frame (audit is off the wire path).
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    assert_eq!(frame::parse_reply(&reply).unwrap().status, frame::STATUS_OK);
    let rec = captured.lock().unwrap().take().expect("the audit sink fired");
    assert_eq!(rec["params"]["a"], "********"); // secret field redacted in the reflected params
    assert_eq!(rec["params"]["b"], 40); //          the rest reflected from the typed XDR struct
    assert_eq!(rec["resp"]["result"]["sum"], 42); // result reflected into the audit response
    assert_eq!(rec["msg"], "did the secret thing");
}

#[tokio::test]
async fn audited_xdr_denial_is_audited() {
    // A denied XDR call is still audited (like the JSON wire) — and because the params are
    // typed-decoded *before* authorization, the audit record carries them even on denial.
    let captured: Arc<Mutex<Option<(Value, Value)>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("conf", "1")
        .method(JsonRpcMethod::new(
            MethodDef::new("xdr.guarded").xdr(2011).audit(),
            |a: AddArgs, _cx: &RequestCtx<()>| {
                Ok::<_, JsonRpcError>(AddResult { sum: i64::from(a.a + a.b), label: "ok".into() })
            },
        ))
        .unwrap()
        .authorizer(|_r: &_, _s: &Session<()>, _t| AuthorizationResponse::deny("nope"))
        .audit_sink(move |req: &JsonRpcRequest, resp: &Value, _s: &Session<()>, _m: Option<&str>| {
            *cap.lock().unwrap() = Some((req.params.clone(), resp.clone()));
        })
        .build();
    let request = build_request(2011, Some(TEST_ID), &to_bytes(&AddArgs { a: 1, b: 2 }).unwrap()).unwrap();
    let reply = dispatch(&proto, &request).await.into_bytes().unwrap();
    let (code, _) = frame::parse_error_payload(frame::parse_reply(&reply).unwrap().body).unwrap();
    assert_eq!(code, -32000); // NOT_AUTHORIZED on the wire
    let (params, resp) = captured.lock().unwrap().take().expect("the denial was audited");
    assert_eq!(params["a"], 1); // params reflected even on denial (decode precedes authz)
    assert_eq!(resp["error"]["code"], -32000);
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
