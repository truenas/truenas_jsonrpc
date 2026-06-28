//! Integration tests for the dispatch spine: negotiate-less `dispatch` over the
//! `$/sessionSetup` → method-call pipeline (decode → authorize → handler → audit →
//! response), control messages, error mapping, and `$/progress`.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_jsonrpc::{
    AuditOutcome,
    Dispatched, JsonRpcError, JsonRpcMethod, JsonRpcProtocol, JsonRpcRequest, MethodDef,
    NullOutbound, Outbound, RequestCtx, Roles, Session, SessionLifecycle,
};

const ID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

#[derive(Deserialize, Serialize)]
struct EchoArgs {
    msg: String,
}

#[derive(Serialize)]
struct EchoResult {
    echo: String,
}

fn req(method: &str, params: Option<Value>, id: Option<&str>) -> Vec<u8> {
    let mut m = serde_json::Map::new();
    m.insert("jsonrpc".into(), json!("2.0"));
    m.insert("method".into(), json!(method));
    if let Some(id) = id {
        m.insert("id".into(), json!(id));
    }
    if let Some(p) = params {
        m.insert("params".into(), p);
    }
    serde_json::to_vec(&Value::Object(m)).unwrap()
}

async fn call<S: Send + Sync + 'static>(
    proto: &JsonRpcProtocol<S>,
    session: &Arc<Session<S>>,
    wire: &[u8],
) -> Option<Value> {
    match proto.dispatch(wire, session).await {
        Dispatched::Reply(b) => Some(serde_json::from_slice(&b).unwrap()),
        Dispatched::Nothing => None,
        Dispatched::Transfer(_) | Dispatched::Passthrough(_) | Dispatched::Sessions { .. } => unreachable!("transfer/passthrough directive unexpected in this test"),
    }
}

fn echo_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .method(
            JsonRpcMethod::new(MethodDef::new("echo"), |a: EchoArgs, _cx: &RequestCtx<()>| {
                Ok(EchoResult { echo: a.msg })
            }),
        )
        .unwrap()
        .method(
            JsonRpcMethod::new(MethodDef::new("boom"), |_a: EchoArgs, _cx: &RequestCtx<()>| {
                Err::<EchoResult, _>(JsonRpcError::request_failed("kaboom"))
            }),
        )
        .unwrap()
        .build()
}

fn session<S: Send + Sync + 'static>(proto: &JsonRpcProtocol<S>, state: Option<S>) -> Arc<Session<S>> {
    proto.new_session(state, Arc::new(NullOutbound))
}

#[tokio::test]
async fn happy_path_echoes_id_and_result() {
    let proto = echo_proto();
    let s = session(&proto, Some(()));
    let resp = call(&proto, &s, &req("echo", Some(json!({"msg": "hi"})), Some(ID))).await.unwrap();
    assert_eq!(resp, json!({"jsonrpc": "2.0", "result": {"echo": "hi"}, "id": ID}));
}

#[tokio::test]
async fn missing_required_param_is_invalid_params() {
    let proto = echo_proto();
    let s = session(&proto, Some(()));
    let resp = call(&proto, &s, &req("echo", Some(json!({})), Some(ID))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32602);
    assert_eq!(resp["id"], ID);
}

#[tokio::test]
async fn handler_error_passthrough() {
    let proto = echo_proto();
    let s = session(&proto, Some(()));
    let resp = call(&proto, &s, &req("boom", Some(json!({"msg": "x"})), Some(ID))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32803);
    assert_eq!(resp["error"]["message"], "kaboom");
}

#[tokio::test]
async fn unknown_method_is_method_not_found() {
    let proto = echo_proto();
    let s = session(&proto, Some(()));
    let resp = call(&proto, &s, &req("nope", Some(json!({})), Some(ID))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32601);
}

#[tokio::test]
async fn notification_yields_no_reply() {
    let proto = echo_proto();
    let s = session(&proto, Some(()));
    let resp = call(&proto, &s, &req("echo", Some(json!({"msg": "hi"})), None)).await;
    assert!(resp.is_none());
    // An unknown-method notification is also silent.
    let resp = call(&proto, &s, &req("nope", Some(json!({})), None)).await;
    assert!(resp.is_none());
}

#[tokio::test]
async fn parse_and_structural_errors() {
    let proto = echo_proto();
    let s = session(&proto, Some(()));

    // malformed JSON -> INVALID_JSON
    let resp = call(&proto, &s, b"{not json").await.unwrap();
    assert_eq!(resp["error"]["code"], -32700);

    // empty top-level array -> INVALID_REQUEST (a non-empty array is a JSON-RPC 2.0 batch)
    let resp = call(&proto, &s, b"[]").await.unwrap();
    assert_eq!(resp["error"]["code"], -32600);

    // non-UUID id -> INVALID_REQUEST (id echoed as null)
    let resp = call(&proto, &s, &req("echo", Some(json!({"msg": "x"})), Some("not-a-uuid"))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32600);
    assert_eq!(resp["id"], Value::Null);

    // bad jsonrpc version -> INVALID_REQUEST (id echoed)
    let wire = br#"{"jsonrpc": "1.0", "method": "echo", "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "params": {"msg":"x"}}"#;
    let resp = call(&proto, &s, wire).await.unwrap();
    assert_eq!(resp["error"]["code"], -32600);
    assert_eq!(resp["id"], ID);
}

#[tokio::test]
async fn invalid_params_precedes_not_authorized() {
    // `echo` requires a role the session lacks; a request with bad params must still get
    // INVALID_PARAMS (decode runs before the authorization gate, matching Python).
    let proto = JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .roles(Roles::new(["AUTH"]))
        .method(
            JsonRpcMethod::new(MethodDef::new("echo").roles(["AUTH"]), |a: EchoArgs, _cx: &RequestCtx<()>| {
                Ok(EchoResult { echo: a.msg })
            }),
        )
        .unwrap()
        .build();
    let s = session(&proto, Some(()));

    // bad params -> INVALID_PARAMS (not NOT_AUTHORIZED)
    let resp = call(&proto, &s, &req("echo", Some(json!({})), Some(ID))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32602);

    // good params -> NOT_AUTHORIZED
    let resp = call(&proto, &s, &req("echo", Some(json!({"msg": "x"})), Some(ID))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32000);
    assert_eq!(resp["error"]["message"], "Not authorized");
}

#[tokio::test]
async fn async_method_happy_path() {
    let proto = JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .async_method(truenas_jsonrpc::AsyncJsonRpcMethod::new(
            MethodDef::new("aecho"),
            |a: EchoArgs, _cx: RequestCtx<()>| async move { Ok(EchoResult { echo: a.msg }) },
        ))
        .unwrap()
        .build();
    let s = session(&proto, Some(()));
    let resp = call(&proto, &s, &req("aecho", Some(json!({"msg": "yo"})), Some(ID))).await.unwrap();
    assert_eq!(resp, json!({"jsonrpc": "2.0", "result": {"echo": "yo"}, "id": ID}));
}

#[tokio::test]
async fn session_gate_and_setup() {
    #[derive(Deserialize)]
    struct Creds {
        token: String,
    }
    #[derive(Serialize)]
    struct LoginResult {
        welcome: String,
    }
    let proto = JsonRpcProtocol::<String>::builder("test", "1.0.0")
        .method(
            JsonRpcMethod::new(MethodDef::new("whoami"), |_a: EchoArgs, cx: &RequestCtx<String>| {
                let who = cx.session().with_internal(|s| s.cloned().unwrap_or_default());
                Ok(EchoResult { echo: who })
            }),
        )
        .unwrap()
        .session_setup(
            MethodDef::new("$/sessionSetup"),
            |c: Creds, session: &Session<String>| {
                if c.token == "good" {
                    session.set_internal("root".to_string());
                    Ok((SessionLifecycle::Established, LoginResult { welcome: "root".into() }))
                } else {
                    Err(JsonRpcError::not_authorized("bad token"))
                }
            },
        )
        .build();
    let s = session(&proto, None);

    // Before setup: the gate rejects (whoami accepts EchoArgs, send a valid one).
    let resp = call(&proto, &s, &req("whoami", Some(json!({"msg": "_"})), Some(ID))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32002, "expected SESSION_NOT_ESTABLISHED");

    // A failed setup leaves the lifecycle unchanged (retry allowed).
    let resp = call(&proto, &s, &req("$/sessionSetup", Some(json!({"token": "bad"})), Some(ID))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32000);
    assert_eq!(s.lifecycle(), SessionLifecycle::None);

    // A good setup establishes the session.
    let resp = call(&proto, &s, &req("$/sessionSetup", Some(json!({"token": "good"})), Some(ID))).await.unwrap();
    assert_eq!(resp["result"], json!({"welcome": "root"}));
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);

    // Now the gated method works and sees the identity.
    let resp = call(&proto, &s, &req("whoami", Some(json!({"msg": "_"})), Some(ID))).await.unwrap();
    assert_eq!(resp["result"], json!({"echo": "root"}));
}

#[tokio::test]
async fn server_info_probe() {
    let proto = JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .server_info(|_s: &Session<()>| Ok(json!({"name": "truenas", "version": "25.10"})))
        .build();
    let s = session(&proto, Some(()));
    let resp = call(&proto, &s, &req("$/serverInfo", None, Some(ID))).await.unwrap();
    assert_eq!(resp["result"], json!({"name": "truenas", "version": "25.10"}));
}

#[tokio::test]
#[allow(clippy::type_complexity)]
async fn audit_redacts_secret_fields() {
    let captured: Arc<Mutex<Vec<(Value, Option<String>)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .method(
            JsonRpcMethod::new(
                MethodDef::new("login").audit_message("user login").secret_fields(["password"]),
                |a: Value, _cx: &RequestCtx<()>| Ok(a),
            ),
        )
        .unwrap()
        .audit_sink(move |r: &JsonRpcRequest, _outcome: AuditOutcome<'_>, _s: &Session<()>, msg: Option<&str>| {
            sink.lock().unwrap().push((r.params.clone(), msg.map(str::to_string)));
        })
        .build();
    let s = session(&proto, Some(()));
    let resp = call(&proto, &s, &req("login", Some(json!({"user": "u", "password": "hunter2"})), Some(ID)))
        .await
        .unwrap();
    // The real password is on the wire.
    assert_eq!(resp["result"]["password"], "hunter2");
    // But redacted in the audit view.
    let rows = captured.lock().unwrap();
    assert_eq!(rows.len(), 1);
    let (params, msg) = &rows[0];
    assert_eq!(params["password"], "********");
    assert_eq!(params["user"], "u");
    assert_eq!(msg.as_deref(), Some("user login"));
}

#[tokio::test]
async fn progress_reaches_the_outbound_sink() {
    struct VecSink(Arc<Mutex<Vec<Value>>>);
    impl Outbound for VecSink {
        fn send(&self, message: Vec<u8>) {
            self.0.lock().unwrap().push(serde_json::from_slice(&message).unwrap());
        }
    }
    let sink = Arc::new(Mutex::new(Vec::new()));
    let proto = JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .method(
            JsonRpcMethod::new(MethodDef::new("work"), |_a: EchoArgs, cx: &RequestCtx<()>| {
                cx.update_progress(Some(50.0), Some("half"), None);
                Ok(EchoResult { echo: "done".into() })
            }),
        )
        .unwrap()
        .build();
    let s = proto.new_session(Some(()), Arc::new(VecSink(sink.clone())));
    let resp = call(&proto, &s, &req("work", Some(json!({"msg": "_"})), Some(ID))).await.unwrap();
    assert_eq!(resp["result"], json!({"echo": "done"}));
    let msgs = sink.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], json!({"jsonrpc": "2.0", "method": "$/progress", "params": {"id": ID, "percent": 50.0, "description": "half"}}));
}

#[tokio::test]
async fn cancel_and_close_control_ops_are_audited() {
    // `$/cancelRequest` and `$/sessionClose` are audited through the structured-outcome sink —
    // success or failure — with no method metadata (so no redaction, no static message). Close
    // needs an ESTABLISHED session, so set one up first (the setup is audited too).
    let captured: Arc<Mutex<Vec<(String, bool)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let proto = JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .session_setup(MethodDef::new("$/sessionSetup"), |_a: Value, _s: &Session<()>| {
            Ok((SessionLifecycle::Established, json!({ "ok": true })))
        })
        .audit_sink(move |r: &JsonRpcRequest, outcome: AuditOutcome<'_>, _s: &Session<()>, _m: Option<&str>| {
            sink.lock().unwrap().push((r.method.clone(), outcome.succeeded()));
        })
        .build();
    let s = session(&proto, Some(()));

    call(&proto, &s, &req("$/sessionSetup", Some(json!({})), Some(ID))).await;
    // Cancel an unknown target → audited as a failed control op (the wire reply is an error).
    let cancel = call(&proto, &s, &req("$/cancelRequest", Some(json!({ "target_id": ID })), Some(ID))).await;
    assert!(cancel.unwrap()["error"]["code"].is_i64());
    // Close the (ESTABLISHED) session → audited as a successful control op.
    call(&proto, &s, &req("$/sessionClose", None, Some(ID))).await;
    assert_eq!(s.lifecycle(), SessionLifecycle::Closed);

    let rows = captured.lock().unwrap();
    assert!(rows.iter().any(|(m, ok)| m == "$/sessionSetup" && *ok), "setup audited");
    assert!(rows.iter().any(|(m, ok)| m == "$/cancelRequest" && !*ok), "cancel-denial audited");
    assert!(rows.iter().any(|(m, ok)| m == "$/sessionClose" && *ok), "close audited");
}
