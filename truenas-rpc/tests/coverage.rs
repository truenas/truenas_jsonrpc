//! Coverage-completing integration tests. spine.rs/conformance.rs cover the happy
//! request path; this file exercises the rest of the reachable surface — the `$/`
//! control messages (cancel/close/setupContinue/serverInfo error+panic paths), the
//! protocol/session/RequestCtx accessors, the builder option setters and overrides, and
//! the authz/audit branches — so the crate reaches 100% line coverage.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_rpc::{
    AsyncRpcMethod, AuditOutcome, Clock, Dispatched, Error, IdGen, JsonRpcError, JsonRpcProtocol,
    MethodDef, NullOutbound, RequestCtx, RequestInfo, RoleMask, Roles, RpcMethod, Session,
    SessionId, SessionLifecycle,
};

const ID: &str = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
const ID2: &str = "00000000-0000-0000-0000-000000000001";

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
        Dispatched::Transfer(_) | Dispatched::Passthrough(_) | Dispatched::Sessions { .. } => {
            unreachable!("transfer/passthrough directive unexpected in this test")
        }
    }
}

#[derive(Deserialize, Serialize)]
struct EchoArgs {
    msg: String,
}
#[derive(Serialize)]
struct EchoResult {
    echo: String,
}

fn echo_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("test", "1.0.0")
        .method(RpcMethod::new(
            MethodDef::new("echo"),
            |a: EchoArgs, _c: &RequestCtx<()>| Ok::<_, JsonRpcError>(EchoResult { echo: a.msg }),
        ))
        .unwrap()
        .build()
}

// --- accessors / helpers -----------------------------------------------------

#[tokio::test]
async fn protocol_accessors_and_dispatched_helpers() {
    let proto = JsonRpcProtocol::<()>::builder("myproto", "9.9").build();
    assert_eq!(proto.name(), "myproto");
    assert_eq!(proto.version(), "9.9");
    assert!(!proto.has_session_setup());
    // send_notification to an unregistered topic is an error (covered fully in pubsub.rs).
    assert!(proto
        .send_notification("topic", &json!({ "x": 1 }))
        .is_err());

    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    // A reply carries bytes; a suppressed notification does not.
    let reply = proto.dispatch(&req("nope", None, Some(ID)), &s).await;
    assert!(reply.into_bytes().is_some());
    let nothing = proto.dispatch(&req("nope", None, None), &s).await;
    assert!(nothing.into_bytes().is_none());
}

#[tokio::test]
async fn closed_session_rejects_further_dispatch() {
    let proto = echo_proto();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    proto.close_session(&s);
    assert_eq!(s.lifecycle(), SessionLifecycle::Closed);
    let resp = call(
        &proto,
        &s,
        &req("echo", Some(json!({ "msg": "hi" })), Some(ID)),
    )
    .await
    .unwrap();
    assert_eq!(resp["error"]["code"], -32002);
    assert_eq!(resp["error"]["message"], "Session is closed");
}

#[tokio::test]
async fn empty_method_name_is_invalid_request() {
    let proto = echo_proto();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let resp = call(&proto, &s, &req("", Some(json!({})), Some(ID)))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32600);
}

// --- RequestCtx + Session surface --------------------------------------------

#[tokio::test]
async fn request_ctx_and_session_surface() {
    let id_seen = Arc::new(Mutex::new(None::<String>));
    let name_seen = Arc::new(Mutex::new(String::new()));
    let cancelled = Arc::new(AtomicBool::new(true));
    let raise_ok = Arc::new(AtomicBool::new(false));
    let (i, n, c, r) = (
        id_seen.clone(),
        name_seen.clone(),
        cancelled.clone(),
        raise_ok.clone(),
    );
    let proto = JsonRpcProtocol::<String>::builder("pname", "1")
        .method(RpcMethod::new(
            MethodDef::new("probe"),
            move |_a: Value, cx: &RequestCtx<String>| {
                *i.lock().unwrap() = cx.id().map(str::to_string);
                *n.lock().unwrap() = cx.session().protocol_name().to_string();
                c.store(cx.is_cancelled(), Ordering::SeqCst);
                r.store(cx.raise_if_cancelled().is_ok(), Ordering::SeqCst);
                cx.set_audit("probed");
                let who = cx
                    .session()
                    .with_internal(|s| s.cloned().unwrap_or_default());
                cx.session()
                    .with_internal_mut(|s| *s = Some(format!("{who}-mut")));
                let _ = cx.session().external();
                Ok::<Value, JsonRpcError>(json!({ "who": who }))
            },
        ))
        .unwrap()
        .build();
    let s = proto.new_session(Some("orig".to_string()), Arc::new(NullOutbound));
    let resp = call(&proto, &s, &req("probe", Some(json!({})), Some(ID)))
        .await
        .unwrap();
    assert_eq!(resp["result"]["who"], "orig");
    assert_eq!(id_seen.lock().unwrap().as_deref(), Some(ID));
    assert_eq!(*name_seen.lock().unwrap(), "pname");
    assert!(!cancelled.load(Ordering::SeqCst));
    assert!(raise_ok.load(Ordering::SeqCst));
    assert_eq!(
        s.with_internal(|x| x.cloned()),
        Some("orig-mut".to_string())
    );
}

// --- MethodDef setters + builder overrides -----------------------------------

#[tokio::test]
async fn method_def_setters_are_all_usable() {
    let def = MethodDef::new("full")
        .pre_auth()
        .audit()
        .audit_message("did full")
        .cancellable()
        .roles(["admin", "ops"])
        .doc("the full method")
        .secret_fields(["secret"]);
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .roles(Roles::new(["admin", "ops"]))
        .method(RpcMethod::new(def, |a: Value, _c: &RequestCtx<()>| {
            Ok::<Value, JsonRpcError>(a)
        }))
        .unwrap()
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    s.set_roles(RoleMask::FULL_ADMIN); // satisfies the method's ["admin", "ops"] requirement
                                       // cancellable + id → run_method registers/removes the in-flight entry.
    let resp = call(
        &proto,
        &s,
        &req("full", Some(json!({ "secret": "x" })), Some(ID)),
    )
    .await
    .unwrap();
    assert_eq!(resp["result"]["secret"], "x");
}

#[tokio::test]
async fn builder_id_gen_and_clock_overrides() {
    #[derive(Clone, Copy)]
    struct NilId;
    impl IdGen for NilId {
        fn new_id(&self) -> SessionId {
            SessionId::nil()
        }
    }
    struct FixedClock;
    impl Clock for FixedClock {
        fn now_unix(&self) -> f64 {
            42.0
        }
    }
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .id_gen(NilId)
        .clock(FixedClock)
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    assert_eq!(s.id(), SessionId::nil());
}

#[test]
fn builder_rejects_reserved_and_duplicate_names() {
    let reserved_dollar = JsonRpcProtocol::<()>::builder("p", "1").method(RpcMethod::new(
        MethodDef::new("$/x"),
        |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
    ));
    assert!(reserved_dollar.is_err());
    let reserved_rpc = JsonRpcProtocol::<()>::builder("p", "1").method(RpcMethod::new(
        MethodDef::new("rpc.y"),
        |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
    ));
    assert!(reserved_rpc.is_err());
    let dup = JsonRpcProtocol::<()>::builder("p", "1")
        .method(RpcMethod::new(
            MethodDef::new("dup"),
            |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("dup"),
            |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
        ));
    assert!(dup.is_err());
}

// --- $/serverInfo error + panic paths ----------------------------------------

#[tokio::test]
async fn server_info_not_configured_is_method_not_found() {
    let proto = JsonRpcProtocol::<()>::builder("p", "1").build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let resp = call(&proto, &s, &req("$/serverInfo", None, Some(ID)))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32601);
}

#[tokio::test]
async fn server_info_handler_error_maps_to_wire() {
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .server_info(|_s: &Session<()>| Err(JsonRpcError::internal("info boom")))
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let resp = call(&proto, &s, &req("$/serverInfo", None, Some(ID)))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32603);
    assert_eq!(resp["error"]["message"], "info boom");
}

#[tokio::test]
async fn server_info_handler_panic_is_internal_error() {
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .server_info(|_s: &Session<()>| -> Result<Value, JsonRpcError> { panic!("info kaboom") })
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let resp = call(&proto, &s, &req("$/serverInfo", None, Some(ID)))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32603);
}

// --- $/sessionClose ----------------------------------------------------------

#[tokio::test]
async fn session_close_with_no_session_fails() {
    let proto = JsonRpcProtocol::<()>::builder("p", "1").build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let resp = call(&proto, &s, &req("$/sessionClose", None, Some(ID)))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32803);
}

// --- $/sessionSetup + $/sessionSetupContinue ---------------------------------

#[derive(Deserialize, Serialize)]
struct SetupArgs {
    password: String,
}

fn setup_proto() -> JsonRpcProtocol<String> {
    JsonRpcProtocol::<String>::builder("p", "1")
        .session_setup(
            MethodDef::new("$/sessionSetup").secret_fields(["password"]),
            |a: SetupArgs, _s: &Session<String>| match a.password.as_str() {
                "good" => Ok((SessionLifecycle::Established, json!({ "welcome": "admin" }))),
                "step1" => Ok((SessionLifecycle::Init, json!({ "need": "more" }))),
                "panic" => panic!("setup kaboom"),
                _ => Err(JsonRpcError::not_authorized("bad token")),
            },
        )
        .session_setup_continue(
            MethodDef::new("$/sessionSetupContinue"),
            |a: SetupArgs, session: &Session<String>| {
                session.set_internal("admin".to_string());
                if a.password == "step2" {
                    Ok((SessionLifecycle::Established, json!({ "welcome": "admin" })))
                } else {
                    Err(JsonRpcError::not_authorized("bad"))
                }
            },
        )
        .build()
}

#[tokio::test]
async fn session_setup_has_setup_flag() {
    assert!(setup_proto().has_session_setup());
}

#[tokio::test]
async fn session_setup_then_close_succeeds() {
    let proto = setup_proto();
    let s = proto.new_session(None, Arc::new(NullOutbound));
    let r = call(
        &proto,
        &s,
        &req(
            "$/sessionSetup",
            Some(json!({ "password": "good" })),
            Some(ID),
        ),
    )
    .await
    .unwrap();
    assert_eq!(r["result"], json!({ "welcome": "admin" }));
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
    assert_eq!(s.external(), Some(json!({ "welcome": "admin" })));

    let c = call(&proto, &s, &req("$/sessionClose", None, Some(ID2)))
        .await
        .unwrap();
    assert_eq!(c["result"], json!(true));
    assert_eq!(s.lifecycle(), SessionLifecycle::Closed);
}

#[tokio::test]
async fn session_setup_multi_step_then_continue() {
    let proto = setup_proto();
    let s = proto.new_session(None, Arc::new(NullOutbound));
    // bad token → error, lifecycle unchanged
    let bad = call(
        &proto,
        &s,
        &req(
            "$/sessionSetup",
            Some(json!({ "password": "no" })),
            Some(ID),
        ),
    )
    .await
    .unwrap();
    assert_eq!(bad["error"]["code"], -32000);
    assert_eq!(s.lifecycle(), SessionLifecycle::None);
    // step1 → Init
    let r1 = call(
        &proto,
        &s,
        &req(
            "$/sessionSetup",
            Some(json!({ "password": "step1" })),
            Some(ID),
        ),
    )
    .await
    .unwrap();
    assert_eq!(r1["result"], json!({ "need": "more" }));
    assert_eq!(s.lifecycle(), SessionLifecycle::Init);
    // continue step2 → Established
    let r2 = call(
        &proto,
        &s,
        &req(
            "$/sessionSetupContinue",
            Some(json!({ "password": "step2" })),
            Some(ID2),
        ),
    )
    .await
    .unwrap();
    assert_eq!(r2["result"], json!({ "welcome": "admin" }));
    assert_eq!(s.lifecycle(), SessionLifecycle::Established);
}

#[tokio::test]
async fn session_setup_continue_in_wrong_state_is_request_failed() {
    let proto = setup_proto();
    let s = proto.new_session(None, Arc::new(NullOutbound));
    // continue is only valid in INIT; in NONE it's refused before the handler runs.
    let resp = call(
        &proto,
        &s,
        &req(
            "$/sessionSetupContinue",
            Some(json!({ "password": "x" })),
            Some(ID),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp["error"]["code"], -32803);
}

#[tokio::test]
async fn session_setup_handler_panic_is_internal_error() {
    let proto = setup_proto();
    let s = proto.new_session(None, Arc::new(NullOutbound));
    let resp = call(
        &proto,
        &s,
        &req(
            "$/sessionSetup",
            Some(json!({ "password": "panic" })),
            Some(ID),
        ),
    )
    .await
    .unwrap();
    assert_eq!(resp["error"]["code"], -32603);
}

#[tokio::test]
async fn session_setup_not_configured_is_method_not_found() {
    let proto = JsonRpcProtocol::<()>::builder("p", "1").build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let setup = call(
        &proto,
        &s,
        &req("$/sessionSetup", Some(json!({})), Some(ID)),
    )
    .await
    .unwrap();
    assert_eq!(setup["error"]["code"], -32601);
    let cont = call(
        &proto,
        &s,
        &req("$/sessionSetupContinue", Some(json!({})), Some(ID)),
    )
    .await
    .unwrap();
    assert_eq!(cont["error"]["code"], -32601);
}

#[tokio::test]
async fn session_setup_is_audited_and_redacted() {
    let captured: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let proto = JsonRpcProtocol::<String>::builder("p", "1")
        .session_setup(
            MethodDef::new("$/sessionSetup").secret_fields(["password"]),
            |_a: SetupArgs, _s: &Session<String>| {
                Ok((SessionLifecycle::Established, json!({ "token": "sekret" })))
            },
        )
        .audit_sink(
            move |r: &RequestInfo,
                  _outcome: AuditOutcome<'_>,
                  _s: &Session<String>,
                  _m: Option<&str>| {
                cap.lock().unwrap().push(json!({ "params": r.params }));
            },
        )
        .build();
    let s = proto.new_session(None, Arc::new(NullOutbound));
    call(
        &proto,
        &s,
        &req(
            "$/sessionSetup",
            Some(json!({ "user": "u", "password": "pw" })),
            Some(ID),
        ),
    )
    .await;
    let rows = captured.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["params"]["password"], "********");
    assert_eq!(rows[0]["params"]["user"], "u");
}

// --- handler panic isolation -------------------------------------------------

#[tokio::test]
async fn sync_handler_panic_is_internal_error() {
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .method(RpcMethod::new(
            MethodDef::new("boom"),
            |_a: Value, _c: &RequestCtx<()>| -> Result<Value, JsonRpcError> {
                panic!("handler kaboom")
            },
        ))
        .unwrap()
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let resp = call(&proto, &s, &req("boom", Some(json!({})), Some(ID)))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32603);
}

// --- authz + audit branches --------------------------------------------------

#[tokio::test]
async fn unauthorized_call_is_not_authorized() {
    // A method whose required role the session lacks → NOT_AUTHORIZED (the native role gate).
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .roles(Roles::new(["AUTH"]))
        .method(RpcMethod::new(
            MethodDef::new("m").roles(["AUTH"]),
            |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
        ))
        .unwrap()
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let resp = call(&proto, &s, &req("m", Some(json!({})), Some(ID)))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32000);
    assert_eq!(resp["error"]["message"], "Not authorized");
}

#[tokio::test]
async fn audited_request_without_params_snapshots_empty_object() {
    // The params snapshot (now feeding only audit) reflects no-params as `{}`, not null.
    let seen = Arc::new(Mutex::new(Value::Null));
    let sp = seen.clone();
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .method(RpcMethod::new(
            MethodDef::new("noargs").audit(),
            |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
        ))
        .unwrap()
        .audit_sink(
            move |req: &RequestInfo,
                  _outcome: AuditOutcome<'_>,
                  _s: &Session<()>,
                  _m: Option<&str>| {
                *sp.lock().unwrap() = req.params.clone();
            },
        )
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    call(&proto, &s, &req("noargs", None, Some(ID)))
        .await
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), json!({}));
}

#[test]
fn role_mask_and_registry_basics() {
    assert!(RoleMask::NONE.is_empty());
    assert!(!RoleMask::FULL_ADMIN.is_empty());
    let roles = Roles::new(["a", "b", "c"]);
    let a = roles.get("a").unwrap();
    let b = roles.get("b").unwrap();
    let ab = roles.mask(["a", "b"]).unwrap();
    assert!(ab.satisfies(a)); // {a,b} ⊇ {a}
    assert!(!a.satisfies(ab)); // {a} ⊉ {a,b}
    assert!(a.satisfies(RoleMask::NONE)); // empty requirement is always satisfied
    assert_eq!(a.union(b), ab); // union (hierarchy expansion)
    assert!(roles.get("z").is_none()); // unknown name
    assert_eq!(roles.mask(["a", "z"]).unwrap_err(), "z"); // unknown name → Err
}

#[test]
fn method_with_roles_but_no_registry_is_a_build_error() {
    let r = JsonRpcProtocol::<()>::builder("p", "1").method(RpcMethod::new(
        MethodDef::new("m").roles(["x"]),
        |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
    ));
    assert!(
        matches!(r, Err(Error::Config(_))),
        "expected a Config build error"
    );
}

#[test]
fn method_with_unregistered_role_is_a_build_error() {
    let r = JsonRpcProtocol::<()>::builder("p", "1")
        .roles(Roles::new(["known"]))
        .method(RpcMethod::new(
            MethodDef::new("m").roles(["unknown"]),
            |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
        ));
    assert!(
        matches!(r, Err(Error::Config(_))),
        "expected a Config build error"
    );
}

#[tokio::test]
async fn audit_message_join_variants() {
    let cap = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let sink = cap.clone();
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .method(RpcMethod::new(
            MethodDef::new("both").audit_message("static"),
            |_a: Value, cx: &RequestCtx<()>| {
                cx.set_audit("runtime");
                Ok::<Value, JsonRpcError>(json!(null))
            },
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("runtime_only").audit(),
            |_a: Value, cx: &RequestCtx<()>| {
                cx.set_audit("rt");
                Ok::<Value, JsonRpcError>(json!(null))
            },
        ))
        .unwrap()
        .method(RpcMethod::new(
            MethodDef::new("neither").audit(),
            |_a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(json!(null)),
        ))
        .unwrap()
        .audit_sink(
            move |_r: &RequestInfo,
                  _outcome: AuditOutcome<'_>,
                  _s: &Session<()>,
                  msg: Option<&str>| {
                sink.lock().unwrap().push(msg.map(str::to_string));
            },
        )
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    call(&proto, &s, &req("both", Some(json!({})), Some(ID))).await;
    call(&proto, &s, &req("runtime_only", Some(json!({})), Some(ID))).await;
    call(&proto, &s, &req("neither", Some(json!({})), Some(ID))).await;
    let rows = cap.lock().unwrap();
    assert_eq!(rows[0].as_deref(), Some("static runtime"));
    assert_eq!(rows[1].as_deref(), Some("rt"));
    assert_eq!(rows[2], None);
}

#[tokio::test]
async fn audit_redacts_secrets_in_nested_arrays() {
    let cap = Arc::new(Mutex::new(Vec::<Value>::new()));
    let sink = cap.clone();
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .method(RpcMethod::new(
            MethodDef::new("login").audit().secret_fields(["password"]),
            |a: Value, _c: &RequestCtx<()>| Ok::<Value, JsonRpcError>(a),
        ))
        .unwrap()
        .audit_sink(
            move |r: &RequestInfo,
                  _outcome: AuditOutcome<'_>,
                  _s: &Session<()>,
                  _m: Option<&str>| {
                sink.lock().unwrap().push(r.params.clone());
            },
        )
        .build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let params = json!({ "accounts": [{ "password": "a" }, { "password": "b" }], "password": "c" });
    call(&proto, &s, &req("login", Some(params), Some(ID))).await;
    let rows = cap.lock().unwrap();
    assert_eq!(rows[0]["password"], "********");
    assert_eq!(rows[0]["accounts"][0]["password"], "********");
    assert_eq!(rows[0]["accounts"][1]["password"], "********");
}

// --- $/cancelRequest ---------------------------------------------------------

#[tokio::test]
async fn cancel_missing_target_id_is_invalid_params() {
    let proto = JsonRpcProtocol::<()>::builder("p", "1").build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let r = call(
        &proto,
        &s,
        &req("$/cancelRequest", Some(json!({})), Some(ID)),
    )
    .await
    .unwrap();
    assert_eq!(r["error"]["code"], -32602);
    let r2 = call(&proto, &s, &req("$/cancelRequest", None, Some(ID)))
        .await
        .unwrap();
    assert_eq!(r2["error"]["code"], -32602);
}

#[tokio::test]
async fn cancel_unknown_target_is_request_failed() {
    // A FULL_ADMIN passes the owner-or-admin gate and reaches the existence check → not-found.
    let proto = JsonRpcProtocol::<()>::builder("p", "1").build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    s.set_roles(RoleMask::FULL_ADMIN);
    let r = call(
        &proto,
        &s,
        &req(
            "$/cancelRequest",
            Some(json!({ "target_id": ID2 })),
            Some(ID),
        ),
    )
    .await
    .unwrap();
    assert_eq!(r["error"]["code"], -32803);
}

#[tokio::test]
async fn cancel_unknown_target_by_non_admin_is_not_authorized() {
    // A non-owner/non-admin is denied *before* the existence check (no existence leak).
    let proto = JsonRpcProtocol::<()>::builder("p", "1").build();
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    let r = call(
        &proto,
        &s,
        &req(
            "$/cancelRequest",
            Some(json!({ "target_id": ID2 })),
            Some(ID),
        ),
    )
    .await
    .unwrap();
    assert_eq!(r["error"]["code"], -32000);
    assert_eq!(r["error"]["message"], "Not authorized");
}

/// Spawn a cancellable request whose handler parks until `proceed`, returning handles to
/// observe it. Used to have a request genuinely in-flight when `$/cancelRequest` arrives.
fn parking_proto(
    started: Arc<AtomicBool>,
    proceed: Arc<AtomicBool>,
    canceller_called: Arc<AtomicBool>,
) -> Arc<JsonRpcProtocol<()>> {
    let (st, pr) = (started.clone(), proceed.clone());
    let cc = canceller_called;
    let b = JsonRpcProtocol::<()>::builder("p", "1")
        .method(RpcMethod::new(
            MethodDef::new("slow").cancellable(),
            move |_a: Value, cx: &RequestCtx<()>| {
                st.store(true, Ordering::SeqCst);
                while !pr.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                cx.raise_if_cancelled()?;
                Ok::<Value, JsonRpcError>(json!({ "done": true }))
            },
        ))
        .unwrap()
        .cancellation(move |_req: &RequestInfo, _s: &Session<()>| cc.store(true, Ordering::SeqCst));
    Arc::new(b.build())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_in_flight_request_sets_flag_and_calls_canceller() {
    let started = Arc::new(AtomicBool::new(false));
    let proceed = Arc::new(AtomicBool::new(false));
    let canceller = Arc::new(AtomicBool::new(false));
    let proto = parking_proto(started.clone(), proceed.clone(), canceller.clone());
    let session = proto.new_session(Some(()), Arc::new(NullOutbound));

    let work = {
        let (p, s, wire) = (
            proto.clone(),
            session.clone(),
            req("slow", Some(json!({})), Some(ID)),
        );
        tokio::spawn(async move { p.dispatch(&wire, &s).await.into_bytes() })
    };
    while !started.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let cancel = call(
        &proto,
        &session,
        &req(
            "$/cancelRequest",
            Some(json!({ "target_id": ID })),
            Some(ID2),
        ),
    )
    .await
    .unwrap();
    assert_eq!(cancel["result"], json!(true));
    assert!(canceller.load(Ordering::SeqCst));

    proceed.store(true, Ordering::SeqCst);
    let work_bytes = work.await.unwrap().unwrap();
    let v: Value = serde_json::from_slice(&work_bytes).unwrap();
    assert_eq!(v["error"]["code"], -32800); // REQUEST_CANCELLED, observed cooperatively
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_by_a_different_non_admin_session_is_denied() {
    let started = Arc::new(AtomicBool::new(false));
    let proceed = Arc::new(AtomicBool::new(false));
    let canceller = Arc::new(AtomicBool::new(false));
    let proto = parking_proto(started.clone(), proceed.clone(), canceller.clone());
    let owner = proto.new_session(Some(()), Arc::new(NullOutbound));
    let other = proto.new_session(Some(()), Arc::new(NullOutbound)); // different session, no roles

    let work = {
        let (p, s, wire) = (
            proto.clone(),
            owner.clone(),
            req("slow", Some(json!({})), Some(ID)),
        );
        tokio::spawn(async move { p.dispatch(&wire, &s).await.into_bytes() })
    };
    while !started.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    // `other` is neither the owner nor FULL_ADMIN → it cannot cancel the owner's request.
    let cancel = call(
        &proto,
        &other,
        &req(
            "$/cancelRequest",
            Some(json!({ "target_id": ID })),
            Some(ID2),
        ),
    )
    .await
    .unwrap();
    assert_eq!(cancel["error"]["code"], -32000);
    assert_eq!(cancel["error"]["message"], "Not authorized");
    assert!(!canceller.load(Ordering::SeqCst));

    proceed.store(true, Ordering::SeqCst);
    let _ = work.await.unwrap();
}

// --- async pipeline decode/authz branches ------------------------------------

#[tokio::test]
async fn async_pipeline_decode_and_authz_branches() {
    let proto = JsonRpcProtocol::<()>::builder("p", "1")
        .roles(Roles::new(["AUTH"]))
        .async_method(AsyncRpcMethod::new(
            MethodDef::new("aecho").roles(["AUTH"]),
            |a: EchoArgs, _cx: RequestCtx<()>| async move {
                Ok::<_, JsonRpcError>(EchoResult { echo: a.msg })
            },
        ))
        .unwrap()
        .build();
    // A session without the required role.
    let s = proto.new_session(Some(()), Arc::new(NullOutbound));
    // bad params → INVALID_PARAMS (async decode-error branch, before the gate)
    let bad = call(&proto, &s, &req("aecho", Some(json!({})), Some(ID)))
        .await
        .unwrap();
    assert_eq!(bad["error"]["code"], -32602);
    // good params but the role isn't granted → NOT_AUTHORIZED (async authz-denied branch)
    let denied = call(
        &proto,
        &s,
        &req("aecho", Some(json!({ "msg": "x" })), Some(ID)),
    )
    .await
    .unwrap();
    assert_eq!(denied["error"]["code"], -32000);
    // a FULL_ADMIN session → allowed → result (async run branch)
    let admin = proto.new_session(Some(()), Arc::new(NullOutbound));
    admin.set_roles(RoleMask::FULL_ADMIN);
    let ok = call(
        &proto,
        &admin,
        &req("aecho", Some(json!({ "msg": "hi" })), Some(ID)),
    )
    .await
    .unwrap();
    assert_eq!(ok["result"]["echo"], "hi");
}
