//! The mechanism-agnostic session-setup driver's refusal arms: `DENIED` / `EXPIRED` / `OTP_REQUIRED`
//! (the challenge → success path is covered end-to-end by the SCRAM test). A dummy mechanism drives a
//! server whose `$/sessionSetup` echoes back a canned `AuthResult` chosen by the request.

use serde_json::{json, Value};
use truenas_rpc::{JsonRpcError, JsonRpcProtocol, MethodDef, Session, SessionLifecycle};
use truenas_rpc_client::{AuthOutcome, ClientConfig, ClientError, Endpoint, JsonRpcClient, Mechanism};
use truenas_rpc_server::{JsonRpc, TruenasRpcServer, UnixConfig};

/// A no-crypto mechanism whose first message carries `{"want": <response_type>}`.
struct Echo {
    want: &'static str,
}
impl Mechanism for Echo {
    fn first(&mut self) -> Result<Value, ClientError> {
        Ok(json!({ "mechanism": "echo", "want": self.want }))
    }
    fn respond(&mut self, _data: &Value) -> Result<Value, ClientError> {
        Err(ClientError::Auth("echo has no continue step".into()))
    }
}

/// `$/sessionSetup` returns a canned `AuthResult`: `SUCCESS` for the known single-shot mechanism tags
/// (and empty peer-cred), or the refusal `response_type` an `Echo`'s `want` field selects.
fn arms_proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("arms", "1")
        .session_setup(MethodDef::new("$/sessionSetup"), |a: Value, _s: &Session<()>| {
            let mech = a.get("mechanism");
            let response = match mech.and_then(|m| m.get("mechanism")).and_then(Value::as_str) {
                Some("CLIENT_CERTIFICATE") => json!({ "response_type": "SUCCESS", "session_id": "s-mtls" }),
                Some("OAUTH") => json!({ "response_type": "SUCCESS", "session_id": "s-oauth" }),
                Some("GSSAPI_BEARER_TOKEN") => json!({ "response_type": "SUCCESS", "session_id": "s-bearer" }),
                _ if mech.is_none() => json!({ "response_type": "SUCCESS", "session_id": "s-peercred" }),
                _ => match mech.and_then(|m| m.get("want")).and_then(Value::as_str) {
                    Some("OTP_REQUIRED") => json!({ "response_type": "OTP_REQUIRED", "username": "alice" }),
                    Some("EXPIRED") => json!({ "response_type": "EXPIRED" }),
                    _ => json!({ "response_type": "DENIED" }),
                },
            };
            Ok::<_, JsonRpcError>((SessionLifecycle::None, json!({ "response": response })))
        })
        .build()
}

async fn connect(tag: &str) -> (std::path::PathBuf, JsonRpcClient) {
    let path = std::env::temp_dir().join(format!("tnrpc-arms-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let srv = TruenasRpcServer::<()>::builder("arms-server").protocol("arms", arms_proto()).build();
    let listener = TruenasRpcServer::<()>::bind_unix(&UnixConfig::new(&path)).unwrap();
    tokio::spawn(async move { srv.serve_unix_listener(listener, JsonRpc).await });
    let (client, _neg, _notifs) =
        JsonRpcClient::connect_negotiate(&Endpoint::unix(&path), "arms", ClientConfig::default())
            .await
            .unwrap();
    (path, client)
}

#[tokio::test]
async fn driver_maps_every_refusal_response() {
    let (path, client) = connect("refusals").await;

    assert!(matches!(client.authenticate_with(Echo { want: "DENIED" }).await.unwrap(), AuthOutcome::Denied));
    assert!(matches!(client.authenticate_with(Echo { want: "EXPIRED" }).await.unwrap(), AuthOutcome::Expired));
    match client.authenticate_with(Echo { want: "OTP_REQUIRED" }).await.unwrap() {
        AuthOutcome::OtpRequired { username } => assert_eq!(username, "alice"),
        other => panic!("expected OtpRequired, got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn single_shot_helpers_establish() {
    let (path, client) = connect("helpers").await;

    // Each helper sends its mechanism object (or, for peer-cred, none) and maps SUCCESS → Established.
    for outcome in [
        client.authenticate_peercred().await.unwrap(),
        client.authenticate_mtls().await.unwrap(),
        client.authenticate_oauth("a.jwt.token").await.unwrap(),
        client.authenticate_bearer("a-bearer-token").await.unwrap(),
    ] {
        assert!(matches!(outcome, AuthOutcome::Established { .. }), "got {outcome:?}");
    }

    let _ = std::fs::remove_file(&path);
}
