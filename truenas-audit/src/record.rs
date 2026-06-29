//! Building the audit record's `(AUDIT_* type, message string)` — pure, no syscalls, fully tested.
//!
//! The message mirrors linux-PAM's field layout (`op=<svc>:<verb>`, `acct=`, `addr=`,
//! `res=success|failed`) and then carries the TrueNAS audit payload **flattened** to native fields:
//! `svc_*` (the service/credential context) and `event_data_<key>` (the request params, one field
//! per argument; a nested value is stringified to JSON, so deeply-nested params still land — just
//! less greppable). Values are libaudit-encoded: a clean value is `key="value"`, a value containing
//! `"`, a byte `< 0x21`, or `0x7F` is hex-encoded as `key=HEX` (uppercase, unquoted).

use serde_json::Value;

use truenas_rpc::{AuditOutcome, RequestInfo};

// AUDIT_* user-message types (uapi/linux/audit.h + audit-records.h); see the PAM mapping.
const AUDIT_USER_AUTH: u16 = 1100;
const AUDIT_USER_ACCT: u16 = 1101;
const AUDIT_USER_END: u16 = 1106;
const AUDIT_TRUSTED_APP: u16 = 1121;

/// The `NOT_AUTHORIZED` JSON-RPC error code (a denial → `AUDIT_USER_ACCT`, `res=failed`).
const NOT_AUTHORIZED: i32 = -32000;

/// The authenticated principal an audit record describes — produced by the embedder's extractor
/// from the session's identity + peer. All optional: an unauthenticated/anonymous call still audits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditPrincipal {
    /// The account name (`acct=` / `svc_cred_username=`).
    pub user: Option<String>,
    /// The Unix uid, if known.
    pub uid: Option<u32>,
    /// The client origin (`addr=` / `svc_origin=`), e.g. `10.0.0.5:5234` or `unix:uid=0`.
    pub origin: Option<String>,
    /// The credential class (`svc_cred=`), e.g. `API_KEY` / `USER_SESSION`.
    pub cred_type: Option<String>,
    /// The API-key id (`svc_cred_api_key_id=`), if the credential is an API key.
    pub api_key_id: Option<String>,
}

/// Build one audit record: classify the event, then assemble the field string. `aid` is the unique
/// audit id (a fresh uuid the caller supplies — injected so this stays pure/deterministic).
pub(crate) fn build_record(
    service: &str,
    aid: &str,
    sess: &str,
    request: &RequestInfo,
    outcome: AuditOutcome<'_>,
    principal: &AuditPrincipal,
    audit_message: Option<&str>,
) -> (u16, String) {
    let error = outcome.error();
    let success = outcome.succeeded();
    let (msg_type, verb, is_control) = classify(&request.method, error.map(|e| e.code));

    let mut buf = String::with_capacity(256);
    // Standard (ausearch-keyed) fields — `op`/`res` are bare tokens, the rest are nv-encoded.
    buf.push_str("op=");
    buf.push_str(service);
    buf.push(':');
    buf.push_str(verb);
    push_opt(&mut buf, "acct", principal.user.as_deref());
    push_opt(&mut buf, "addr", principal.origin.as_deref());
    buf.push(' ');
    buf.push_str("res=");
    buf.push_str(if success { "success" } else { "failed" });

    // Audit-specific identifiers.
    encode_nv(&mut buf, "method", &request.method);
    push_opt(&mut buf, "reqid", request.id.as_deref());
    encode_nv(&mut buf, "sess", sess);
    encode_nv(&mut buf, "svc", service);
    encode_nv(&mut buf, "aid", aid);
    encode_nv(&mut buf, "event", if is_control { "CONTROL_MESSAGE" } else { "METHOD_CALL" });

    // Flattened svc_data (service/credential context).
    encode_nv(&mut buf, "svc_protocol", "JSONRPC");
    push_opt(&mut buf, "svc_origin", principal.origin.as_deref());
    push_opt(&mut buf, "svc_cred", principal.cred_type.as_deref());
    push_opt(&mut buf, "svc_cred_username", principal.user.as_deref());
    push_opt(&mut buf, "svc_cred_api_key_id", principal.api_key_id.as_deref());

    // Flattened event_data: the description, then one field per (already-redacted) param.
    push_opt(&mut buf, "event_desc", audit_message);
    if let Value::Object(map) = &request.params {
        for (k, v) in map {
            encode_nv(&mut buf, &format!("event_data_{}", sanitize_key(k)), &value_to_field(v));
        }
    }
    // The error, flattened into native fields (code + message + optional data) — not a JSON blob.
    if let Some(err) = error {
        encode_nv(&mut buf, "event_error_code", &err.code.to_string());
        encode_nv(&mut buf, "event_error", &err.message);
        if let Some(data) = &err.data {
            encode_nv(&mut buf, "event_error_data", &value_to_field(data));
        }
    }

    (msg_type, buf)
}

/// A synthetic record reporting `n` records dropped because the audit queue overflowed (the kernel
/// audit subsystem has the same "lost" concept).
pub(crate) fn lost_record(service: &str, n: u64) -> (u16, String) {
    (AUDIT_TRUSTED_APP, format!("op={service}:audit_lost res=failed lost=\"{n}\""))
}

/// Map an event to its `(AUDIT_* type, op-verb, is_control)`, mirroring linux-PAM's switch.
fn classify(method: &str, error_code: Option<i32>) -> (u16, &'static str, bool) {
    match method {
        "$/sessionSetup" | "$/sessionSetupContinue" => (AUDIT_USER_AUTH, "authentication", true),
        "$/sessionClose" => (AUDIT_USER_END, "session_close", true),
        m if m.starts_with("$/") => (AUDIT_TRUSTED_APP, "control", true),
        _ if error_code == Some(NOT_AUTHORIZED) => (AUDIT_USER_ACCT, "accounting", false),
        _ => (AUDIT_TRUSTED_APP, "method", false),
    }
}

/// A JSON value as an audit field string: scalars become their text, a nested object/array is
/// stringified to compact JSON (which the encoder then hex-encodes), so the record stays flat.
fn value_to_field(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(_) | Value::Object(_) => v.to_string(),
    }
}

/// Append ` key=<encoded>` for a present value; emit nothing if `None`.
fn push_opt(buf: &mut String, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        encode_nv(buf, key, v);
    }
}

/// Append ` key="value"` (clean) or ` key=HEX` (when the value needs encoding), libaudit-style.
fn encode_nv(buf: &mut String, key: &str, value: &str) {
    buf.push(' ');
    buf.push_str(key);
    buf.push('=');
    if needs_encoding(value) {
        for b in value.bytes() {
            buf.push(char::from_digit((b >> 4) as u32, 16).unwrap().to_ascii_uppercase());
            buf.push(char::from_digit((b & 0x0f) as u32, 16).unwrap().to_ascii_uppercase());
        }
    } else {
        buf.push('"');
        buf.push_str(value);
        buf.push('"');
    }
}

/// libaudit's `audit_value_needs_encoding`: a `"`, any control/space byte (`< 0x21`), or `0x7F`.
/// An empty value is encoded too (so it can't be confused with a bare token).
fn needs_encoding(value: &str) -> bool {
    value.is_empty() || value.bytes().any(|b| b == b'"' || b < 0x21 || b == 0x7f)
}

/// Keep a param name usable as an audit field name (no spaces/`=`): map anything outside
/// `[A-Za-z0-9_]` to `_`.
fn sanitize_key(key: &str) -> String {
    key.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use truenas_rpc::JsonRpcError;

    fn req(method: &str, params: Value) -> RequestInfo {
        RequestInfo { method: method.into(), id: Some("rid-1".into()), params, roles: vec![] }
    }

    #[test]
    fn clean_value_is_quoted_dirty_is_hex() {
        let mut b = String::new();
        encode_nv(&mut b, "acct", "admin");
        encode_nv(&mut b, "x", "a b"); // space → encode
        encode_nv(&mut b, "y", "he\"llo"); // quote → encode
        assert_eq!(b, " acct=\"admin\" x=612062 y=6865226C6C6F");
        // round-trip sanity: "a b" → 61 20 62
        assert!(needs_encoding("a b") && needs_encoding("\"") && needs_encoding(""));
        assert!(!needs_encoding("admin") && !needs_encoding("API_KEY"));
    }

    #[test]
    fn method_call_flattens_params_and_picks_trusted_app() {
        let p = AuditPrincipal {
            user: Some("admin".into()),
            origin: Some("10.0.0.5:5234".into()),
            cred_type: Some("API_KEY".into()),
            api_key_id: Some("2".into()),
            uid: Some(0),
        };
        let (ty, msg) = build_record(
            "truenas-api",
            "aid-123",
            "sess-1",
            &req("pool.query", json!({ "pool": "tank", "recursive": true })),
            AuditOutcome::Success,
            &p,
            Some("query pools"),
        );
        assert_eq!(ty, AUDIT_TRUSTED_APP);
        assert!(msg.starts_with("op=truenas-api:method acct=\"admin\" addr=\"10.0.0.5:5234\" res=success"));
        assert!(msg.contains(" method=\"pool.query\""));
        assert!(msg.contains(" event=\"METHOD_CALL\""));
        assert!(msg.contains(" svc_cred=\"API_KEY\" svc_cred_username=\"admin\" svc_cred_api_key_id=\"2\""));
        // "query pools" has a space, so it hex-encodes (libaudit behavior) rather than quoting.
        assert!(msg.contains(" event_desc=") && !msg.contains("event_desc=\""));
        assert!(msg.contains(" event_data_pool=\"tank\""));
        assert!(msg.contains(" event_data_recursive=\"true\""));
    }

    #[test]
    fn nested_param_is_stringified_then_hex_encoded() {
        let (_, msg) = build_record(
            "svc",
            "aid",
            "sess-1",
            &req("x.query", json!({ "filters": [["name", "=", "x"]] })),
            AuditOutcome::Success,
            &AuditPrincipal::default(),
            None,
        );
        // The nested array stringifies to JSON, which contains `[`/`"` → hex-encoded value.
        assert!(msg.contains(" event_data_filters="));
        assert!(!msg.contains("event_data_filters=\"")); // hex, not quoted
    }

    #[test]
    fn failure_and_denial_classification() {
        let (ty, msg) = build_record(
            "svc",
            "aid",
            "sess-1",
            &req("secret.op", json!({})),
            AuditOutcome::Failure(&JsonRpcError {
                code: -32000,
                message: "Not authorized".to_string(),
                data: None,
            }),
            &AuditPrincipal::default(),
            None,
        );
        assert_eq!(ty, AUDIT_USER_ACCT); // NOT_AUTHORIZED → accounting
        assert!(msg.contains("op=svc:accounting"));
        assert!(msg.contains(" res=failed"));
        assert!(msg.contains(" event_error_code=\"-32000\""));
        assert!(msg.contains(" event_error=")); // message "Not authorized" (hex — has a space)
    }

    #[test]
    fn session_setup_maps_to_user_auth() {
        let (ty, msg) = build_record(
            "svc",
            "aid",
            "sess-1",
            &req("$/sessionSetup", json!({ "mechanism": "********" })),
            AuditOutcome::Success,
            &AuditPrincipal::default(),
            None,
        );
        assert_eq!(ty, AUDIT_USER_AUTH);
        assert!(msg.contains("op=svc:authentication"));
        assert!(msg.contains(" event=\"CONTROL_MESSAGE\""));
        // a redacted secret param flattens to the masked value
        assert!(msg.contains(" event_data_mechanism=\"********\""));
    }
}
