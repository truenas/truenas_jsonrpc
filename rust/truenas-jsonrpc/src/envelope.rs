//! Permissive inbound envelope parsing + response construction.
//!
//! Mirrors Python's `JSONRPCEnvelope` (every field decoded permissively, then validated
//! in code) and `protocol.py::_dispatch_one` steps 1–3: malformed JSON → `INVALID_JSON`;
//! a valid non-object (incl. a top-level array/batch) → `INVALID_REQUEST`; a present `id`
//! must be a canonical UUID string; `jsonrpc == "2.0"`; `method` a non-empty string.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::ErrorCode;
use crate::JSONRPC_VERSION;

/// A structurally valid inbound request. `id == None` is a **notification**.
pub(crate) struct ParsedRequest {
    pub id: Option<String>,
    pub method: String,
    pub params: Option<Box<RawValue>>,
}

/// A structural parse failure. Python **always** replies to these (parse/id/jsonrpc/
/// method errors are never suppressed, even for an id-less message), so a `ParseError`
/// is always turned into a wire reply.
pub(crate) struct ParseError {
    pub code: ErrorCode,
    pub message: String,
    pub data: Option<String>,
    pub id: Option<String>,
}

#[derive(Deserialize)]
struct RawEnvelope {
    #[serde(default)]
    jsonrpc: Option<Box<RawValue>>,
    #[serde(default)]
    method: Option<Box<RawValue>>,
    #[serde(default)]
    id: Option<Box<RawValue>>,
    #[serde(default)]
    params: Option<Box<RawValue>>,
}

fn as_json_string(raw: &RawValue) -> Option<String> {
    serde_json::from_str::<String>(raw.get()).ok()
}

/// True if `value` is a canonical hyphenated UUID string (case-insensitive) — the exact
/// rule Python's `_is_uuid` enforces (`str(uuid.UUID(value)) == value.lower()`).
pub(crate) fn is_canonical_uuid(value: &str) -> bool {
    // Canonical hyphenated UUID (case-insensitive) — equivalent to Python's `_is_uuid`
    // (`str(uuid.UUID(value)) == value.lower()`) but allocation-free and parse-free.
    let b = value.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Parse + structurally validate one inbound frame. Steps 1–3 of the dispatch flow.
pub(crate) fn parse(wire: &[u8]) -> Result<ParsedRequest, ParseError> {
    // 1. Malformed JSON → INVALID_JSON. A valid non-object → INVALID_REQUEST.
    let raw: Box<RawValue> = serde_json::from_slice(wire).map_err(|e| ParseError {
        code: ErrorCode::InvalidJson,
        message: "Parse error".into(),
        data: Some(e.to_string()),
        id: None,
    })?;
    if raw.get().trim_start().as_bytes().first() != Some(&b'{') {
        return Err(ParseError {
            code: ErrorCode::InvalidRequest,
            message: "Invalid request".into(),
            data: Some("the request must be a JSON object".into()),
            id: None,
        });
    }
    // `raw` is an already-validated JSON object and every `RawEnvelope` field is an
    // optional `RawValue` (which captures any value verbatim), so this re-parse is
    // infallible — a failure would be a serde_json bug, not bad input.
    let env: RawEnvelope = serde_json::from_str(raw.get())
        .expect("a validated JSON object always deserializes into RawEnvelope");

    // 2. Resolve id: a present id MUST be a canonical UUID string; absent → notification.
    let id = match env.id {
        None => None,
        Some(raw_id) => match as_json_string(&raw_id) {
            Some(s) if is_canonical_uuid(&s) => Some(s),
            _ => {
                return Err(ParseError {
                    code: ErrorCode::InvalidRequest,
                    message: "Invalid request".into(),
                    data: Some("'id' must be a UUID string".into()),
                    id: None,
                })
            }
        },
    };

    // 3. Structural validation (never suppressed, even without an id).
    if env.jsonrpc.as_deref().and_then(as_json_string).as_deref() != Some(JSONRPC_VERSION) {
        return Err(ParseError {
            code: ErrorCode::InvalidRequest,
            message: "Invalid request".into(),
            data: Some("'jsonrpc' must be exactly '2.0'".into()),
            id,
        });
    }
    let method = match env.method.as_deref().and_then(as_json_string) {
        Some(m) if !m.is_empty() => m,
        _ => {
            return Err(ParseError {
                code: ErrorCode::InvalidRequest,
                message: "Invalid request".into(),
                data: Some("'method' must be a non-empty string".into()),
                id,
            })
        }
    };

    Ok(ParsedRequest { id, method, params: env.params })
}

// --- response construction ---------------------------------------------------

#[derive(Serialize)]
struct SuccessEnvelope<'a> {
    jsonrpc: &'static str,
    result: &'a RawValue,
    id: Option<&'a str>,
}

#[derive(Serialize)]
struct WireError<'a> {
    code: i32,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a serde_json::Value>,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    jsonrpc: &'static str,
    error: WireError<'a>,
    id: Option<&'a str>,
}

/// Build a success response: `{"jsonrpc":"2.0","result":<result>,"id":<id|null>}`.
/// `id` is `None` only for a notification (whose reply the caller then suppresses).
pub(crate) fn success(id: Option<&str>, result: &RawValue) -> Vec<u8> {
    serde_json::to_vec(&SuccessEnvelope { jsonrpc: JSONRPC_VERSION, result, id })
        .expect("serializing a success envelope cannot fail")
}

/// Build an error response: `{"jsonrpc":"2.0","error":{code,message,data?},"id":<id|null>}`.
pub(crate) fn error(
    id: Option<&str>,
    code: i32,
    message: &str,
    data: Option<&serde_json::Value>,
) -> Vec<u8> {
    serde_json::to_vec(&ErrorEnvelope {
        jsonrpc: JSONRPC_VERSION,
        error: WireError { code, message, data },
        id,
    })
    .expect("serializing an error envelope cannot fail")
}

/// Convenience: render a [`ParseError`] to wire bytes (always sent).
pub(crate) fn error_from_parse(e: &ParseError) -> Vec<u8> {
    let data = e.data.as_ref().map(|s| serde_json::Value::String(s.clone()));
    error(e.id.as_deref(), e.code.code(), &e.message, data.as_ref())
}

#[cfg(test)]
mod tests {
    use super::is_canonical_uuid;

    #[test]
    fn canonical_uuid_accepts_and_rejects() {
        // Accepted: canonical hyphenated form, case-insensitive.
        assert!(is_canonical_uuid("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"));
        assert!(is_canonical_uuid("F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6"));
        // Wrong length → rejected before the per-byte scan.
        assert!(!is_canonical_uuid(""));
        assert!(!is_canonical_uuid("not-a-uuid"));
        // Length 36 but a non-hex digit where a hex digit is required.
        assert!(!is_canonical_uuid("g81d4fae-7dec-11d0-a765-00a0c91e6bf6"));
        // Length 36 but a non-hyphen where a hyphen is required (index 8).
        assert!(!is_canonical_uuid("f81d4fae07dec-11d0-a765-00a0c91e6bf6"));
    }
}
