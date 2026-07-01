//! The **JSON-RPC protocol runtime** — the hand-written hook implementations the engine drives:
//! 4-byte length-prefix framing and the JSON-RPC 2.0 envelope (method-by-name + UUID id), plus the
//! **TXDR binary sub-wire**: a method the IDL flags `xdr` is called by proc-id over a TXDR frame on
//! the *same* negotiated connection (the server auto-detects `{` vs the TXDR magic). One
//! `CorrelationKey = Uuid` covers both wires because a TXDR reply id is `[u8;16]` = a UUID's bytes.
//! Also home to the `$/negotiate` / `$/sessionSetup` / `$/sessionClose` capabilities.

use bytes::BytesMut;
use serde_json::value::RawValue;
use uuid::Uuid;

use truenas_rpc::JsonRpcError;

use crate::config::{ClientConfig, Endpoint};
use crate::engine::{
    Authenticates, CallEngine, Client, EncodedCall, Framing, GracefulClose, Inbound, MethodKey,
    Negotiates, NotificationStream, ProtocolRuntime,
};
use crate::error::ClientError;

const HEADER: usize = 4;

/// 4-byte big-endian length prefix framing (the JSON-RPC + TXDR wire framing).
pub struct LengthPrefix;

impl Framing for LengthPrefix {
    fn take_frame(&self, acc: &mut BytesMut, limit: usize) -> Result<Option<Vec<u8>>, ClientError> {
        if acc.len() < HEADER {
            return Ok(None);
        }
        let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
        if len > limit {
            return Err(ClientError::Decode(format!("inbound frame ({len} bytes) exceeds limit {limit}")));
        }
        if acc.len() < HEADER + len {
            return Ok(None);
        }
        let _ = acc.split_to(HEADER); // drop the length prefix
        Ok(Some(acc.split_to(len).to_vec()))
    }

    fn frame_into(&self, out: &mut Vec<u8>, payload: &[u8]) {
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
    }
}

/// How a JSON-RPC-runtime call addresses its method: by **name** (the JSON text wire) or by XDR
/// **proc-id** (the TXDR binary sub-wire, on the same connection). The engine's codegen-facing
/// [`MethodKey`] maps onto this.
pub enum JsonRpcMethod {
    /// A JSON-RPC method name.
    Name(String),
    /// A TXDR proc-id (the method was flagged `xdr` in the IDL).
    Proc(u32),
}

/// The JSON-RPC runtime. Stateless beyond its framing (request ids are fresh UUIDs).
pub struct JsonRpcRuntime {
    framing: LengthPrefix,
}

impl Default for JsonRpcRuntime {
    fn default() -> Self {
        JsonRpcRuntime { framing: LengthPrefix }
    }
}

impl ProtocolRuntime for JsonRpcRuntime {
    type MethodKey = JsonRpcMethod;
    type CorrelationKey = Uuid;
    type Topic = String;
    type Framing = LengthPrefix;

    fn framing(&self) -> &LengthPrefix {
        &self.framing
    }

    fn encode_call(&self, method: &JsonRpcMethod, params: &[u8]) -> EncodedCall<Uuid> {
        let id = Uuid::new_v4();
        let wire = match method {
            // Name → the JSON text envelope; the reply comes back as JSON, correlated by the id string.
            JsonRpcMethod::Name(name) => encode_json_request(name, &id, params),
            // Proc → a TXDR frame using the call's UUID as the 16-byte xid; `params` are already
            // XDR-encoded by the caller. The reply comes back as a TXDR frame, correlated by the xid.
            JsonRpcMethod::Proc(proc) => {
                let mut out = Vec::with_capacity(params.len() + 40);
                truenas_xdr::frame::build_request_into(&mut out, *proc, Some(*id.as_bytes()), params)
                    .expect("XDR request envelope encodes");
                out
            }
        };
        EncodedCall { wire, key: id }
    }

    fn parse_inbound(&self, frame: &[u8]) -> Result<Inbound<Self>, ClientError> {
        // A JSON envelope always begins with `{`; anything else on this connection is a TXDR frame.
        if frame.first() == Some(&b'{') {
            parse_json_reply(frame)
        } else {
            parse_xdr_reply(frame)
        }
    }
}

/// Build a JSON-RPC 2.0 request `{"jsonrpc":"2.0","method":<name>,"id":"<uuid>","params":<params>}`
/// in one pass: the method name is JSON-escaped, the id is the canonical hyphenated UUID written
/// allocation-free, and the already-encoded `params` JSON bytes are spliced directly (no `RawValue`
/// re-wrap, no `format!`). An empty `params` omits the member. Byte-identical to the two-step form.
fn encode_json_request(name: &str, id: &Uuid, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(params.len() + name.len() + 64);
    out.extend_from_slice(br#"{"jsonrpc":"2.0","method":"#);
    serde_json::to_writer(&mut out, name).expect("a string always serializes");
    out.extend_from_slice(br#","id":""#);
    let mut buf = [0u8; uuid::fmt::Hyphenated::LENGTH];
    out.extend_from_slice(id.hyphenated().encode_lower(&mut buf).as_bytes());
    if params.is_empty() {
        out.extend_from_slice(br#""}"#);
    } else {
        out.extend_from_slice(br#"","params":"#);
        out.extend_from_slice(params);
        out.push(b'}');
    }
    out
}

/// The JSON `error` member / TXDR error detail: `{code, message, data?}`.
#[derive(serde::Deserialize)]
struct WireError {
    code: i32,
    message: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

/// Classify one inbound JSON-RPC frame: a reply (has an `id`) or a notification (a `method`, no
/// `id`). Result/params bytes are the raw JSON member text (spliced through to the caller).
fn parse_json_reply(frame: &[u8]) -> Result<Inbound<JsonRpcRuntime>, ClientError> {
    #[derive(serde::Deserialize)]
    struct Env {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        method: Option<String>,
        #[serde(default)]
        result: Option<Box<RawValue>>,
        #[serde(default)]
        error: Option<WireError>,
        #[serde(default)]
        params: Option<Box<RawValue>>,
    }

    let env: Env = serde_json::from_slice(frame).map_err(|e| ClientError::Decode(e.to_string()))?;
    if let Some(id) = env.id {
        let key =
            Uuid::parse_str(&id).map_err(|e| ClientError::Decode(format!("bad reply id {id:?}: {e}")))?;
        let result = match env.error {
            Some(e) => Err(JsonRpcError { code: e.code, message: e.message, data: e.data }),
            None => Ok(raw_bytes(env.result)),
        };
        Ok(Inbound::Reply { key, result })
    } else if let Some(method) = env.method {
        Ok(Inbound::Notification { topic: method, payload: raw_bytes(env.params) })
    } else {
        Err(ClientError::Decode("inbound message has neither id nor method".to_string()))
    }
}

/// Classify one inbound TXDR frame: a reply correlated by its 16-byte xid (= a UUID). `STATUS_OK`
/// carries the raw XDR result bytes; `STATUS_ERR` carries the `(code, detail-json)` error payload.
fn parse_xdr_reply(frame: &[u8]) -> Result<Inbound<JsonRpcRuntime>, ClientError> {
    use truenas_xdr::frame;
    let reply = frame::parse_reply(frame).map_err(|e| ClientError::Decode(e.to_string()))?;
    let Some(rid) = reply.rid else {
        return Err(ClientError::Decode("XDR reply carries no id".to_string()));
    };
    let key = Uuid::from_bytes(rid);
    let result = if reply.status == frame::STATUS_OK {
        Ok(reply.body.to_vec())
    } else {
        let (_code, detail) =
            frame::parse_error_payload(reply.body).map_err(|e| ClientError::Decode(e.to_string()))?;
        let e: WireError =
            serde_json::from_slice(&detail).map_err(|e| ClientError::Decode(e.to_string()))?;
        Err(JsonRpcError { code: e.code, message: e.message, data: e.data })
    };
    Ok(Inbound::Reply { key, result })
}

/// The raw JSON text of a `RawValue` member, or `null` when absent.
fn raw_bytes(v: Option<Box<RawValue>>) -> Vec<u8> {
    v.map(|r| r.get().as_bytes().to_vec()).unwrap_or_else(|| b"null".to_vec())
}

// --- Capabilities ------------------------------------------------------------------------------

/// The `$/negotiate` result: the bound protocol, the server name, and the offered protocols.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Negotiated {
    /// The bound protocol name.
    pub protocol: String,
    /// The server's name, if reported.
    #[serde(default)]
    pub server: Option<String>,
    /// The protocols the server offers.
    #[serde(default)]
    pub available: Vec<String>,
}

impl Negotiates for JsonRpcRuntime {
    type Negotiated = Negotiated;
    fn encode_negotiate(&self, protocol: &str) -> EncodedCall<Uuid> {
        let protocol = serde_json::to_string(protocol).unwrap_or_else(|_| "\"\"".to_string());
        let params = format!(r#"{{"protocol":{protocol}}}"#).into_bytes();
        self.encode_call(&JsonRpcMethod::Name("$/negotiate".to_string()), &params)
    }
}

impl Authenticates for JsonRpcRuntime {
    fn encode_setup(&self, params: Option<&RawValue>) -> EncodedCall<Uuid> {
        self.encode_call(&JsonRpcMethod::Name("$/sessionSetup".to_string()), raw_param(params))
    }
    fn encode_setup_continue(&self, params: Option<&RawValue>) -> EncodedCall<Uuid> {
        self.encode_call(&JsonRpcMethod::Name("$/sessionSetupContinue".to_string()), raw_param(params))
    }
}

impl GracefulClose for JsonRpcRuntime {
    fn encode_close(&self) -> EncodedCall<Uuid> {
        self.encode_call(&JsonRpcMethod::Name("$/sessionClose".to_string()), &[])
    }
}

/// The raw JSON bytes of an optional control-path `RawValue` param (empty = no params member).
fn raw_param(params: Option<&RawValue>) -> &[u8] {
    params.map(|r| r.get().as_bytes()).unwrap_or(&[])
}

// --- The concrete JSON-RPC client --------------------------------------------------------------

/// A JSON-RPC client: the engine over the JSON-RPC runtime.
pub type JsonRpcClient = Client<JsonRpcRuntime>;

impl JsonRpcClient {
    /// Connect (no `$/negotiate` yet). Use [`connect_negotiate`](Self::connect_negotiate) for the
    /// common bind-then-use flow.
    pub async fn open(
        endpoint: &Endpoint,
        config: ClientConfig,
    ) -> Result<(Self, NotificationStream<String>), ClientError> {
        Client::connect(JsonRpcRuntime::default(), endpoint, config).await
    }

    /// Connect and bind `protocol` via `$/negotiate`.
    pub async fn connect_negotiate(
        endpoint: &Endpoint,
        protocol: &str,
        config: ClientConfig,
    ) -> Result<(Self, Negotiated, NotificationStream<String>), ClientError> {
        let (client, notifs) = Self::open(endpoint, config).await?;
        let negotiated = client.negotiate(protocol).await?;
        Ok((client, negotiated, notifs))
    }
}

#[async_trait::async_trait]
impl CallEngine for JsonRpcClient {
    async fn call(&self, method: MethodKey<'_>, params: &[u8]) -> Result<Vec<u8>, JsonRpcError> {
        // Map the codegen-facing key onto the runtime key. `params` are already the wire bytes
        // (JSON for a name, XDR for a proc-id) — spliced through the engine with no re-encode.
        let key = match method {
            MethodKey::Name(n) => JsonRpcMethod::Name(n.to_string()),
            MethodKey::Proc(p) => JsonRpcMethod::Proc(p),
        };
        Client::call(self, &key, params).await.map_err(ClientError::into_jsonrpc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The one-pass JSON encoder must be byte-identical to the two-step envelope it replaced, so the
    // server (which enforces a UUID id) and every existing test still see the same bytes.
    #[test]
    fn json_request_is_byte_identical() {
        let id = Uuid::parse_str("f81d4fae-7dec-11d0-a765-00a0c91e6bf6").unwrap();
        // With params.
        assert_eq!(
            encode_json_request("add", &id, br#"{"a":1,"b":2}"#),
            br#"{"jsonrpc":"2.0","method":"add","id":"f81d4fae-7dec-11d0-a765-00a0c91e6bf6","params":{"a":1,"b":2}}"#
        );
        // Without params (control-path close).
        assert_eq!(
            encode_json_request("$/sessionClose", &id, b""),
            br#"{"jsonrpc":"2.0","method":"$/sessionClose","id":"f81d4fae-7dec-11d0-a765-00a0c91e6bf6"}"#
        );
    }
}
