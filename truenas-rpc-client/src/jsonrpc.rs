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
use truenas_rpc::TransferDirection;

use crate::engine::{
    Authenticates, CallEngine, Client, Framing, GracefulClose, Inbound, MethodKey, Negotiates,
    NotificationStream, ProtocolRuntime, Transfers,
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

/// The JSON-RPC runtime: framing + a per-connection request-id source. Request ids are **not**
/// random per call — that would burn ~120 ns of userspace RNG on every send for correlation that
/// only needs uniqueness. Instead a 64-bit random `prefix` is drawn once at construction and the
/// low 64 bits are a monotonic sequence (drawn by the engine under the pending lock it already
/// holds). The high random half keeps the wire id globally unique across connections — so the
/// server's per-protocol `$/cancelRequest` table never collides, and a peer using fully-random
/// UUIDv4 stays interoperable (the wire id is 128 opaque bits either way).
pub struct JsonRpcRuntime {
    framing: LengthPrefix,
    prefix: u64,
}

impl Default for JsonRpcRuntime {
    fn default() -> Self {
        // One random draw per connection (amortized over every call it makes). The low 64 bits of a
        // v4 UUID are fully random (the version/variant bits sit higher), so take those as the prefix.
        JsonRpcRuntime { framing: LengthPrefix, prefix: Uuid::new_v4().as_u128() as u64 }
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

    fn key_for_seq(&self, seq: u64) -> Uuid {
        // High 64 bits: the per-connection random prefix. Low 64 bits: the monotonic sequence. The
        // result is a valid canonical UUID (the server validates format, not how it was minted).
        Uuid::from_u128(((self.prefix as u128) << 64) | seq as u128)
    }

    fn encode_call(&self, method: &JsonRpcMethod, params: &[u8], key: &Uuid) -> Vec<u8> {
        match method {
            // Name → the JSON text envelope; the reply comes back as JSON, correlated by the id string.
            JsonRpcMethod::Name(name) => encode_json_request(name, key, params),
            // Proc → a TXDR frame using the call's UUID as the 16-byte xid; `params` are already
            // XDR-encoded by the caller. The reply comes back as a TXDR frame, correlated by the xid.
            JsonRpcMethod::Proc(proc) => encode_xdr_request(*proc, key, params),
        }
    }

    fn encode_cancel(&self, target: &Uuid) -> Option<Vec<u8>> {
        // A **no-id** `$/cancelRequest` notification (fire-and-forget): the server cancels the target
        // and sends nothing back. `target_id` is the target call's id — the canonical UUID the
        // request went out under (`Uuid`'s `Display` is the canonical hyphenated lowercase form).
        let params = format!(r#"{{"target_id":"{target}"}}"#);
        Some(encode_json_notification("$/cancelRequest", params.as_bytes()))
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

/// Encode a TXDR request frame (proc-id key): the 16-byte `id` becomes the xid, `params` are the
/// caller's already-XDR-encoded body. Written straight into the request buffer — no id allocation.
fn encode_xdr_request(proc: u32, id: &Uuid, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(params.len() + 40);
    truenas_xdr::frame::build_request_into(&mut out, proc, Some(*id.as_bytes()), params)
        .expect("XDR request envelope encodes");
    out
}

/// A no-id JSON-RPC notification `{"jsonrpc":"2.0","method":..,"params":..}` — the fire-and-forget
/// shape (no `id`, so the server sends no reply). Used for `$/cancelRequest` on a call's drop.
fn encode_json_notification(method: &str, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(params.len() + method.len() + 48);
    out.extend_from_slice(br#"{"jsonrpc":"2.0","method":"#);
    serde_json::to_writer(&mut out, method).expect("a string always serializes");
    if params.is_empty() {
        out.push(b'}');
    } else {
        out.extend_from_slice(br#","params":"#);
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
        let payload = raw_bytes(env.params);
        // Both `$/progress` and `$/transferReady` are correlated by `params.id` (the target call),
        // not a topic — route them to that call, not the general notification stream.
        if method == "$/progress" {
            Ok(Inbound::Progress { key: notification_target(&payload)?, payload })
        } else if method == "$/transferReady" {
            Ok(Inbound::TransferReady { key: notification_target(&payload)?, payload })
        } else {
            Ok(Inbound::Notification { topic: method, payload })
        }
    } else {
        Err(ClientError::Decode("inbound message has neither id nor method".to_string()))
    }
}

/// The target call id (`params.id`) of a per-call server message (`$/progress` / `$/transferReady`)
/// — the correlation key it routes to. The full `payload` (including `id`) is delivered as-is; a
/// consumer's progress type just ignores the extra field.
fn notification_target(payload: &[u8]) -> Result<Uuid, ClientError> {
    #[derive(serde::Deserialize)]
    struct Target {
        id: String,
    }
    let t: Target = serde_json::from_slice(payload)
        .map_err(|e| ClientError::Decode(format!("$/progress params: {e}")))?;
    Uuid::parse_str(&t.id).map_err(|e| ClientError::Decode(format!("bad $/progress id {:?}: {e}", t.id)))
}

/// A decoded `$/progress` update (the JSON-RPC progress shape). Decode a payload from
/// [`Client::call_with_progress`](crate::Client::call_with_progress) with `serde_json::from_slice`;
/// the update's target-`id` field is ignored (the engine already routed by it).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Progress {
    /// Completion percentage, if the handler reported one.
    #[serde(default)]
    pub percent: Option<f64>,
    /// A human-readable status line, if any.
    #[serde(default)]
    pub description: Option<String>,
    /// Any handler-specific extra payload.
    #[serde(default)]
    pub extra: Option<serde_json::Value>,
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
    fn encode_negotiate(&self, protocol: &str, key: &Uuid) -> Vec<u8> {
        let protocol = serde_json::to_string(protocol).unwrap_or_else(|_| "\"\"".to_string());
        let params = format!(r#"{{"protocol":{protocol}}}"#).into_bytes();
        encode_json_request("$/negotiate", key, &params)
    }
}

impl Authenticates for JsonRpcRuntime {
    fn encode_setup(&self, params: Option<&RawValue>, key: &Uuid) -> Vec<u8> {
        encode_json_request("$/sessionSetup", key, raw_param(params))
    }
    fn encode_setup_continue(&self, params: Option<&RawValue>, key: &Uuid) -> Vec<u8> {
        encode_json_request("$/sessionSetupContinue", key, raw_param(params))
    }
}

impl GracefulClose for JsonRpcRuntime {
    fn encode_close(&self, key: &Uuid) -> Vec<u8> {
        encode_json_request("$/sessionClose", key, &[])
    }
}

impl Transfers for JsonRpcRuntime {
    fn parse_transfer_ready(
        &self,
        payload: &[u8],
    ) -> Result<(TransferDirection, Vec<u8>), ClientError> {
        #[derive(serde::Deserialize)]
        struct Ready {
            direction: String,
            #[serde(default)]
            result: Option<Box<RawValue>>,
        }
        let r: Ready = serde_json::from_slice(payload)
            .map_err(|e| ClientError::Decode(format!("$/transferReady: {e}")))?;
        // `TransferDirection` is Serialize-only in the core, so match the wire string here rather
        // than pull a Deserialize impl into the dispatch crate.
        let direction = match r.direction.as_str() {
            "download" => TransferDirection::Download,
            "upload" => TransferDirection::Upload,
            other => {
                return Err(ClientError::Decode(format!("unknown transfer direction {other:?}")))
            }
        };
        let result = r.result.map(|v| v.get().as_bytes().to_vec()).unwrap_or_else(|| b"null".to_vec());
        Ok((direction, result))
    }

    fn encode_transfer_go(&self, key: &Uuid) -> Vec<u8> {
        encode_json_notification("$/transferGo", format!(r#"{{"id":"{key}"}}"#).as_bytes())
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
        // Encode straight from the borrowed seam key — no owning `JsonRpcMethod::Name(String)` clone
        // of the (always-`&'static`) method name. `params` are already the wire bytes (JSON for a
        // name, XDR for a proc-id), spliced through with no re-encode.
        self.round_trip(|key| match method {
            MethodKey::Name(n) => encode_json_request(n, key, params),
            MethodKey::Proc(p) => encode_xdr_request(p, key, params),
        })
        .await
        .map_err(ClientError::into_jsonrpc)
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
