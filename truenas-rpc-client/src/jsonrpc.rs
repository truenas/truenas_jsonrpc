//! The **JSON-RPC protocol runtime** — the hand-written hook implementations the engine drives:
//! 4-byte length-prefix framing, the JSON-RPC 2.0 envelope (method-by-name + UUID id), and the
//! `$/negotiate` / `$/sessionSetup` / `$/sessionClose` capabilities.

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
    type MethodKey = String;
    type CorrelationKey = Uuid;
    type Topic = String;
    type Framing = LengthPrefix;

    fn framing(&self) -> &LengthPrefix {
        &self.framing
    }

    fn encode_call(&self, method: &String, params: Option<&RawValue>) -> EncodedCall<Uuid> {
        let id = Uuid::new_v4();
        EncodedCall { wire: build_request(method, &id, params), key: id }
    }

    fn parse_inbound(&self, frame: &[u8]) -> Result<Inbound<Self>, ClientError> {
        parse_envelope(frame)
    }
}

/// Build a JSON-RPC 2.0 request `{"jsonrpc":"2.0","method":..,"id":<uuid>,"params":..}` — `params`
/// (already-encoded JSON) is spliced raw, no re-parse. The id is the canonical hyphenated UUID.
fn build_request(method: &str, id: &Uuid, params: Option<&RawValue>) -> Vec<u8> {
    let method = serde_json::to_string(method).unwrap_or_else(|_| "\"\"".to_string());
    match params {
        Some(p) => {
            format!(r#"{{"jsonrpc":"2.0","method":{method},"id":"{id}","params":{}}}"#, p.get())
        }
        None => format!(r#"{{"jsonrpc":"2.0","method":{method},"id":"{id}"}}"#),
    }
    .into_bytes()
}

/// Classify one inbound JSON-RPC frame: a reply (has an `id`) or a notification (a `method`, no `id`).
fn parse_envelope(frame: &[u8]) -> Result<Inbound<JsonRpcRuntime>, ClientError> {
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
    #[derive(serde::Deserialize)]
    struct WireError {
        code: i32,
        message: String,
        #[serde(default)]
        data: Option<serde_json::Value>,
    }

    let env: Env = serde_json::from_slice(frame).map_err(|e| ClientError::Decode(e.to_string()))?;
    if let Some(id) = env.id {
        let key =
            Uuid::parse_str(&id).map_err(|e| ClientError::Decode(format!("bad reply id {id:?}: {e}")))?;
        let result = match env.error {
            Some(e) => Err(JsonRpcError { code: e.code, message: e.message, data: e.data }),
            None => Ok(env.result.unwrap_or_else(null_raw)),
        };
        Ok(Inbound::Reply { key, result })
    } else if let Some(method) = env.method {
        Ok(Inbound::Notification { topic: method, payload: env.params.unwrap_or_else(null_raw) })
    } else {
        Err(ClientError::Decode("inbound message has neither id nor method".to_string()))
    }
}

fn null_raw() -> Box<RawValue> {
    RawValue::from_string("null".to_string()).expect("`null` is valid JSON")
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
        let params = RawValue::from_string(format!(r#"{{"protocol":{protocol}}}"#))
            .expect("valid json");
        self.encode_call(&"$/negotiate".to_string(), Some(&params))
    }
}

impl Authenticates for JsonRpcRuntime {
    fn encode_setup(&self, params: Option<&RawValue>) -> EncodedCall<Uuid> {
        self.encode_call(&"$/sessionSetup".to_string(), params)
    }
    fn encode_setup_continue(&self, params: Option<&RawValue>) -> EncodedCall<Uuid> {
        self.encode_call(&"$/sessionSetupContinue".to_string(), params)
    }
}

impl GracefulClose for JsonRpcRuntime {
    fn encode_close(&self) -> EncodedCall<Uuid> {
        self.encode_call(&"$/sessionClose".to_string(), None)
    }
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
        let name = match method {
            MethodKey::Name(n) => n.to_string(),
            MethodKey::Proc(p) => {
                return Err(JsonRpcError::internal(format!(
                    "the JSON-RPC client addresses methods by name, not proc-id ({p})"
                )))
            }
        };
        let raw = if params.is_empty() {
            None
        } else {
            let s = std::str::from_utf8(params)
                .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
            Some(
                RawValue::from_string(s.to_string())
                    .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?,
            )
        };
        let result =
            Client::call(self, &name, raw.as_deref()).await.map_err(ClientError::into_jsonrpc)?;
        Ok(result.get().as_bytes().to_vec())
    }
}
