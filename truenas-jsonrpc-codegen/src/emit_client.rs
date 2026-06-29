//! Client emit — a transport-agnostic `Transport` trait plus a
//! typed client with one `async fn` per request method (filterable → `QueryResult<Entry>`,
//! subscriptions → `subscribe_*` + a `TOPICS` table). The emitted code depends on
//! `truenas-jsonrpc` + serde/serde_json + `async-trait` (NOT on this codegen crate).

use crate::error::{CodegenError, Result};
use crate::model::{Direction, SchemaNode, Spec};
use crate::naming::pascal_case;
use crate::typemap::{ref_name, str_lit};

/// Generate the client module (the `Transport` trait, `QueryResult`, and the typed client).
pub fn generate(spec: &Spec, origin: &str) -> Result<String> {
    let client = format!("{}Client", pascal_case(&spec.name));
    let mut methods = String::new();
    let mut topics: Vec<(String, String)> = Vec::new();

    for (wire, m) in spec.methods.iter() {
        let params = ref_name_of(&m.params, "params")?;
        if m.direction() == Direction::ServerClient {
            let notifies = ref_name_of(m.notifies.as_ref().ok_or_else(|| miss("notifies"))?, "notifies")?;
            topics.push((wire.to_string(), notifies));
            methods.push_str(&format!(
                "    /// Subscribe to `{wire}`; returns the subscription id.\n    pub async fn subscribe_{}(&self, request: {params}) -> Result<String, truenas_jsonrpc::JsonRpcError> {{\n        let raw = self.send({}, &request).await?;\n        serde_json::from_str(raw.get()).map_err(|e| truenas_jsonrpc::JsonRpcError::internal(e.to_string()))\n    }}\n",
                m.handler, str_lit(wire)
            ));
        } else if m.filterable {
            let entry = ref_name_of(
                m.entry.as_ref().expect("filterable entry present (guaranteed by validate)"),
                "entry",
            )?;
            methods.push_str(&format!(
                "    /// Filterable query `{wire}`.\n    pub async fn {}(&self, request: {params}, query_filters: Option<truenas_jsonrpc::QueryFilters>, query_options: Option<truenas_jsonrpc::QueryOptions>) -> Result<QueryResult<{entry}>, truenas_jsonrpc::JsonRpcError> {{\n        let mut value = serde_json::to_value(&request).map_err(|e| truenas_jsonrpc::JsonRpcError::invalid_params(e.to_string()))?;\n        let obj = value.as_object_mut().ok_or_else(|| truenas_jsonrpc::JsonRpcError::invalid_params(\"query params must be an object\"))?;\n        if let Some(f) = query_filters {{ obj.insert(\"query-filters\".to_string(), serde_json::to_value(f).map_err(|e| truenas_jsonrpc::JsonRpcError::invalid_params(e.to_string()))?); }}\n        if let Some(o) = query_options {{ obj.insert(\"query-options\".to_string(), serde_json::to_value(o).map_err(|e| truenas_jsonrpc::JsonRpcError::invalid_params(e.to_string()))?); }}\n        let raw = self.send_value({}, &value).await?;\n        serde_json::from_str(raw.get()).map_err(|e| truenas_jsonrpc::JsonRpcError::internal(e.to_string()))\n    }}\n",
                m.handler, str_lit(wire)
            ));
        } else {
            // plain or python (from the client's view both are a typed request → result)
            let result = ref_name_of(m.result.as_ref().ok_or_else(|| miss("result"))?, "result")?;
            methods.push_str(&format!(
                "    /// Call `{wire}`.\n    pub async fn {}(&self, request: {params}) -> Result<{result}, truenas_jsonrpc::JsonRpcError> {{\n        let raw = self.send({}, &request).await?;\n        serde_json::from_str(raw.get()).map_err(|e| truenas_jsonrpc::JsonRpcError::internal(e.to_string()))\n    }}\n",
                m.handler, str_lit(wire)
            ));
        }
    }

    let topics_const = if topics.is_empty() {
        String::new()
    } else {
        let entries: Vec<String> =
            topics.iter().map(|(w, n)| format!("({}, {})", str_lit(w), str_lit(n))).collect();
        format!(
            "\n/// Subscribable topics: `(wire-name, notification-type-name)`.\npub const TOPICS: &[(&str, &str)] = &[{}];\n",
            entries.join(", ")
        )
    };

    Ok(format!(
        "{}{PREAMBLE}\npub struct {client}<T> {{\n    transport: T,\n}}\n\nimpl<T: Transport> {client}<T> {{\n    /// Wrap a transport.\n    pub fn new(transport: T) -> Self {{\n        Self {{ transport }}\n    }}\n\n    async fn send<P: serde::Serialize>(&self, method: &str, params: &P) -> Result<Box<serde_json::value::RawValue>, truenas_jsonrpc::JsonRpcError> {{\n        let raw = serde_json::value::to_raw_value(params).map_err(|e| truenas_jsonrpc::JsonRpcError::invalid_params(e.to_string()))?;\n        self.transport.call(method, Some(&raw)).await\n    }}\n\n    async fn send_value(&self, method: &str, params: &serde_json::Value) -> Result<Box<serde_json::value::RawValue>, truenas_jsonrpc::JsonRpcError> {{\n        let raw = serde_json::value::to_raw_value(params).map_err(|e| truenas_jsonrpc::JsonRpcError::invalid_params(e.to_string()))?;\n        self.transport.call(method, Some(&raw)).await\n    }}\n\n{methods}}}\n{topics_const}",
        header(origin),
    ))
}

fn header(origin: &str) -> String {
    format!("// GENERATED by truenas-jsonrpc-codegen from {origin} — DO NOT EDIT BY HAND.\n//\n// A typed client over a `Transport` you implement for your connection.\n")
}

const PREAMBLE: &str = r#"
/// The request/response transport the client calls over. Implement it for your connection
/// (WebSocket / Unix socket / TCP); the client is transport- and runtime-agnostic.
#[async_trait::async_trait]
pub trait Transport {
    /// Send a JSON-RPC request for `method` and return the decoded `result` JSON.
    async fn call(
        &self,
        method: &str,
        params: Option<&serde_json::value::RawValue>,
    ) -> Result<Box<serde_json::value::RawValue>, truenas_jsonrpc::JsonRpcError>;
}

/// The result of a filterable query: a row list, a single record (`get`), or a count.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum QueryResult<E> {
    /// The matching rows.
    Rows(Vec<E>),
    /// A single record (`query-options.get`).
    One(E),
    /// A count (`query-options.count`).
    Count(i64),
}
"#;

fn ref_name_of(node: &SchemaNode, slot: &str) -> Result<String> {
    match &node.reference {
        Some(r) => ref_name(r),
        None => Err(CodegenError::new(format!("{slot} must be a $ref to a $def"))),
    }
}

fn miss(slot: &str) -> CodegenError {
    CodegenError::new(format!("missing '{slot}'"))
}
