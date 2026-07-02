//! Client emit — a typed async client, one `async fn` per RPC, over a
//! [`truenas_rpc_client::CallEngine`] the consumer supplies (e.g. a `JsonRpcClient`). Filterable
//! methods return `truenas_rpc_client::QueryResult<Entry>`; subscriptions emit `subscribe_*` + a
//! `TOPICS` table. The emitted code depends on `truenas-rpc-client` + `truenas-rpc` + serde/serde_json
//! (NOT on this codegen crate).

use crate::error::{CodegenError, Result};
use crate::model::{Direction, SchemaNode, Spec};
use crate::naming::pascal_case;
use crate::typemap::{ref_name, str_lit};

/// Generate the client module (a typed client generic over a `CallEngine`).
pub fn generate(spec: &Spec, origin: &str) -> Result<String> {
    let client = format!("{}Client", pascal_case(&spec.name));
    let mut methods = String::new();
    let mut topics: Vec<(String, String)> = Vec::new();

    for (wire, m) in spec.methods.iter() {
        let params = ref_name_of(&m.params, "params")?;
        let key = format!("truenas_rpc_client::MethodKey::Name({})", str_lit(wire));
        if m.transfer.is_some() {
            // A raw-fd transfer: send the request, do the `$/transferReady` handshake, hand the
            // blocking fd to `callback` for the self-delimiting bulk stream, then return the server's
            // final result. The interim (`$/transferReady` payload) is available on the handle.
            let result = ref_name_of(m.result.as_ref().ok_or_else(|| miss("result"))?, "result")?;
            methods.push_str(&format!(
                "    /// Raw-fd transfer `{wire}`: `callback` receives a blocking `TransferHandle` for the bulk stream; returns the server's final result.\n    pub async fn {}(&self, request: {params}, callback: impl FnOnce(truenas_rpc_client::TransferHandle) -> std::io::Result<()> + Send + 'static) -> Result<{result}, truenas_rpc::JsonRpcError> {{\n        let params = serde_json::to_vec(&request).map_err(|e| truenas_rpc::JsonRpcError::invalid_params(e.to_string()))?;\n        let bytes = self.engine.transfer({key}, &params, Box::new(callback)).await?;\n        serde_json::from_slice(&bytes).map_err(|e| truenas_rpc::JsonRpcError::internal(e.to_string()))\n    }}\n",
                m.handler
            ));
        } else if m.direction() == Direction::ServerClient {
            let notifies =
                ref_name_of(m.notifies.as_ref().ok_or_else(|| miss("notifies"))?, "notifies")?;
            topics.push((wire.to_string(), notifies));
            methods.push_str(&format!(
                "    /// Subscribe to `{wire}`; returns the subscription id (notifications arrive on the engine's stream).\n    pub async fn subscribe_{}(&self, request: {params}) -> Result<truenas_rpc_client::SubId, truenas_rpc::JsonRpcError> {{\n        let params = serde_json::to_vec(&request).map_err(|e| truenas_rpc::JsonRpcError::invalid_params(e.to_string()))?;\n        let bytes = self.engine.call({key}, &params).await?;\n        serde_json::from_slice(&bytes).map_err(|e| truenas_rpc::JsonRpcError::internal(e.to_string()))\n    }}\n",
                m.handler
            ));
        } else if m.filterable {
            let entry = ref_name_of(
                m.entry.as_ref().expect("filterable entry present (guaranteed by validate)"),
                "entry",
            )?;
            methods.push_str(&format!(
                "    /// Filterable query `{wire}`.\n    pub async fn {}(&self, request: {params}, query_filters: Option<truenas_rpc::QueryFilters>, query_options: Option<truenas_rpc::QueryOptions>) -> Result<truenas_rpc_client::QueryResult<{entry}>, truenas_rpc::JsonRpcError> {{\n        let mut value = serde_json::to_value(&request).map_err(|e| truenas_rpc::JsonRpcError::invalid_params(e.to_string()))?;\n        let obj = value.as_object_mut().ok_or_else(|| truenas_rpc::JsonRpcError::invalid_params(\"query params must be an object\"))?;\n        if let Some(f) = query_filters {{ obj.insert(\"query-filters\".to_string(), serde_json::to_value(f).map_err(|e| truenas_rpc::JsonRpcError::invalid_params(e.to_string()))?); }}\n        if let Some(o) = query_options {{ obj.insert(\"query-options\".to_string(), serde_json::to_value(o).map_err(|e| truenas_rpc::JsonRpcError::invalid_params(e.to_string()))?); }}\n        let params = serde_json::to_vec(&value).map_err(|e| truenas_rpc::JsonRpcError::invalid_params(e.to_string()))?;\n        let bytes = self.engine.call({key}, &params).await?;\n        serde_json::from_slice(&bytes).map_err(|e| truenas_rpc::JsonRpcError::internal(e.to_string()))\n    }}\n",
                m.handler
            ));
        } else {
            // plain or python (from the client's view both are a typed request → result). A method
            // declared `xdr` in the IDL is called over the TXDR binary sub-wire (by proc-id) on the
            // same connection — the server already serves both wires; here the client picks the
            // binary path transparently, encoding params + decoding the result via XDR.
            let result = ref_name_of(m.result.as_ref().ok_or_else(|| miss("result"))?, "result")?;
            let (doc, body) = match (m.xdr, m.xdr_id) {
                (true, Some(id)) => (
                    format!("Call `{wire}` over the binary XDR wire (proc-id {id})."),
                    format!(
                        "        let params = truenas_rpc_client::to_xdr(&request).map_err(|e| truenas_rpc::JsonRpcError::invalid_params(e.to_string()))?;\n        let bytes = self.engine.call(truenas_rpc_client::MethodKey::Proc({id}u32), &params).await?;\n        truenas_rpc_client::from_xdr(&bytes).map_err(|e| truenas_rpc::JsonRpcError::internal(e.to_string()))\n",
                    ),
                ),
                _ => (
                    format!("Call `{wire}`."),
                    format!(
                        "        let params = serde_json::to_vec(&request).map_err(|e| truenas_rpc::JsonRpcError::invalid_params(e.to_string()))?;\n        let bytes = self.engine.call({key}, &params).await?;\n        serde_json::from_slice(&bytes).map_err(|e| truenas_rpc::JsonRpcError::internal(e.to_string()))\n",
                    ),
                ),
            };
            methods.push_str(&format!(
                "    /// {doc}\n    pub async fn {}(&self, request: {params}) -> Result<{result}, truenas_rpc::JsonRpcError> {{\n{body}    }}\n",
                m.handler
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
        "{}\npub struct {client}<E> {{\n    engine: E,\n}}\n\nimpl<E: truenas_rpc_client::CallEngine> {client}<E> {{\n    /// Wrap a [`CallEngine`](truenas_rpc_client::CallEngine) — e.g. a connected\n    /// `truenas_rpc_client::JsonRpcClient` (after `$/negotiate`).\n    pub fn new(engine: E) -> Self {{\n        Self {{ engine }}\n    }}\n\n{methods}}}\n{topics_const}",
        header(origin),
    ))
}

fn header(origin: &str) -> String {
    format!("// GENERATED by truenas-rpc-codegen from {origin} — DO NOT EDIT BY HAND.\n//\n// A typed async client over a `truenas_rpc_client::CallEngine` (e.g. a `JsonRpcClient`).\n")
}

fn ref_name_of(node: &SchemaNode, slot: &str) -> Result<String> {
    match &node.reference {
        Some(r) => ref_name(r),
        None => Err(CodegenError::new(format!("{slot} must be a $ref to a $def"))),
    }
}

fn miss(slot: &str) -> CodegenError {
    CodegenError::new(format!("missing '{slot}'"))
}
