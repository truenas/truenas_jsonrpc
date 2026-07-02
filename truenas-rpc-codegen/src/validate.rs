//! Spec validation — the cross-cutting rules (the structural `additionalProperties:false` /
//! required-field rules are enforced by serde `deny_unknown_fields` at parse time;
//! type-mappability is checked at generation by [`crate::typemap`]).

use std::collections::HashMap;

use crate::error::{CodegenError, Result};
use crate::model::{Direction, Spec};
use crate::naming::is_ident;
use crate::typemap::ref_name;

/// Validate the cross-cutting method rules. `origin` is the source spec (for messages).
pub fn validate(spec: &Spec, origin: &str) -> Result<()> {
    let err = |m: String| CodegenError::at(origin, m);
    let mut seen_xdr_ids: HashMap<i64, String> = HashMap::new();
    let mut any_xdr = false;

    for (wire, m) in spec.methods.iter() {
        if !is_ident(&m.handler) {
            return Err(err(format!(
                "method {wire:?} handler {:?} is not a valid identifier",
                m.handler
            )));
        }

        // Every $ref in a method slot must resolve to a known $def.
        let slots = [
            ("params", Some(&m.params)),
            ("result", m.result.as_ref()),
            ("entry", m.entry.as_ref()),
            ("notifies", m.notifies.as_ref()),
            (
                "transfer.ready",
                m.transfer.as_ref().and_then(|t| t.ready.as_ref()),
            ),
        ];
        for (slot, node) in slots {
            if let Some(node) = node {
                if let Some(reference) = &node.reference {
                    let name = ref_name(reference)
                        .map_err(|e| err(format!("method {wire:?} {slot}: {}", e.message())))?;
                    if !spec.defs.contains_key(&name) {
                        return Err(err(format!(
                            "method {wire:?} {slot} $ref to unknown $defs type: {name:?}"
                        )));
                    }
                }
            }
        }

        // filterable ⇒ entry required & result forbidden.
        if m.filterable {
            if m.entry.is_none() {
                return Err(err(format!(
                    "method {wire:?}: filterable requires an 'entry' type"
                )));
            }
            if m.result.is_some() {
                return Err(err(format!(
                    "method {wire:?}: filterable must not have 'result' (the result is array-of-entry)"
                )));
            }
        }

        // xdr ⇒ xdr_id required, > 1000, unique. `xdr` is the **TXDR binary sub-wire of JSON-RPC**,
        // not exclusive to ONC RPC — a method may be `xdr` under `["json-rpc"]` alone. Do NOT couple
        // `xdr` to the `onc-rpc` protocol; ONC RPC merely adds a second framing over these proc-ids.
        if m.xdr {
            any_xdr = true;
            match m.xdr_id {
                None => return Err(err(format!("method {wire:?}: xdr requires 'xdr_id'"))),
                Some(id) => {
                    if id <= 1000 {
                        return Err(err(format!(
                            "method {wire:?} xdr_id {id} is reserved (0..=1000 are for control messages); use an id > 1000"
                        )));
                    }
                    if let Some(prev) = seen_xdr_ids.insert(id, wire.to_string()) {
                        return Err(err(format!(
                            "method {wire:?} xdr_id {id} collides with method {prev:?}"
                        )));
                    }
                }
            }
        }

        // python ⇒ result required & not combinable with filterable/entry/xdr/server_client.
        if m.python {
            if m.result.is_none() {
                return Err(err(format!("method {wire:?}: python requires 'result'")));
            }
            if m.filterable
                || m.entry.is_some()
                || m.xdr
                || m.direction() == Direction::ServerClient
            {
                return Err(err(format!(
                    "method {wire:?}: python cannot combine with filterable/entry/xdr/server_client"
                )));
            }
        }

        // async ⇒ a plain request/result method (registered via `async_method`): result required,
        // not combinable with filterable/python/server_client (each has its own dispatch).
        if m.is_async {
            if m.result.is_none() {
                return Err(err(format!("method {wire:?}: async requires 'result'")));
            }
            if m.filterable || m.python || m.direction() == Direction::ServerClient {
                return Err(err(format!(
                    "method {wire:?}: async cannot combine with filterable/python/server_client"
                )));
            }
        }

        // transfer ⇒ a request/result method with a raw-fd hand-off: result required, and not
        // combinable with any other dispatch kind. Transfers are JSON-wire only (the `Dispatched::
        // Transfer` directive has no binary-wire path), so `xdr` is out; the fd hand-off is not a
        // query/subscription/python body, and it is not `$/cancelRequest`-cancellable.
        if m.transfer.is_some() {
            if m.result.is_none() {
                return Err(err(format!("method {wire:?}: transfer requires 'result'")));
            }
            if m.xdr
                || m.filterable
                || m.python
                || m.is_async
                || m.cancellable
                || m.direction() == Direction::ServerClient
            {
                return Err(err(format!(
                    "method {wire:?}: transfer cannot combine with xdr/filterable/async/python/cancellable/server_client"
                )));
            }
        }

        // A subscription (server→client) cannot ride the binary wire — the binary framing carries no
        // server-push path (so it is never reachable over ONC RPC or the TXDR sub-wire).
        if m.xdr && m.direction() == Direction::ServerClient {
            return Err(err(format!(
                "method {wire:?}: a server_client subscription cannot be xdr (the binary wire has no server-push)"
            )));
        }
    }

    // The declared wire protocols: non-empty, each supported, no duplicates.
    if spec.protocols.is_empty() {
        return Err(err(
            "protocols must list at least one wire protocol".to_string()
        ));
    }
    let mut seen_protocols: HashMap<&str, ()> = HashMap::new();
    let mut has_onc = false;
    for p in &spec.protocols {
        match classify(p) {
            ProtocolKind::JsonRpc => {}
            ProtocolKind::OncRpc => has_onc = true,
            ProtocolKind::Unsupported => {
                return Err(err(format!(
                    "unsupported protocol {p:?} (supported: json-rpc, onc-rpc)"
                )))
            }
        }
        if seen_protocols.insert(p.as_str(), ()).is_some() {
            return Err(err(format!("protocol {p:?} listed twice")));
        }
    }
    // ONC RPC needs at least one binary-reachable method, else the engine serves only the NULL probe.
    if has_onc && !any_xdr {
        return Err(err(
            "onc-rpc is declared but no method is xdr-reachable (set xdr + xdr_id on a method); \
             ONC RPC would expose only the NULL probe"
                .to_string(),
        ));
    }

    // Top-level audit config: a given service must be non-empty; a given queue bound must be > 0.
    if let Some(a) = &spec.audit {
        if a.service.as_deref() == Some("") {
            return Err(err("audit.service must be a non-empty string".to_string()));
        }
        if a.queue_bound == Some(0) {
            return Err(err("audit.queueBound must be greater than 0".to_string()));
        }
    }
    Ok(())
}

/// The wire protocols the codegen knows how to emit for. An IDL may *declare* any protocol string,
/// but only these are supported — everything else is [`ProtocolKind::Unsupported`] (a validation
/// error). Only `json-rpc` and `onc-rpc` are named here, so a future protocol never needs naming in
/// committed code.
enum ProtocolKind {
    JsonRpc,
    OncRpc,
    Unsupported,
}

fn classify(name: &str) -> ProtocolKind {
    match name {
        "json-rpc" => ProtocolKind::JsonRpc,
        "onc-rpc" => ProtocolKind::OncRpc,
        _ => ProtocolKind::Unsupported,
    }
}
