//! Spec validation — ports the cross-cutting rules from `gen.py::validate` /
//! `API_SPEC_SCHEMA` (the structural `additionalProperties:false` / required-field rules are
//! enforced by serde `deny_unknown_fields` at parse time; type-mappability is checked at
//! generation by [`crate::typemap`]).

use std::collections::HashMap;

use crate::error::{CodegenError, Result};
use crate::model::{Direction, Spec};
use crate::naming::is_ident;
use crate::typemap::ref_name;

/// Validate the cross-cutting method rules. `origin` is the source spec (for messages).
pub fn validate(spec: &Spec, origin: &str) -> Result<()> {
    let err = |m: String| CodegenError::at(origin, m);
    let mut seen_xdr_ids: HashMap<i64, String> = HashMap::new();

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
                return Err(err(format!("method {wire:?}: filterable requires an 'entry' type")));
            }
            if m.result.is_some() {
                return Err(err(format!(
                    "method {wire:?}: filterable must not have 'result' (the result is array-of-entry)"
                )));
            }
        }

        // xdr ⇒ xdr_id required, > 1000, unique.
        if m.xdr {
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
            if m.filterable || m.entry.is_some() || m.xdr || m.direction() == Direction::ServerClient {
                return Err(err(format!(
                    "method {wire:?}: python cannot combine with filterable/entry/xdr/server_client"
                )));
            }
        }
    }
    Ok(())
}
