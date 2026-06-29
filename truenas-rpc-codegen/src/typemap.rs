//! JSON-Schema node → Rust type. A string-enum becomes a named generated `enum` (Rust has
//! no anonymous enums); those definitions accumulate in [`TypeCtx`].

use serde_json::Value;

use crate::error::{CodegenError, Result};
use crate::model::SchemaNode;
use crate::naming::pascal_case;

/// Accumulates the generated nested-enum definitions discovered while mapping types.
#[derive(Default)]
pub struct TypeCtx {
    defs: Vec<(String, String)>, // (name, definition), deduped by name
}

impl TypeCtx {
    fn add_enum(&mut self, name: &str, def: String) {
        if !self.defs.iter().any(|(n, _)| n == name) {
            self.defs.push((name.to_string(), def));
        }
    }
    /// The accumulated enum definitions, in first-seen order.
    pub fn enum_defs(&self) -> impl Iterator<Item = &str> {
        self.defs.iter().map(|(_, d)| d.as_str())
    }
}

/// Resolve a `#/$defs/<Name>` reference to its `<Name>` (the only supported `$ref` form).
pub fn ref_name(reference: &str) -> Result<String> {
    reference
        .strip_prefix("#/$defs/")
        .filter(|n| crate::naming::is_ident(n))
        .map(str::to_string)
        .ok_or_else(|| CodegenError::new(format!("unsupported $ref (only #/$defs/<Name> is allowed): {reference:?}")))
}

/// The Rust type for a schema node. `name_hint` names a generated enum (`<Struct><Field>`).
pub fn rust_type(node: &SchemaNode, name_hint: &str, ctx: &mut TypeCtx) -> Result<String> {
    let base = if let Some(reference) = &node.reference {
        ref_name(reference)?
    } else if let Some(values) = &node.enum_values {
        let name = name_hint.to_string();
        let def = emit_enum(&name, values)?;
        ctx.add_enum(&name, def);
        name
    } else {
        match node.ty.as_deref() {
            Some("string") => "String".to_string(),
            Some("integer") => "i64".to_string(),
            Some("number") => "f64".to_string(),
            Some("boolean") => "bool".to_string(),
            Some("array") => {
                let items = node
                    .items
                    .as_deref()
                    .ok_or_else(|| CodegenError::new("array schema must have an object 'items'"))?;
                format!("Vec<{}>", rust_type(items, &format!("{name_hint}Item"), ctx)?)
            }
            Some("object") => {
                return Err(CodegenError::new(
                    "inline object types aren't supported; use a $ref to a $def",
                ))
            }
            other => {
                return Err(CodegenError::new(format!(
                    "unsupported schema (need $ref, enum, or a known type), got type={other:?}"
                )))
            }
        }
    };
    Ok(if node.secret { format!("truenas_rpc::Secret<{base}>") } else { base })
}

/// A Rust string literal for `s` (JSON string escaping is valid Rust string escaping for
/// our ASCII/UTF-8 content).
pub fn str_lit(s: &str) -> String {
    serde_json::to_string(s).expect("a string always serializes")
}

fn emit_enum(name: &str, values: &[Value]) -> Result<String> {
    if values.is_empty() {
        return Err(CodegenError::new(format!("enum {name:?} must have at least one value")));
    }
    let mut variants = String::new();
    for v in values {
        let s = v
            .as_str()
            .ok_or_else(|| CodegenError::new(format!("enum {name:?} values must all be strings")))?;
        let ident = pascal_case(s);
        if ident.is_empty() {
            return Err(CodegenError::new(format!(
                "enum {name:?} value {s:?} has no identifier characters"
            )));
        }
        // A plain serde string-enum: JSON encodes the renamed string; the XDR codec encodes
        // the declaration-order variant index (so reordering variants is XDR-wire-breaking).
        variants.push_str(&format!("    #[serde(rename = {})]\n    {ident},\n", str_lit(s)));
    }
    Ok(format!(
        "#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]\npub enum {name} {{\n{variants}}}"
    ))
}
