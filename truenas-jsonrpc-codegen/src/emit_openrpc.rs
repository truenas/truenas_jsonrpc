//! OpenRPC 1.3.2 emit. The A/B compares the parsed `serde_json::Value`s (order-insensitive for
//! object keys), so this builds a semantically-equal document; method/param/required arrays
//! preserve order (they are order-significant).

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use crate::error::{CodegenError, Result};
use crate::model::{Direction, MethodSpec, SchemaNode, Spec};
use crate::typemap::ref_name;

fn schema_ref(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

/// Generate the OpenRPC document (pretty JSON + trailing newline).
pub fn generate(spec: &Spec, origin: &str) -> Result<String> {
    let mut public: Vec<(&str, &MethodSpec)> = spec
        .methods
        .iter()
        .filter(|(w, _)| !(w.starts_with("$/") || w.starts_with("rpc.")))
        .collect();
    public.sort_by(|a, b| a.0.cmp(b.0));

    let mut methods = Vec::new();
    for (wire, m) in &public {
        methods.push(method_object(spec, wire, m)?);
    }

    let mut schemas = Map::new();
    for name in collect_component_names(&public, spec)? {
        let def = spec
            .defs
            .get(&name)
            .ok_or_else(|| CodegenError::new(format!("$ref to unknown $defs type: {name:?}")))?;
        schemas.insert(name.clone(), component_body(Some(&name), def, spec)?);
    }

    let doc = json!({
        "x-generated": format!("Generated from {origin} by truenas-jsonrpc-codegen — do not edit by hand."),
        "openrpc": "1.3.2",
        "info": { "title": spec.name, "version": spec.version },
        "methods": methods,
        "components": { "schemas": Value::Object(schemas), "errors": error_components() },
    });
    Ok(serde_json::to_string_pretty(&doc).expect("an OpenRPC Value always serializes") + "\n")
}

fn method_object(spec: &Spec, wire: &str, m: &MethodSpec) -> Result<Value> {
    let params_name = ref_name_req(&m.params, "params")?;
    let params_def = spec
        .defs
        .get(&params_name)
        .ok_or_else(|| CodegenError::new(format!("params $ref to unknown $defs type: {params_name:?}")))?;
    let required: HashSet<&str> = params_def.required.iter().map(String::as_str).collect();

    // Base params (required-first, stable), then (for filterable) the two query descriptors.
    let mut base: Vec<(bool, Value)> = Vec::new();
    for (p, ps) in params_def.properties.iter() {
        let req = required.contains(p);
        base.push((req, json!({ "name": p, "required": req, "schema": property_schema(ps, req, spec)? })));
    }
    base.sort_by_key(|(req, _)| !req);
    let mut params: Vec<Value> = base.into_iter().map(|(_, v)| v).collect();
    if m.filterable {
        params.extend(query_param_descriptors());
    }

    let mut obj = Map::new();
    obj.insert("name".into(), json!(wire));
    if let Some(s) = &m.summary {
        obj.insert("summary".into(), json!(s));
    }
    obj.insert("paramStructure".into(), json!("by-name"));
    obj.insert("params".into(), Value::Array(params));

    let direction = m.direction();
    if m.filterable {
        let entry = ref_name_req(
            m.entry.as_ref().expect("filterable entry present (guaranteed by validate)"),
            "entry",
        )?;
        obj.insert(
            "result".into(),
            json!({ "name": entry, "schema": { "type": "array", "items": schema_ref(&entry) } }),
        );
        obj.insert("x-query".into(), json!(true));
    } else if direction != Direction::ServerClient {
        if let Some(result) = &m.result {
            let r = ref_name_req(result, "result")?;
            obj.insert("result".into(), json!({ "name": r, "schema": schema_ref(&r) }));
        }
    }
    obj.insert("x-direction".into(), json!(direction_str(direction)));
    if direction == Direction::ServerClient {
        if let Some(notifies) = &m.notifies {
            let n = ref_name_req(notifies, "notifies")?;
            obj.insert("x-notifies".into(), schema_ref(&n));
        }
    }
    if !m.roles.is_empty() {
        obj.insert("x-roles".into(), json!(m.roles));
    }
    Ok(Value::Object(obj))
}

/// A property/param schema: `default` inlined; an optional (not required, no default) →
/// `{anyOf:[base,null], default:null}`; else the bare base. Secret is dropped.
fn property_schema(node: &SchemaNode, required: bool, spec: &Spec) -> Result<Value> {
    let base = base_schema(node, spec)?;
    if let Some(default) = &node.default {
        let mut obj = base.as_object().cloned().unwrap_or_default();
        obj.insert("default".into(), default.clone());
        Ok(Value::Object(obj))
    } else if !required {
        Ok(json!({ "anyOf": [base, { "type": "null" }], "default": null }))
    } else {
        Ok(base)
    }
}

fn base_schema(node: &SchemaNode, spec: &Spec) -> Result<Value> {
    if let Some(r) = &node.reference {
        return Ok(schema_ref(&ref_name(r)?));
    }
    if let Some(values) = &node.enum_values {
        return Ok(json!({ "type": "string", "enum": values }));
    }
    match node.ty.as_deref() {
        Some("array") => {
            let items = node
                .items
                .as_deref()
                .ok_or_else(|| CodegenError::new("array schema must have an object 'items'"))?;
            Ok(json!({ "type": "array", "items": base_schema(items, spec)? }))
        }
        Some("object") => component_body(None, node, spec),
        Some(t @ ("string" | "integer" | "number" | "boolean")) => Ok(json!({ "type": t })),
        other => Err(CodegenError::new(format!("cannot map schema to OpenRPC: type={other:?}"))),
    }
}

fn component_body(name: Option<&str>, schema: &SchemaNode, spec: &Spec) -> Result<Value> {
    let required: HashSet<&str> = schema.required.iter().map(String::as_str).collect();
    let mut props = Map::new();
    for (p, ps) in schema.properties.iter() {
        props.insert(p.to_string(), property_schema(ps, required.contains(p), spec)?);
    }
    let mut body = Map::new();
    if let Some(n) = name {
        body.insert("title".into(), json!(n));
    }
    body.insert("type".into(), json!("object"));
    body.insert("properties".into(), Value::Object(props));
    body.insert("required".into(), json!(schema.required));
    Ok(Value::Object(body))
}

/// Ordered, de-duplicated names of every `$def` reachable from the public methods' slots.
fn collect_component_names(public: &[(&str, &MethodSpec)], spec: &Spec) -> Result<Vec<String>> {
    let mut seen: Vec<String> = Vec::new();
    for (_, m) in public {
        for node in [Some(&m.params), m.result.as_ref(), m.notifies.as_ref(), m.entry.as_ref()]
            .into_iter()
            .flatten()
        {
            visit_refs(node, spec, &mut seen)?;
        }
    }
    Ok(seen)
}

fn visit_refs(node: &SchemaNode, spec: &Spec, seen: &mut Vec<String>) -> Result<()> {
    if let Some(r) = &node.reference {
        let name = ref_name(r)?;
        if !seen.contains(&name) {
            seen.push(name.clone());
            for (_, ps) in spec.defs.get(&name).into_iter().flat_map(|d| d.properties.iter()) {
                visit_refs(ps, spec, seen)?;
            }
        }
    } else if node.ty.as_deref() == Some("array") {
        for items in node.items.iter() {
            visit_refs(items, spec, seen)?;
        }
    }
    Ok(())
}

fn query_param_descriptors() -> Vec<Value> {
    vec![
        json!({ "name": "query-filters", "required": false,
                "schema": { "type": "array", "items": { "type": "array" }, "default": [] } }),
        json!({ "name": "query-options", "required": false, "schema": { "type": "object", "properties": {
            "count": { "type": "boolean", "default": false },
            "order_by": { "anyOf": [{ "type": "array", "items": { "type": "string" } }, { "type": "null" }], "default": null },
            "offset": { "type": "integer", "default": 0 },
            "limit": { "type": "integer", "default": 0 }
        } } }),
    ]
}

fn error_components() -> Value {
    // The protocol-wide error taxonomy (Title-cased). Fixed
    // constants, so the messages are spelled out rather than computed.
    const CODES: &[(&str, i32, &str)] = &[
        ("INVALID_JSON", -32700, "Invalid Json"),
        ("INVALID_REQUEST", -32600, "Invalid Request"),
        ("METHOD_NOT_FOUND", -32601, "Method Not Found"),
        ("INVALID_PARAMS", -32602, "Invalid Params"),
        ("INTERNAL_ERROR", -32603, "Internal Error"),
        ("NOT_AUTHORIZED", -32000, "Not Authorized"),
        ("SESSION_NOT_ESTABLISHED", -32002, "Session Not Established"),
        ("REQUEST_CANCELLED", -32800, "Request Cancelled"),
        ("REQUEST_FAILED", -32803, "Request Failed"),
    ];
    let mut m = Map::new();
    for (name, code, message) in CODES {
        m.insert(name.to_string(), json!({ "code": code, "message": message }));
    }
    Value::Object(m)
}

fn direction_str(d: Direction) -> &'static str {
    match d {
        Direction::ClientServer => "client_server",
        Direction::ServerClient => "server_client",
    }
}

fn ref_name_req(node: &SchemaNode, slot: &str) -> Result<String> {
    match &node.reference {
        Some(r) => ref_name(r),
        None => Err(CodegenError::new(format!("{slot} must be a $ref to a $def"))),
    }
}
