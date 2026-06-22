//! The json-idl dialect, as serde types. `Spec` and `MethodSpec` use
//! `deny_unknown_fields` (a typo'd key fails fast, the meta-schema's
//! `additionalProperties:false`); schema nodes are open (they tolerate annotation keys like
//! `$comment`/`title`/`description`, which serde ignores by default).

use std::fmt;
use std::marker::PhantomData;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// A JSON object that preserves its key order (without an `indexmap` dependency): the
/// hand-written `Deserialize` collects `MapAccess` entries, which serde_json yields in
/// document order. Struct `properties` order is XDR-wire-significant, hence this.
#[derive(Debug, Default, Clone)]
pub struct OrderedMap<V>(pub Vec<(String, V)>);

impl<V> OrderedMap<V> {
    /// The value for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&V> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    /// Whether `key` is present.
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }
    /// Iterate entries in document order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for OrderedMap<V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedVisitor<V>(PhantomData<V>);
        impl<'de, V: Deserialize<'de>> Visitor<'de> for OrderedVisitor<V> {
            type Value = OrderedMap<V>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, V>()? {
                    out.push((k, v));
                }
                Ok(OrderedMap(out))
            }
        }
        deserializer.deserialize_map(OrderedVisitor(PhantomData))
    }
}

/// A whole json-idl spec file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// `$schema` (ignored — declared only so `deny_unknown_fields` accepts the key).
    #[serde(rename = "$schema", default)]
    #[allow(dead_code)]
    pub schema: Option<String>,
    /// `$comment` (ignored — declared only so `deny_unknown_fields` accepts the key).
    #[serde(rename = "$comment", default)]
    #[allow(dead_code)]
    pub comment: Option<String>,
    /// The service name (OpenRPC `info.title`).
    pub name: String,
    /// The service version (OpenRPC `info.version`).
    pub version: String,
    /// Named request/result/entry types.
    #[serde(rename = "$defs", default)]
    pub defs: OrderedMap<SchemaNode>,
    /// Wire-name → method.
    pub methods: OrderedMap<MethodSpec>,
}

/// A single method definition.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodSpec {
    /// The hand-written handler symbol this method binds to.
    pub handler: String,
    /// Human summary (OpenRPC `summary`; `MethodDef::doc`).
    #[serde(default)]
    pub summary: Option<String>,
    /// The params type (normally a `$ref` into `$defs`).
    pub params: SchemaNode,
    /// The result type (a `$ref`); absent for filterable/server_client.
    #[serde(default)]
    pub result: Option<SchemaNode>,
    /// The published-notification payload type (server_client topics).
    #[serde(default)]
    pub notifies: Option<SchemaNode>,
    /// The streamed element type of a filterable method.
    #[serde(default)]
    pub entry: Option<SchemaNode>,
    /// Audit every call.
    #[serde(default)]
    pub audit: bool,
    /// A static audit description (implies `audit`).
    #[serde(rename = "auditMessage", default)]
    pub audit_message: Option<String>,
    /// Allow before the session is established.
    #[serde(rename = "preAuth", default)]
    pub pre_auth: bool,
    /// Opt into `$/cancelRequest`.
    #[serde(default)]
    pub cancellable: bool,
    /// Declared role names (metadata only).
    #[serde(default)]
    pub roles: Vec<String>,
    /// `client_server` (default) or `server_client` (a subscribable topic).
    #[serde(default)]
    pub direction: Option<Direction>,
    /// A filterable (query) method.
    #[serde(default)]
    pub filterable: bool,
    /// Also reachable over the XDR binary wire.
    #[serde(default)]
    pub xdr: bool,
    /// The XDR proc-id (required when `xdr`; must be > 1000).
    #[serde(default)]
    pub xdr_id: Option<i64>,
    /// A python-backed method (body runs via the PyO3 bridge).
    #[serde(default)]
    pub python: bool,
}

impl MethodSpec {
    /// The effective direction (absent → `client_server`).
    pub fn direction(&self) -> Direction {
        self.direction.unwrap_or(Direction::ClientServer)
    }
}

/// A method's payload direction.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// A normal request method.
    ClientServer,
    /// A subscribable notification topic.
    ServerClient,
}

/// A JSON-Schema node (a `$def` value, or a method's params/result/entry/notifies type).
/// Only the keys the dialect uses are captured; others (e.g. `$comment`) are ignored.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SchemaNode {
    /// A `$ref` to a `$def` (`#/$defs/<Name>`).
    #[serde(rename = "$ref", default)]
    pub reference: Option<String>,
    /// The JSON-Schema `type`.
    #[serde(rename = "type", default)]
    pub ty: Option<String>,
    /// Object properties (order preserved).
    #[serde(default)]
    pub properties: OrderedMap<SchemaNode>,
    /// Required property names.
    #[serde(default)]
    pub required: Vec<String>,
    /// Array element type.
    #[serde(default)]
    pub items: Option<Box<SchemaNode>>,
    /// String-enum variants.
    #[serde(rename = "enum", default)]
    pub enum_values: Option<Vec<Value>>,
    /// Marks a field as secret (audit-redacted; wrapped in `Secret<T>`).
    #[serde(default)]
    pub secret: bool,
    /// A default value for the field.
    #[serde(rename = "default", default)]
    pub default: Option<Value>,
}
