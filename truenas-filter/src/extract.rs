//! Per-query **needed-field analysis** + a serde field-extracting view builder.
//!
//! [`tnfilter`](crate::tnfilter) evaluates filters/ordering against a `serde_json::Value`
//! *view* of each row. Materializing the whole row (`serde_json::to_value`) is the dominant
//! per-row cost, yet the pipeline only ever reads the handful of fields named by the
//! `query-filters` and `order_by`. [`compute_needed`] works that set out once per query, and
//! [`build_view`] then builds only what's required:
//!
//! - [`Needed::Nothing`] (no filters, no `order_by`) — the view is never traversed, so it is
//!   a free `Value::Null`. This is the `count`-all / unfiltered-page hot path, where the old
//!   code paid a full `to_value` per row for a value nothing ever looked at.
//! - [`Needed::Keys`] (every referenced path is a single flat top-level field) — a
//!   [`FieldExtractor`] serializes the row but keeps *only* those fields; a struct's other
//!   fields are never serialized at all (serde hands each field to `serialize_field`, which
//!   simply doesn't recurse into the un-needed ones). Non-struct rows — most importantly a
//!   dynamic `serde_json::Value` object, which serde routes through `serialize_map` — fall
//!   back to a full `to_value`, producing byte-identical bytes, just unoptimized.
//! - [`Needed::Full`] (a nested / indexed / `*`-wildcard path is involved) — the whole row is
//!   materialized, exactly as before.
//!
//! This is a pure throughput optimization: the resulting view feeds the *same*
//! comparison/order engine, so results are byte-for-byte unchanged (the conformance corpus
//! still gates them). It does **not** reach a typed field accessor's zero-allocation numbers
//! — a struct match still builds a small one-or-few-field `Value` — but it removes the bulk
//! of the per-row cost: the full object map plus a `Value` for every unreferenced field.

use std::fmt;

use serde::ser::{Error as SerError, Impossible, Serialize, SerializeStruct, Serializer};
use serde_json::{Map, Value};

use crate::path::PathPart;
use crate::{CompiledFilters, CompiledOptions, FilterError};

/// Which fields the filter/order pipeline will actually read from each row's view — computed
/// once per query by [`compute_needed`] so per-row view construction can skip everything else.
#[derive(Debug)]
pub(crate) enum Needed {
    /// No field is read (no filters and no `order_by`) — the view is never traversed.
    Nothing,
    /// Only these flat top-level keys are read; build a pruned view containing just them.
    Keys(Vec<Box<str>>),
    /// A nested / indexed / `*`-wildcard path is involved — the full `Value` view is required.
    Full,
}

/// Work out the [`Needed`] field set for a compiled query.
///
/// Walks every leaf filter path and every `order_by` key. If they are *all* single flat
/// top-level keys, the view can be the pruned [`Needed::Keys`]; if any is nested / indexed /
/// wildcard / escaped, the whole row is needed ([`Needed::Full`]); if there are none at all,
/// no view is needed ([`Needed::Nothing`]).
pub(crate) fn compute_needed(filters: &CompiledFilters, options: &CompiledOptions) -> Needed {
    let mut keys: Vec<Box<str>> = Vec::new();
    let mut full = false;
    {
        let mut add = |parts: &[PathPart]| {
            if full {
                return;
            }
            match simple_key(parts) {
                Some(k) => {
                    if !keys.iter().any(|e| &**e == k) {
                        keys.push(Box::from(k));
                    }
                }
                None => full = true,
            }
        };
        filters.visit_paths(&mut add);
        options.visit_order_keys(&mut add);
    }
    if full {
        Needed::Full
    } else if keys.is_empty() {
        Needed::Nothing
    } else {
        Needed::Keys(keys)
    }
}

/// A path that is exactly one plain top-level key (not a wildcard, not a list index, no
/// embedded `.` from an escaped dot) → the key; anything else → `None` (needs the full view).
///
/// The no-`.` guard keeps the fast path obviously correct: a struct's field names can never
/// contain `.`, and a single component only contains one after an escaped-dot merge (e.g.
/// `a\.b`), so such a key could never name a real struct field anyway — routing it to the
/// full view sidesteps the `order_by` *top_key*-vs-split-key subtlety entirely.
fn simple_key(parts: &[PathPart]) -> Option<&str> {
    match parts {
        [p] if !p.is_wildcard && p.index.is_none() && !p.key.contains('.') => Some(&p.key),
        _ => None,
    }
}

/// Build the `serde_json::Value` view of `item` that the pipeline needs (see [`Needed`]).
pub(crate) fn build_view<E: Serialize>(item: &E, needed: &Needed) -> Result<Value, FilterError> {
    match needed {
        Needed::Nothing => Ok(Value::Null),
        Needed::Full => full_view(item),
        Needed::Keys(keys) => match item.serialize(FieldExtractor { needed: keys.as_slice() }) {
            Ok(view) => Ok(view),
            // The row isn't a struct (e.g. a dynamic `Value` object via `serialize_map`, or a
            // scalar/array row) — fall back to the full materialization, which is correct for
            // any shape; only the struct fast path is an optimization.
            Err(ExtractError::NotStruct) => full_view(item),
            Err(ExtractError::Ser(m)) => Err(unrepresentable(m)),
        },
    }
}

fn full_view<E: Serialize>(item: &E) -> Result<Value, FilterError> {
    serde_json::to_value(item).map_err(|e| unrepresentable(e.to_string()))
}

fn unrepresentable(detail: impl fmt::Display) -> FilterError {
    FilterError::Eval(format!("row is not representable for filtering: {detail}"))
}

// --- the field-extracting serializer -----------------------------------------------------

/// A `Serializer` that, for a struct row, produces a `Value::Object` holding *only* the
/// `needed` top-level fields; for any non-struct top-level value it fails with
/// [`ExtractError::NotStruct`] so [`build_view`] can fall back to a full `to_value`.
struct FieldExtractor<'a> {
    needed: &'a [Box<str>],
}

/// Either "this row isn't a struct, fall back" or a genuine serialization failure.
#[derive(Debug)]
enum ExtractError {
    /// The top-level value is not a struct — the caller should fall back to a full `to_value`.
    NotStruct,
    /// The row's own `Serialize` (or a kept field's) failed.
    Ser(String),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractError::NotStruct => f.write_str("row is not a struct"),
            ExtractError::Ser(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ExtractError {}

impl SerError for ExtractError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        ExtractError::Ser(msg.to_string())
    }
}

/// Collects only the `needed` fields of one struct into an object.
struct StructPruner<'a> {
    needed: &'a [Box<str>],
    out: Map<String, Value>,
}

impl SerializeStruct for StructPruner<'_> {
    type Ok = Value;
    type Error = ExtractError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), ExtractError> {
        // Un-needed fields are dropped here without ever serializing their value — that skip
        // is the whole point of the extractor.
        if self.needed.iter().any(|k| &**k == key) {
            let v = serde_json::to_value(value).map_err(|e| ExtractError::Ser(e.to_string()))?;
            self.out.insert(key.to_owned(), v);
        }
        Ok(())
    }

    fn end(self) -> Result<Value, ExtractError> {
        Ok(Value::Object(self.out))
    }
}

/// Reject helper for every non-struct entry point.
fn not_struct<T>() -> Result<T, ExtractError> {
    Err(ExtractError::NotStruct)
}

impl<'a> Serializer for FieldExtractor<'a> {
    type Ok = Value;
    type Error = ExtractError;
    type SerializeSeq = Impossible<Value, ExtractError>;
    type SerializeTuple = Impossible<Value, ExtractError>;
    type SerializeTupleStruct = Impossible<Value, ExtractError>;
    type SerializeTupleVariant = Impossible<Value, ExtractError>;
    type SerializeMap = Impossible<Value, ExtractError>;
    type SerializeStruct = StructPruner<'a>;
    type SerializeStructVariant = Impossible<Value, ExtractError>;

    // The one fast path: a struct row keeps only its needed fields.
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<StructPruner<'a>, ExtractError> {
        Ok(StructPruner { needed: self.needed, out: Map::new() })
    }

    // Everything else is "not a struct" → caller falls back to a full `to_value`. (Maps,
    // including dynamic `Value` objects, deliberately go here: the full path is already
    // byte-correct for them, and only the typed-struct case benefits from pruning.)
    fn serialize_bool(self, _v: bool) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_i8(self, _v: i8) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_i16(self, _v: i16) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_i32(self, _v: i32) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_i64(self, _v: i64) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_u8(self, _v: u8) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_u16(self, _v: u16) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_u32(self, _v: u32) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_u64(self, _v: u64) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_f32(self, _v: f32) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_f64(self, _v: f64) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_char(self, _v: char) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_str(self, _v: &str) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_bytes(self, _v: &[u8]) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_none(self) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _v: &T) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_unit(self) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
    ) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _v: &T,
    ) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _v: &T,
    ) -> Result<Value, ExtractError> {
        not_struct()
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, ExtractError> {
        not_struct()
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, ExtractError> {
        not_struct()
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, ExtractError> {
        not_struct()
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, ExtractError> {
        not_struct()
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, ExtractError> {
        not_struct()
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, ExtractError> {
        not_struct()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compile_filters, compile_options};
    use serde_json::json;

    fn needed(filters: Value, opts: Value) -> Needed {
        let cf = compile_filters(filters.as_array().unwrap()).unwrap();
        let co = compile_options(&serde_json::from_value(opts).unwrap()).unwrap();
        compute_needed(&cf, &co)
    }

    #[test]
    fn needed_classification() {
        // No paths at all → Nothing.
        assert!(matches!(needed(json!([]), json!({})), Needed::Nothing));
        // A flat filter key → Keys; a duplicate key dedups; an order_by key joins in.
        assert!(matches!(
            needed(json!([["a", "=", 1], ["a", ">", 0]]), json!({"order_by": ["b"]})),
            Needed::Keys(ref ks)
                if ks.len() == 2 && ks.iter().any(|k| &**k == "a") && ks.iter().any(|k| &**k == "b")
        ));
        // Nested, indexed, wildcard, and escaped-dot single keys each force Full.
        assert!(matches!(needed(json!([["a.b", "=", 1]]), json!({})), Needed::Full));
        assert!(matches!(needed(json!([["0", "=", 1]]), json!({})), Needed::Full));
        assert!(matches!(needed(json!([["*", "=", 1]]), json!({})), Needed::Full));
        assert!(matches!(needed(json!([["a\\.b", "=", 1]]), json!({})), Needed::Full));
        assert!(matches!(needed(json!([]), json!({"order_by": ["a.b"]})), Needed::Full));
        // Once Full, a later simple key is short-circuited (exercises the `if full` guard).
        assert!(matches!(needed(json!([["a.b", "=", 1], ["c", "=", 2]]), json!({})), Needed::Full));
    }

    /// A two-field struct (hand-written `Serialize` — this crate doesn't pull in serde derive).
    struct Row {
        a: i32,
        b: i32,
    }
    impl Serialize for Row {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut st = s.serialize_struct("Row", 2)?;
            st.serialize_field("a", &self.a)?;
            st.serialize_field("b", &self.b)?;
            st.end()
        }
    }

    /// A value whose `Serialize` always fails — to exercise the error paths.
    struct Fails;
    impl Serialize for Fails {
        fn serialize<S: Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
            Err(S::Error::custom("boom"))
        }
    }

    /// A struct whose one (needed) field fails to serialize.
    struct Holder;
    impl Serialize for Holder {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut st = s.serialize_struct("Holder", 1)?;
            st.serialize_field("a", &Fails)?;
            st.end()
        }
    }

    #[test]
    fn build_view_branches() {
        let keys = Needed::Keys(vec![Box::from("a")]);
        // Struct fast path keeps only `a`, drops `b`.
        assert_eq!(build_view(&Row { a: 1, b: 2 }, &keys).unwrap(), json!({"a": 1}));
        // Nothing → free null view; Full → whole row.
        assert_eq!(build_view(&Row { a: 1, b: 2 }, &Needed::Nothing).unwrap(), Value::Null);
        assert_eq!(build_view(&Row { a: 1, b: 2 }, &Needed::Full).unwrap(), json!({"a": 1, "b": 2}));
        // A dynamic Value object isn't a struct → falls back to to_value (full, correct).
        assert_eq!(build_view(&json!({"a": 1, "b": 2}), &keys).unwrap(), json!({"a": 1, "b": 2}));
        // A failing field on the struct fast path, and a failing row on the full path, both
        // surface as Eval. When the failing field `a` isn't among the needed keys it is never
        // serialized, so `Holder` extracts cleanly to an empty object.
        assert!(matches!(build_view(&Holder, &keys), Err(FilterError::Eval(_))));
        assert_eq!(build_view(&Holder, &Needed::Keys(vec![Box::from("z")])).unwrap(), json!({}));
        assert!(matches!(build_view(&Fails, &Needed::Full), Err(FilterError::Eval(_))));
    }

    #[test]
    fn extractor_rejects_every_non_struct_shape() {
        let n: Vec<Box<str>> = vec![Box::from("x")];
        let fe = || FieldExtractor { needed: &n };
        macro_rules! reject {
            ($($e:expr),* $(,)?) => { $( assert!(matches!($e, Err(ExtractError::NotStruct))); )* };
        }
        // Driven through each `Serialize` impl (scalars, str/char, option, unit, seq/tuple, map).
        reject!(
            true.serialize(fe()),
            1i8.serialize(fe()),
            1i16.serialize(fe()),
            1i32.serialize(fe()),
            1i64.serialize(fe()),
            1u8.serialize(fe()),
            1u16.serialize(fe()),
            1u32.serialize(fe()),
            1u64.serialize(fe()),
            1f32.serialize(fe()),
            1f64.serialize(fe()),
            'c'.serialize(fe()),
            "s".serialize(fe()),
            Option::<i32>::None.serialize(fe()),
            Some(1i32).serialize(fe()),
            ().serialize(fe()),
            vec![1i32].serialize(fe()),
            (1i32, 2i32).serialize(fe()),
            json!({"a": 1}).serialize(fe()),
        );
        // The variant / newtype / unit-struct / bytes entry points have no convenient derive,
        // so call them directly.
        reject!(
            fe().serialize_bytes(b"z"),
            fe().serialize_unit_struct("U"),
            fe().serialize_unit_variant("E", 0, "V"),
            fe().serialize_newtype_struct("N", &1i32),
            fe().serialize_newtype_variant("E", 0, "V", &1i32),
            fe().serialize_tuple_struct("T", 2),
            fe().serialize_tuple_variant("E", 0, "V", 2),
            fe().serialize_struct_variant("E", 0, "V", 1),
        );
    }

    #[test]
    fn error_display_and_kind() {
        assert_eq!(ExtractError::NotStruct.to_string(), "row is not a struct");
        assert_eq!(<ExtractError as SerError>::custom("nope").to_string(), "nope");
    }
}
