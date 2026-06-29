//! `query-options` compilation and the post-filter pipeline (the C engine's
//! `filter_options.c` + `apply_options`, minus `select` — see the crate-level deviation note).
//!
//! Pipeline order: **count → order → offset → limit** (count is handled by [`crate::tnfilter`];
//! offset/limit do not apply to it). `order_by` supports `-`/`nulls_first:`/`nulls_last:`
//! prefixes and is a stable, last-spec-first multi-key sort with Python comparison semantics.
//! The `select` projection is intentionally omitted so the response row shape stays stable
//! and the engine is read-only (it never builds a projected object).

use std::cmp::Ordering;

use serde::Deserialize;
use serde_json::Value;

use crate::path::{split_path, PathPart};
use crate::value::{py_eq, py_order};
use crate::FilterError;

const NULL: Value = Value::Null;

/// Wire model for `query-options` (the supported subset of the C `compile_options` kwargs;
/// `select` is omitted — see the crate-level deviation note). All fields default off, so an
/// absent `query-options` is the identity.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct QueryOptions {
    /// Return only the first match (with no `order_by`, short-circuits the scan).
    #[serde(default)]
    pub get: bool,
    /// Return the count of matches instead of the rows.
    #[serde(default)]
    pub count: bool,
    /// Ordering directives (`-`/`nulls_first:`/`nulls_last:` prefixes).
    #[serde(default)]
    pub order_by: Option<Vec<String>>,
    /// Skip the first N matches.
    #[serde(default)]
    pub offset: usize,
    /// Cap results at N rows (0 = no cap).
    #[serde(default)]
    pub limit: usize,
}

struct OrderSpec {
    keys: Vec<PathPart>,
    /// Full de-prefixed field string; the C engine partitions nulls by a *literal*
    /// top-level lookup of this (distinct from the nested sort-key traversal).
    top_key: String,
    reverse: bool,
    /// 0 = none, 1 = nulls_first, 2 = nulls_last.
    nulls_mode: u8,
}

/// Pre-compiled `query-options`. Built by [`compile_options`].
pub struct CompiledOptions {
    shortcircuit: bool,
    count_flag: bool,
    order_specs: Vec<OrderSpec>,
    offset: usize,
    limit: usize,
}

impl std::fmt::Debug for CompiledOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CompiledOptions(count={}, order={}, offset={}, limit={})",
            self.count_flag,
            self.order_specs.len(),
            self.offset,
            self.limit
        )
    }
}

/// Compile `query-options`, validating the same constraints as the C engine.
///
/// [`FilterError::Compile`] for `get` + `limit > 1`, `get` + `offset`, `limit > 10000`, or an
/// empty `order_by` field name.
pub fn compile_options(opts: &QueryOptions) -> Result<CompiledOptions, FilterError> {
    if opts.get && opts.limit > 1 {
        return Err(FilterError::Compile(
            "get=True is incompatible with limit > 1".into(),
        ));
    }
    if opts.get && opts.offset > 0 {
        return Err(FilterError::Compile(
            "get=True is incompatible with offset".into(),
        ));
    }
    if opts.limit > 10000 {
        return Err(FilterError::Compile("limit must not exceed 10000".into()));
    }

    let order_specs = match &opts.order_by {
        Some(items) => items
            .iter()
            .map(|s| compile_order(s))
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };

    Ok(CompiledOptions {
        // shortcircuit: get with no ordering means stop at the first match.
        shortcircuit: opts.get && order_specs.is_empty(),
        count_flag: opts.count,
        order_specs,
        offset: opts.offset,
        limit: opts.limit,
    })
}

fn compile_order(d: &str) -> Result<OrderSpec, FilterError> {
    let (nulls_mode, after_nulls) = if let Some(rest) = d.strip_prefix("nulls_first:") {
        (1u8, rest)
    } else if let Some(rest) = d.strip_prefix("nulls_last:") {
        (2u8, rest)
    } else {
        (0u8, d)
    };
    let (reverse, field) = match after_nulls.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, after_nulls),
    };
    if field.is_empty() {
        return Err(FilterError::Compile(
            "filter_list: order_by field name is empty".into(),
        ));
    }
    Ok(OrderSpec {
        keys: split_path(field),
        top_key: field.to_string(),
        reverse,
        nulls_mode,
    })
}

impl CompiledOptions {
    pub(crate) fn count_flag(&self) -> bool {
        self.count_flag
    }
    pub(crate) fn shortcircuit(&self) -> bool {
        self.shortcircuit
    }
    pub(crate) fn has_order(&self) -> bool {
        !self.order_specs.is_empty()
    }
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Visit the split key path of every `order_by` spec, for [`crate::extract`]'s needed-field
    /// analysis. (The nulls partition's literal `top_key` lookup is covered too: a spec only
    /// qualifies for the pruned view when its key is a single plain component, for which
    /// `top_key` equals that component — see `extract::simple_key`.)
    pub(crate) fn visit_order_keys(&self, f: &mut impl FnMut(&[PathPart])) {
        self.order_specs.iter().for_each(|s| f(&s.keys));
    }

    /// Run the non-count pipeline tail on the matched rows: order → offset → limit. Each row
    /// is a `(view, item)` pair — ordering uses the `view`, and the typed `item` is returned
    /// unchanged (no projection).
    pub(crate) fn apply<E>(&self, matched: Vec<(Value, E)>) -> Result<Vec<E>, FilterError> {
        let mut rv = matched;
        if !self.order_specs.is_empty() {
            rv = apply_order(rv, &self.order_specs)?;
        }
        if self.offset > 0 {
            rv = if self.offset < rv.len() {
                rv.split_off(self.offset)
            } else {
                Vec::new()
            };
        }
        if self.limit > 0 && rv.len() > self.limit {
            rv.truncate(self.limit);
        }
        Ok(rv.into_iter().map(|(_, item)| item).collect())
    }
}

// --- order_by ----------------------------------------------------------------

/// Extract a sort key by traversing the nested path (absent / null → `null`).
fn order_get(item: &Value, parts: &[PathPart]) -> Value {
    let mut cur = item;
    for pp in parts {
        match cur {
            Value::Object(map) => match map.get(&pp.key) {
                Some(v) => cur = v,
                None => return Value::Null,
            },
            Value::Array(items) => match pp.index {
                Some(idx) => cur = items.get(idx).unwrap_or(&NULL),
                None => return Value::Null,
            },
            _ => return Value::Null,
        }
    }
    cur.clone()
}

fn apply_order<E>(
    rows: Vec<(Value, E)>,
    specs: &[OrderSpec],
) -> Result<Vec<(Value, E)>, FilterError> {
    let mut rv = rows;
    // Last spec first: each stable pass is overridden by the next, so specs[0] is primary.
    for spec in specs.iter().rev() {
        rv = sort_by_spec(rv, spec)?;
    }
    Ok(rv)
}

/// Compare two `(sort_key, signed_index)` pairs as Python compares the tuples: keys first
/// (may raise), then the integer tiebreak.
fn pair_cmp(ka: &Value, sa: i64, kb: &Value, sb: i64) -> Result<Ordering, FilterError> {
    if py_eq(ka, kb) {
        Ok(sa.cmp(&sb))
    } else {
        py_order(ka, kb)
    }
}

fn sort_by_spec<E>(
    list: Vec<(Value, E)>,
    spec: &OrderSpec,
) -> Result<Vec<(Value, E)>, FilterError> {
    if list.len() <= 1 {
        return Ok(list);
    }

    // Partition out null/absent sort columns (by a *literal* top-level lookup of top_key on
    // the row's `Value` view, `.0`).
    let (nulls, non_nulls) = if spec.nulls_mode != 0 {
        let mut nulls = Vec::new();
        let mut non = Vec::new();
        for item in list {
            let is_null = match &item.0 {
                Value::Object(map) => !matches!(map.get(&spec.top_key), Some(v) if !v.is_null()),
                _ => true,
            };
            if is_null {
                nulls.push(item);
            } else {
                non.push(item);
            }
        }
        (nulls, non)
    } else {
        (Vec::new(), list)
    };

    // Sort non_nulls by (key, signed-index), mirroring the C build/sort/reverse dance.
    let keys: Vec<Value> = non_nulls.iter().map(|it| order_get(&it.0, &spec.keys)).collect();
    let mut order: Vec<usize> = (0..non_nulls.len()).collect();
    let mut err: Option<FilterError> = None;
    order.sort_by(|&a, &b| {
        if err.is_some() {
            return Ordering::Equal;
        }
        let (sa, sb) = if spec.reverse {
            (-(a as i64), -(b as i64))
        } else {
            (a as i64, b as i64)
        };
        match pair_cmp(&keys[a], sa, &keys[b], sb) {
            Ok(o) => o,
            Err(e) => {
                err = Some(e);
                Ordering::Equal
            }
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    if spec.reverse {
        order.reverse();
    }
    // Permute `non_nulls` by `order` without cloning the typed item: each permutation index
    // is used exactly once, so `take` always yields `Some`.
    let mut slots: Vec<Option<(Value, E)>> = non_nulls.into_iter().map(Some).collect();
    let sorted_non: Vec<(Value, E)> =
        order.into_iter().map(|i| slots[i].take().expect("permutation index used once")).collect();

    Ok(match spec.nulls_mode {
        1 => nulls.into_iter().chain(sorted_non).collect(),
        2 => sorted_non.into_iter().chain(nulls).collect(),
        _ => sorted_non,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn co(v: serde_json::Value) -> Result<CompiledOptions, FilterError> {
        compile_options(&serde_json::from_value(v).unwrap())
    }

    /// Wrap dynamic rows as `(view, item)` pairs (here the view is the row itself).
    fn pairs(vs: Vec<Value>) -> Vec<(Value, Value)> {
        vs.into_iter().map(|v| (v.clone(), v)).collect()
    }

    #[test]
    fn validation_and_debug() {
        assert!(co(json!({"get": true, "limit": 5})).is_err());
        assert!(co(json!({"get": true, "offset": 3})).is_err());
        assert!(co(json!({"limit": 10001})).is_err());
        assert!(co(json!({"order_by": [""]})).is_err());
        let c = co(json!({"count": true, "order_by": ["x"], "offset": 1, "limit": 2})).unwrap();
        assert!(format!("{c:?}").contains("CompiledOptions"));
    }

    #[test]
    fn order_get_paths() {
        let p = |s| split_path(s);
        assert_eq!(order_get(&json!({"a": {"b": 3}}), &p("a.b")), json!(3));
        assert_eq!(order_get(&json!({"a": [10, 20]}), &p("a.1")), json!(20)); // array index
        assert_eq!(order_get(&json!({"a": [10]}), &p("a.5")), json!(null)); // out-of-bounds
        assert_eq!(order_get(&json!({"a": 5}), &p("a.b")), json!(null)); // scalar mid-path
        assert_eq!(order_get(&json!({"a": 5}), &p("missing")), json!(null)); // missing key
        assert_eq!(order_get(&json!({"a": [10]}), &p("a.x")), json!(null)); // non-index key on list
    }

    #[test]
    fn apply_pipeline_edges() {
        // single-element sort (n<=1 fast path) + stable ties + offset+limit slice
        let one = vec![json!({"x": 1})];
        assert_eq!(co(json!({"order_by": ["x"]})).unwrap().apply(pairs(one.clone())).unwrap(), one);
        let ties = vec![json!({"x": 1, "i": "a"}), json!({"x": 1, "i": "b"})];
        assert_eq!(co(json!({"order_by": ["x"]})).unwrap().apply(pairs(ties.clone())).unwrap(), ties);
        let rows = vec![json!(0), json!(1), json!(2), json!(3)];
        assert_eq!(co(json!({"offset": 1, "limit": 2})).unwrap().apply(pairs(rows)).unwrap(), vec![json!(1), json!(2)]);
        // offset beyond the end → empty
        assert!(co(json!({"offset": 9})).unwrap().apply(pairs(vec![json!(0)])).unwrap().is_empty());
    }

    #[test]
    fn order_nulls_non_dict_row() {
        // a non-dict row in a nulls-ordered list lands in the nulls bucket
        let rows = vec![json!({"v": 2}), json!("scalar"), json!({"v": 1})];
        let out = co(json!({"order_by": ["nulls_first:v"]})).unwrap().apply(pairs(rows)).unwrap();
        assert_eq!(out, vec![json!("scalar"), json!({"v": 1}), json!({"v": 2})]);
    }
}
