//! Filter compilation and evaluation (the C engine's `filter_list.c`).
//!
//! `[name, op, value]` leaves and `["OR", [branch, …]]` nodes compile to a tree of
//! [`Node`]s (top-level filters are implicitly AND'd). Each leaf pre-splits its path.
//! Evaluation traverses the item by the pre-split path and applies the operator with
//! Python semantics (see [`crate::value`]).
//!
//! The `~` regex operator is intentionally **not** supported — see the crate-level note.

use std::cmp::Ordering;

use serde_json::Value;

use crate::path::{split_path, PathPart};
use crate::value::{casefold_value, py_contains, py_eq, py_order};
use crate::FilterError;

const MAX_DEPTH: usize = 64;
const NULL: Value = Value::Null;

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    In,
    Nin,
    Rin,
    Rnin,
    Sw,
    Nsw,
    Ew,
    New,
}

/// Parse an operator string, peeling the leading `C` case-insensitive prefix.
fn parse_op(s: &str) -> Result<(Op, bool), FilterError> {
    let (ci, bare) = match s.strip_prefix('C') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let op = match bare {
        "=" => Op::Eq,
        "!=" => Op::Ne,
        ">" => Op::Gt,
        ">=" => Op::Ge,
        "<" => Op::Lt,
        "<=" => Op::Le,
        "in" => Op::In,
        "nin" => Op::Nin,
        "rin" => Op::Rin,
        "rnin" => Op::Rnin,
        "^" => Op::Sw,
        "!^" => Op::Nsw,
        "$" => Op::Ew,
        "!$" => Op::New,
        _ => return Err(FilterError::Compile(format!("filter_list: unknown operator '{bare}'"))),
    };
    Ok((op, ci))
}

struct Simple {
    parts: Vec<PathPart>,
    op: Op,
    ci: bool,
    /// Comparison value (also the `startswith`/`endswith` needle and `in` container).
    value: Value,
    /// Casefolded comparison value, when `ci`.
    value_ci: Option<Value>,
}

enum Node {
    Simple(Simple),
    Or(Vec<Node>),
    And(Vec<Node>),
}

/// A pre-compiled filter tree. Multiple top-level filters are implicitly AND'd.
pub struct CompiledFilters {
    filters: Vec<Node>,
}

impl std::fmt::Debug for CompiledFilters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CompiledFilters({} filter(s))", self.filters.len())
    }
}

/// Compile a raw `query-filters` list into a [`CompiledFilters`].
///
/// Returns [`FilterError::Compile`] for malformed syntax (bad operator, wrong node arity,
/// non-string name/operator, un-casefoldable CI value, excessive nesting).
pub fn compile_filters(filters: &[Value]) -> Result<CompiledFilters, FilterError> {
    let mut out = Vec::with_capacity(filters.len());
    for f in filters {
        out.push(compile_node(f, 0)?);
    }
    Ok(CompiledFilters { filters: out })
}

fn compile_node(f: &Value, depth: usize) -> Result<Node, FilterError> {
    if depth > MAX_DEPTH {
        return Err(FilterError::Compile(
            "filter_list: maximum filter nesting depth exceeded".into(),
        ));
    }
    let arr = f
        .as_array()
        .ok_or_else(|| FilterError::Compile("a filter must be a list".into()))?;

    match arr.len() {
        3 => compile_simple(arr),
        2 => {
            let tag = arr[0].as_str();
            if tag != Some("OR") {
                return Err(FilterError::Compile(
                    "filter_list: len-2 filter must start with \"OR\"".into(),
                ));
            }
            let branches = arr[1]
                .as_array()
                .ok_or_else(|| FilterError::Compile("OR branches must be a list".into()))?;
            let mut children = Vec::with_capacity(branches.len());
            for branch in branches {
                children.push(compile_branch(branch, depth)?);
            }
            Ok(Node::Or(children))
        }
        n => Err(FilterError::Compile(format!("filter_list: invalid filter length {n}"))),
    }
}

/// One OR branch: a `[name, op, value]`/nested-`OR` filter, or an AND conjunction when the
/// branch's first element is itself a list (`[[..], [..]]`).
fn compile_branch(branch: &Value, depth: usize) -> Result<Node, FilterError> {
    let arr = branch
        .as_array()
        .ok_or_else(|| FilterError::Compile("an OR branch must be a list".into()))?;
    let is_conjunction = matches!(arr.first(), Some(Value::Array(_)));
    if is_conjunction {
        let mut children = Vec::with_capacity(arr.len());
        for sub in arr {
            children.push(compile_node(sub, depth + 1)?);
        }
        Ok(Node::And(children))
    } else {
        compile_node(branch, depth + 1)
    }
}

fn compile_simple(arr: &[Value]) -> Result<Node, FilterError> {
    let name = arr[0]
        .as_str()
        .ok_or_else(|| FilterError::Compile("filter name must be a string".into()))?;
    let op_str = arr[1]
        .as_str()
        .ok_or_else(|| FilterError::Compile("filter operator must be a string".into()))?;
    let value = arr[2].clone();
    let (op, ci) = parse_op(op_str)?;
    let parts = split_path(name);

    // CI pre-folds the comparison value at compile time; failure (e.g. a non-string,
    // non-list value) is a query-syntax error, like the C engine raising in compile.
    let value_ci = if ci {
        Some(casefold_value(&value).map_err(eval_to_compile)?)
    } else {
        None
    };

    Ok(Node::Simple(Simple { parts, op, ci, value, value_ci }))
}

/// A compile-time casefold failure is a syntax error, not a runtime one — rewrap the
/// message as `Compile` (the only caller passes a casefold `Eval`).
fn eval_to_compile(e: FilterError) -> FilterError {
    let (FilterError::Eval(m) | FilterError::Compile(m)) = e;
    FilterError::Compile(m)
}

/// Whether `item` matches every top-level filter (implicit AND, short-circuiting).
pub(crate) fn matches_all(item: &Value, cf: &CompiledFilters) -> Result<bool, FilterError> {
    for node in &cf.filters {
        if !eval_node(item, node, 0)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn eval_node(item: &Value, node: &Node, depth: usize) -> Result<bool, FilterError> {
    if depth > MAX_DEPTH {
        return Err(FilterError::Eval(
            "filter_list: maximum filter nesting depth exceeded".into(),
        ));
    }
    match node {
        Node::Simple(sf) => eval_simple(item, sf, 0),
        Node::Or(children) => {
            for c in children {
                if eval_node(item, c, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Node::And(children) => {
            for c in children {
                if !eval_node(item, c, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

/// Traverse `item` by `sf.parts[start..]` and apply the operator to the leaf.
///
/// Dict: key lookup (missing → no match). List: `*` recurses over every element (any
/// match), a numeric index selects (out-of-bounds → `null`), any other key → no match.
/// A scalar reached with path remaining is treated as the leaf (the operator applies to
/// it) — mirroring the C engine's `getattr`-fails-then-apply behavior on JSON values.
fn eval_simple(item: &Value, sf: &Simple, start: usize) -> Result<bool, FilterError> {
    let parts = &sf.parts;
    let n = parts.len();

    // Ultra-fast path: single flat key on a dict.
    if start == 0 && n == 1 {
        if let Value::Object(map) = item {
            return match map.get(&parts[0].key) {
                Some(v) => apply_op(sf, v),
                None => Ok(false),
            };
        }
    }

    let mut cur = item;
    let mut i = start;
    while i < n {
        let pp = &parts[i];
        match cur {
            Value::Object(map) => match map.get(&pp.key) {
                Some(v) => cur = v,
                None => return Ok(false),
            },
            Value::Array(items) => {
                if pp.is_wildcard {
                    for entry in items {
                        if eval_simple(entry, sf, i + 1)? {
                            return Ok(true);
                        }
                    }
                    return Ok(false);
                } else if let Some(idx) = pp.index {
                    cur = items.get(idx).unwrap_or(&NULL);
                } else {
                    // Named field on a list → no such attribute → no match.
                    return Ok(false);
                }
            }
            // Scalar with path remaining: apply the operator to it directly.
            _ => return apply_op(sf, cur),
        }
        i += 1;
    }
    apply_op(sf, cur)
}

fn as_str(v: &Value) -> Result<&str, FilterError> {
    v.as_str()
        .ok_or_else(|| FilterError::Eval("expected a string operand".into()))
}

/// Apply the leaf operator to a retrieved value `val` (Python operator semantics).
fn apply_op(sf: &Simple, val: &Value) -> Result<bool, FilterError> {
    // CI: casefold the source (None stays None) and use the pre-folded comparison value.
    let folded: Option<Value> = if sf.ci && !val.is_null() {
        Some(casefold_value(val)?)
    } else {
        None
    };
    let source: &Value = folded.as_ref().unwrap_or(val);
    let cmp: &Value = if sf.ci {
        sf.value_ci.as_ref().expect("ci implies value_ci")
    } else {
        &sf.value
    };

    let r = match sf.op {
        Op::Eq => py_eq(source, cmp),
        Op::Ne => !py_eq(source, cmp),
        Op::Gt => py_order(source, cmp)? == Ordering::Greater,
        Op::Ge => matches!(py_order(source, cmp)?, Ordering::Greater | Ordering::Equal),
        Op::Lt => py_order(source, cmp)? == Ordering::Less,
        Op::Le => matches!(py_order(source, cmp)?, Ordering::Less | Ordering::Equal),
        Op::In => py_contains(cmp, source)?,
        Op::Nin => {
            if val.is_null() {
                false
            } else {
                !py_contains(cmp, source)?
            }
        }
        Op::Rin => {
            if val.is_null() {
                false
            } else {
                py_contains(source, cmp)?
            }
        }
        Op::Rnin => {
            if val.is_null() {
                false
            } else {
                !py_contains(source, cmp)?
            }
        }
        Op::Sw => !val.is_null() && as_str(source)?.starts_with(as_str(cmp)?),
        Op::Nsw => !val.is_null() && !as_str(source)?.starts_with(as_str(cmp)?),
        Op::Ew => !val.is_null() && as_str(source)?.ends_with(as_str(cmp)?),
        Op::New => !val.is_null() && !as_str(source)?.ends_with(as_str(cmp)?),
    };
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(f: serde_json::Value) -> Result<CompiledFilters, FilterError> {
        compile_filters(&[f])
    }

    #[test]
    fn compile_error_paths() {
        assert!(one(json!(["a", "??", 1])).is_err()); // unknown operator
        assert!(one(json!(["a"])).is_err()); // wrong arity (len 1)
        assert!(one(json!(["XOR", []])).is_err()); // len-2 not "OR"
        assert!(one(json!([1, "=", 1])).is_err()); // non-string name
        assert!(one(json!(["a", 5, 1])).is_err()); // non-string operator
        assert!(one(json!("nope")).is_err()); // not a list
        assert!(one(json!(["OR", "x"])).is_err()); // OR branches not a list
        assert!(one(json!(["OR", ["x"]])).is_err()); // an OR branch not a list
        assert!(one(json!(["a", "C=", 5])).is_err()); // CI casefold of a non-string value
    }

    #[test]
    fn eval_branch_edges() {
        // named field on a list → no match
        assert!(!matches_all(&json!({"a": [1, 2]}), &one(json!(["a.x", "=", 1])).unwrap()).unwrap());
        // rin / rnin with a null source → false
        assert!(!matches_all(&json!({"a": null}), &one(json!(["a", "rin", "x"])).unwrap()).unwrap());
        assert!(!matches_all(&json!({"a": null}), &one(json!(["a", "rnin", "x"])).unwrap()).unwrap());
    }

    #[test]
    fn compile_depth_limit() {
        let mut f = json!(["name", "=", "x"]);
        for _ in 0..70 {
            f = json!(["OR", [f]]);
        }
        assert!(matches!(one(f), Err(FilterError::Compile(_))));
    }

    #[test]
    fn eval_depth_guard() {
        // Hand-build a tree deeper than compile would allow, to exercise the defensive
        // runtime depth guard (compile bounds nesting, so this is otherwise unreachable).
        let mut node = Node::Simple(Simple {
            parts: split_path("x"),
            op: Op::Eq,
            ci: false,
            value: json!(1),
            value_ci: None,
        });
        for _ in 0..70 {
            node = Node::Or(vec![node]);
        }
        let cf = CompiledFilters { filters: vec![node] };
        assert!(matches!(matches_all(&json!({"x": 1}), &cf), Err(FilterError::Eval(_))));
    }

    #[test]
    fn debug_impl() {
        assert!(format!("{:?}", one(json!(["a", "=", 1])).unwrap()).contains("CompiledFilters"));
    }
}
