//! Python-object comparison semantics over [`serde_json::Value`].
//!
//! The C engine evaluates operators with CPython rules, so we reproduce them:
//! `==`/`!=` are **total** (cross-type → not-equal) with a numeric tower where
//! `true == 1 == 1.0`; `<`/`>`/`<=`/`>=` **raise** (`TypeError`) on incomparable operands
//! (`None`, mismatched types, dicts) — surfaced here as [`FilterError::Eval`]; `in` uses
//! `PySequence_Contains` (list membership, substring for strings, key membership for dicts);
//! and the `C` case-insensitive prefix `casefold`s its operands.

use std::cmp::Ordering;

use serde_json::Value;

use crate::FilterError;

/// A numeric view of a JSON scalar, for Python's `bool ⊂ int ⊂ float` tower.
#[derive(Clone, Copy)]
enum Num {
    Int(i128),
    Float(f64),
}

fn num_of(v: &Value) -> Option<Num> {
    match v {
        Value::Bool(b) => Some(Num::Int(*b as i128)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(Num::Int(i as i128))
            } else if let Some(u) = n.as_u64() {
                Some(Num::Int(u as i128))
            } else {
                n.as_f64().map(Num::Float)
            }
        }
        _ => None,
    }
}

fn num_eq(a: Num, b: Num) -> bool {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => x == y,
        (Num::Float(x), Num::Float(y)) => x == y,
        (Num::Int(x), Num::Float(y)) | (Num::Float(y), Num::Int(x)) => x as f64 == y,
    }
}

fn num_cmp(a: Num, b: Num) -> Option<Ordering> {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => Some(x.cmp(&y)),
        (Num::Float(x), Num::Float(y)) => x.partial_cmp(&y),
        (Num::Int(x), Num::Float(y)) => (x as f64).partial_cmp(&y),
        (Num::Float(x), Num::Int(y)) => x.partial_cmp(&(y as f64)),
    }
}

/// Python `a == b` (never raises). The numeric tower means `1 == 1.0 == true`.
pub(crate) fn py_eq(a: &Value, b: &Value) -> bool {
    if let (Some(x), Some(y)) = (num_of(a), num_of(b)) {
        return num_eq(x, y);
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| py_eq(v, w)))
        }
        _ => false,
    }
}

/// Python `a < b` outcome as an [`Ordering`], or [`FilterError::Eval`] when CPython would
/// raise `TypeError` (incomparable operands).
pub(crate) fn py_order(a: &Value, b: &Value) -> Result<Ordering, FilterError> {
    if let (Some(x), Some(y)) = (num_of(a), num_of(b)) {
        return num_cmp(x, y).ok_or_else(|| incomparable(a, b));
    }
    match (a, b) {
        (Value::String(x), Value::String(y)) => Ok(x.cmp(y)),
        (Value::Array(x), Value::Array(y)) => array_order(x, y),
        _ => Err(incomparable(a, b)),
    }
}

fn array_order(x: &[Value], y: &[Value]) -> Result<Ordering, FilterError> {
    for (p, q) in x.iter().zip(y) {
        if !py_eq(p, q) {
            return py_order(p, q);
        }
    }
    Ok(x.len().cmp(&y.len()))
}

fn incomparable(a: &Value, b: &Value) -> FilterError {
    FilterError::Eval(format!(
        "'<' not supported between instances of '{}' and '{}'",
        type_name(a),
        type_name(b)
    ))
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if n.is_f64() {
                "float"
            } else {
                "int"
            }
        }
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Python `x in container` (`PySequence_Contains`). List → membership by `==`; string →
/// substring (requires a string `x`); dict → key membership. Other container types raise.
pub(crate) fn py_contains(container: &Value, x: &Value) -> Result<bool, FilterError> {
    match container {
        Value::Array(items) => Ok(items.iter().any(|e| py_eq(e, x))),
        Value::String(s) => match x {
            Value::String(xs) => Ok(s.contains(xs.as_str())),
            _ => Err(FilterError::Eval(
                "'in <string>' requires string as left operand".into(),
            )),
        },
        Value::Object(map) => Ok(match x {
            Value::String(xs) => map.contains_key(xs.as_str()),
            _ => false,
        }),
        _ => Err(FilterError::Eval(format!(
            "argument of type '{}' is not iterable",
            type_name(container)
        ))),
    }
}

/// Python `str.casefold()`, approximated by `to_lowercase` (exact for ASCII; full Unicode
/// casefold — e.g. `ß`→`ss` — is a known limitation, flagged in the plan's watch-items).
pub(crate) fn casefold_str(s: &str) -> String {
    s.to_lowercase()
}

/// `c_casefold`: `str`→casefolded `str`, `list`→casefolded list (each element must be a
/// string), `null`→`null`; any other type raises (`cannot casefold`).
pub(crate) fn casefold_value(v: &Value) -> Result<Value, FilterError> {
    match v {
        Value::Null => Ok(Value::Null),
        Value::String(s) => Ok(Value::String(casefold_str(s))),
        Value::Array(items) => {
            let folded: Result<Vec<Value>, FilterError> = items
                .iter()
                .map(|e| match e {
                    Value::String(s) => Ok(Value::String(casefold_str(s))),
                    other => Err(FilterError::Eval(format!(
                        "filter_list: cannot casefold value of type '{}'",
                        type_name(other)
                    ))),
                })
                .collect();
            Ok(Value::Array(folded?))
        }
        other => Err(FilterError::Eval(format!(
            "filter_list: cannot casefold value of type '{}'",
            type_name(other)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numeric_tower() {
        // eq across int/float/bool
        assert!(py_eq(&json!(1), &json!(1.0)));
        assert!(py_eq(&json!(true), &json!(1)));
        assert!(py_eq(&json!(false), &json!(0)));
        assert!(!py_eq(&json!(1), &json!(2)));
        assert!(py_eq(&json!(1.5), &json!(1.5)));
        // order across int/float/bool, both directions
        use Ordering::*;
        assert_eq!(py_order(&json!(1), &json!(2)).unwrap(), Less);
        assert_eq!(py_order(&json!(2.0), &json!(2)).unwrap(), Equal);
        assert_eq!(py_order(&json!(1.5), &json!(1.0)).unwrap(), Greater);
        assert_eq!(py_order(&json!(2), &json!(1.0)).unwrap(), Greater);
        assert_eq!(py_order(&json!(true), &json!(false)).unwrap(), Greater);
        // large positive (u64 path)
        assert!(py_eq(&json!(u64::MAX), &json!(u64::MAX)));
    }

    #[test]
    fn eq_all_arms() {
        assert!(py_eq(&json!(null), &json!(null)));
        assert!(!py_eq(&json!(null), &json!("x")));
        assert!(py_eq(&json!("a"), &json!("a")));
        assert!(!py_eq(&json!("a"), &json!("b")));
        assert!(!py_eq(&json!("1"), &json!(1)));
        assert!(py_eq(&json!([1, 2]), &json!([1, 2])));
        assert!(!py_eq(&json!([1]), &json!([1, 2])));
        assert!(!py_eq(&json!([1, 2]), &json!([1, 3])));
        assert!(py_eq(&json!({"a": 1, "b": 2}), &json!({"b": 2, "a": 1})));
        assert!(!py_eq(&json!({"a": 1}), &json!({"b": 1})));
        assert!(!py_eq(&json!({"a": 1}), &json!({"a": 1, "b": 2})));
    }

    #[test]
    fn order_strings_arrays_and_errors() {
        use Ordering::*;
        assert_eq!(py_order(&json!("a"), &json!("b")).unwrap(), Less);
        assert_eq!(py_order(&json!([1, 2]), &json!([1, 3])).unwrap(), Less);
        assert_eq!(py_order(&json!([1]), &json!([1, 2])).unwrap(), Less); // length tiebreak
        assert_eq!(py_order(&json!([1, 2]), &json!([1, 2])).unwrap(), Equal);
        // incomparable → Err, exercising type_name for every variant
        assert!(py_order(&json!(null), &json!(1)).is_err());
        assert!(py_order(&json!("a"), &json!(1)).is_err());
        assert!(py_order(&json!({}), &json!({})).is_err());
        assert!(py_order(&json!(true), &json!("x")).is_err());
        assert!(py_order(&json!(1.5), &json!("x")).is_err());
        assert!(py_order(&json!([1, "x"]), &json!([1, 2])).is_err()); // incomparable element
        assert!(py_order(&json!([1]), &json!(1)).is_err()); // list vs int → type_name "list"
    }

    #[test]
    fn contains_all_arms() {
        assert!(py_contains(&json!([1, 2, 3]), &json!(2)).unwrap());
        assert!(!py_contains(&json!([1, 2]), &json!(9)).unwrap());
        assert!(py_contains(&json!("abc"), &json!("b")).unwrap());
        assert!(!py_contains(&json!("abc"), &json!("z")).unwrap());
        assert!(py_contains(&json!("abc"), &json!(1)).is_err()); // non-string in string
        assert!(py_contains(&json!({"a": 1}), &json!("a")).unwrap());
        assert!(!py_contains(&json!({"a": 1}), &json!("b")).unwrap());
        assert!(!py_contains(&json!({"a": 1}), &json!(1)).unwrap()); // non-string key → false
        assert!(py_contains(&json!(5), &json!(1)).is_err()); // not iterable
    }

    #[test]
    fn casefold_all_arms() {
        assert_eq!(casefold_str("AbC"), "abc");
        assert_eq!(casefold_value(&json!("Ab")).unwrap(), json!("ab"));
        assert_eq!(casefold_value(&json!(["A", "B"])).unwrap(), json!(["a", "b"]));
        assert_eq!(casefold_value(&json!(null)).unwrap(), json!(null));
        assert!(casefold_value(&json!([1])).is_err()); // non-string element
        assert!(casefold_value(&json!(5)).is_err()); // non-foldable scalar
    }
}
