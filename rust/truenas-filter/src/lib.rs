//! TrueNAS middlewared **query-filters / query-options** engine — a Rust port of the
//! `truenas_pyfilter` C extension (vendored spec: `truens_pos/src/cext/filter_utils/`).
//!
//! A query is a pair of `query-filters` (a `[name, op, value]` / `["OR", [..]]` list) and
//! `query-options` (`get`/`count`/`order_by`/`offset`/`limit`). The two are
//! [`compile_filters`]/[`compile_options`]'d once, then a data source is streamed through
//! [`tnfilter`]: items are pulled lazily and only matches are retained (never the full
//! unfiltered source), mirroring the C engine's `filter_list_run` iterator loop.
//!
//! Semantics match the C engine byte-for-byte (proven by the conformance corpus derived
//! from `truens_pos/tests/test_filter_list.py`): Python object comparison rules (`==`/`!=`
//! total with a numeric tower; `<`/`>`/… raise on incomparable operands) and
//! dotted/indexed/`*`-wildcard/escaped path traversal.
//!
//! ## Deviations from the Python/middleware filter_list
//!
//! Two features are **deliberately not supported**:
//!
//! - **`query-options.select`** (column projection). `select` is the only option that
//!   *reshapes* a row, so dropping it keeps the per-item response shape stable (equal to the
//!   method's `entry` type) and lets the engine be **read-only**: it filters, orders, and
//!   slices, then passes rows through **unchanged** — [`tnfilter`] takes
//!   `IntoIterator<Item = Value>` and *moves* matched rows into the result (no per-item
//!   re-serialization, no projected-object construction).
//! - **The `~` regex operator.** It is the only operator whose semantics can't be guaranteed
//!   byte-identical (Rust's `regex` crate is not Python's `re` — no backreferences/lookaround
//!   and a different dialect) and the only one that would need a regex dependency. Use
//!   `^`/`!^`/`$`/`!$` (starts/ends-with) or `in`/`rin` (containment) instead.
//!
//! Clients that need projection or regex do that client-side. Everything else — the
//! `query-filters` operators (incl. the `C` case-insensitive prefix), `order_by`, `get`,
//! `count`, `offset`, `limit` — is byte-identical to the C oracle.

mod filter;
mod options;
mod path;
mod value;

pub use filter::{compile_filters, CompiledFilters};
pub use options::{compile_options, CompiledOptions, QueryOptions};

use serde_json::Value;

/// A raw `query-filters` list (middleware form): `[name, op, value]` leaves and
/// `["OR", [branch, …]]` nodes. Handed verbatim to [`compile_filters`].
pub type QueryFilters = Vec<Value>;

/// The result of [`tnfilter`]: either the matched rows (post order/offset/limit) or, when
/// `query-options.count` is set, the count of matched rows.
#[derive(Debug, Clone, PartialEq)]
pub enum Filtered {
    /// Matched rows, in result order (the common case).
    Rows(Vec<Value>),
    /// The number of matched rows (`count=true`); offset/limit do not apply.
    Count(i64),
}

/// A filter-engine failure.
///
/// The variant tells the caller how to surface it: [`FilterError::Compile`] is bad query
/// *syntax* (unknown operator, malformed node, invalid option) and should become
/// `INVALID_PARAMS`; [`FilterError::Eval`] is a runtime evaluation failure (comparing
/// incomparable types, a non-string `startswith`/`endswith` source, an un-orderable sort
/// column) and should become `INTERNAL_ERROR` — mirroring Python, where the former is raised
/// by `compile_*` and the latter propagates uncaught out of `tnfilter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    /// Bad filter/option syntax — maps to `INVALID_PARAMS`.
    Compile(String),
    /// Runtime evaluation failure — maps to `INTERNAL_ERROR`.
    Eval(String),
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterError::Compile(m) => write!(f, "invalid query: {m}"),
            FilterError::Eval(m) => write!(f, "filter evaluation failed: {m}"),
        }
    }
}

impl std::error::Error for FilterError {}

/// Filter `data` with a pre-compiled query, returning the matched rows (or their count).
///
/// `data` is consumed **lazily** through its iterator and rows are read-only: each item is
/// tested against `filters` by borrowing it, and a matching row is **moved** into the result
/// unchanged (the unfiltered source is never materialized, and matches are never copied or
/// reshaped). `get` (with no `order_by`) short-circuits at the first match; `count` tallies
/// without retaining; with no `order_by` and a `limit`, only the requested page is kept.
/// With `order_by`, all matches are retained (sorting needs them). The post-filter pipeline
/// is `count` → `order` → `offset` → `limit`.
pub fn tnfilter<I>(
    data: I,
    filters: &CompiledFilters,
    options: &CompiledOptions,
) -> Result<Filtered, FilterError>
where
    I: IntoIterator<Item = Value>,
{
    // count: stream and tally matches; never retain. `shortcircuit` caps the tally at the
    // first match (get with no order_by).
    if options.count_flag() {
        let mut n: i64 = 0;
        for item in data {
            if filter::matches_all(&item, filters)? {
                n += 1;
                if options.shortcircuit() {
                    break;
                }
            }
        }
        return Ok(Filtered::Count(n));
    }

    // Bound retention to the requested page when there is no ordering (the page is just the
    // matches in source order); otherwise we must collect every match to sort.
    let cap: Option<usize> = if !options.has_order() && options.limit() > 0 {
        Some(options.offset().saturating_add(options.limit()))
    } else {
        None
    };

    let mut matched: Vec<Value> = Vec::new();
    for item in data {
        if filter::matches_all(&item, filters)? {
            matched.push(item);
            if options.shortcircuit() {
                break;
            }
            if let Some(c) = cap {
                if matched.len() >= c {
                    break;
                }
            }
        }
    }

    Ok(Filtered::Rows(options.apply(matched)?))
}

/// Test whether a single `item` matches all `filters` (the C engine's `match`, as a pure
/// predicate — without `select`, a match returns the row unchanged, so only the boolean
/// outcome is meaningful).
pub fn tnmatch(item: &Value, filters: &CompiledFilters) -> Result<bool, FilterError> {
    filter::matches_all(item, filters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn error_display() {
        assert!(FilterError::Compile("op".into()).to_string().contains("invalid query"));
        assert!(FilterError::Eval("cmp".into()).to_string().contains("cmp"));
    }

    #[test]
    fn count_branch_variants() {
        let data = || vec![json!({"n": 1}), json!({"n": 1}), json!({"n": 2})];
        let cf = compile_filters(&[json!(["n", "=", 1])]).unwrap();
        // count over all matches
        let co = compile_options(&serde_json::from_value(json!({"count": true})).unwrap()).unwrap();
        assert_eq!(tnfilter(data(), &cf, &co).unwrap(), Filtered::Count(2));
        // count + get → shortcircuit breaks the count at the first match
        let co = compile_options(&serde_json::from_value(json!({"count": true, "get": true})).unwrap())
            .unwrap();
        assert_eq!(tnfilter(data(), &cf, &co).unwrap(), Filtered::Count(1));
    }

    #[test]
    fn tnmatch_predicate() {
        let cf = compile_filters(&[json!(["n", "=", 1])]).unwrap();
        assert!(tnmatch(&json!({"n": 1}), &cf).unwrap());
        assert!(!tnmatch(&json!({"n": 2}), &cf).unwrap());
    }
}
