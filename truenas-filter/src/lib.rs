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

mod extract;
mod filter;
mod options;
mod path;
mod value;

pub use filter::{compile_filters, CompiledFilters};
pub use options::{compile_options, CompiledOptions, QueryOptions};

use serde::Serialize;
use serde_json::Value;

/// A raw `query-filters` list (middleware form): `[name, op, value]` leaves and
/// `["OR", [branch, …]]` nodes. Handed verbatim to [`compile_filters`].
pub type QueryFilters = Vec<Value>;

/// The result of [`tnfilter`]: either the matched rows (post order/offset/limit) or, when
/// `query-options.count` is set, the count of matched rows.
///
/// Generic over the row type `E`: the engine evaluates filters/ordering against a
/// `serde_json::Value` *view* of each row (the byte-identical comparison semantics), but
/// carries the original typed `E` through to the result — so matches can be serialized to
/// **either** the JSON or the XDR wire (a dynamic `Value` can't be XDR-encoded). Pass
/// `E = serde_json::Value` to filter dynamic rows.
#[derive(Debug, Clone, PartialEq)]
pub enum Filtered<E> {
    /// Matched rows, in result order (the common case).
    Rows(Vec<E>),
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
/// `data` is consumed **lazily** through its iterator. Each item is serialized to a
/// `serde_json::Value` *view* once and tested/ordered against that view, while the original
/// typed item is carried through so a match is **moved** into the result unchanged — never
/// copied or reshaped (no `select`). The view is pruned to just the fields the query reads
/// (often none), so the unfiltered source is never materialized in full.
/// `get` (with no `order_by`) short-circuits at the first match; `count`
/// tallies without retaining; with no `order_by` and a `limit`, only the requested page is
/// kept; with `order_by`, all matches are retained (sorting needs them). The post-filter
/// pipeline is `count` → `order` → `offset` → `limit`.
///
/// With `E = serde_json::Value` the view is the row itself (dynamic filtering); with a typed
/// `E` the result is a `Vec<E>` that can be encoded to the JSON **or** XDR wire.
pub fn tnfilter<E, I>(
    data: I,
    filters: &CompiledFilters,
    options: &CompiledOptions,
) -> Result<Filtered<E>, FilterError>
where
    E: Serialize,
    I: IntoIterator<Item = E>,
{
    // Work out which fields the filters/order actually read, once, so each row's view carries
    // only those (or, when nothing is read, nothing at all) — see [`extract`].
    let needed = extract::compute_needed(filters, options);

    // count: stream and tally matches; never retain. `shortcircuit` caps the tally at the
    // first match (get with no order_by).
    if options.count_flag() {
        let mut n: i64 = 0;
        for item in data {
            if filter::matches_all(&extract::build_view(&item, &needed)?, filters)? {
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

    // Carry `(view, item)` for each match: the view drives ordering, the item is the result.
    let mut matched: Vec<(Value, E)> = Vec::new();
    for item in data {
        let v = extract::build_view(&item, &needed)?;
        if filter::matches_all(&v, filters)? {
            matched.push((v, item));
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

    #[test]
    fn unrepresentable_row_is_eval_error() {
        // A row whose `Serialize` fails → the view can't be built → FilterError::Eval. A filter
        // is required: with no filters/order the view is never built (`Needed::Nothing`), so the
        // failing `Serialize` would never be invoked.
        struct Unser;
        impl serde::Serialize for Unser {
            fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::Error;
                Err(S::Error::custom("not serializable"))
            }
        }
        let cf = compile_filters(&[json!(["x", "=", 1])]).unwrap();
        let co = compile_options(&QueryOptions::default()).unwrap();
        assert!(matches!(tnfilter(vec![Unser], &cf, &co), Err(FilterError::Eval(_))));
    }
}
