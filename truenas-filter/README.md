# truenas-filter

The TrueNAS middlewared `query-filters` / `query-options` engine, matching the `truenas_pyfilter`
C engine byte-for-byte. Used by `truenas-rpc`'s filterable methods; also usable standalone.

## Public API

- `compile_filters(&[Value]) -> Result<CompiledFilters, FilterError>` — compile a
  `query-filters` list (`[name, op, value]` leaves; `["OR", [...]]` nodes).
- `compile_options(&QueryOptions) -> Result<CompiledOptions, FilterError>`.
- `tnfilter<E, I>(data, &CompiledFilters, &CompiledOptions) -> Result<Filtered<E>, FilterError>`
  where `E: Serialize`, `I: IntoIterator<Item = E>`. Streams the data source lazily; returns
  `Filtered::Rows(Vec<E>)` or `Filtered::Count(i64)`. Matched rows are moved through unchanged
  (no projection), so the result is encodable to the JSON or XDR wire.
- `tnmatch(&Value, &CompiledFilters) -> Result<bool, FilterError>` — the predicate alone.
- `QueryOptions` (`get`, `count`, `order_by`, `offset`, `limit`), `Filtered<E>`, `FilterError`
  (`Compile` → `INVALID_PARAMS`; `Eval` → `INTERNAL_ERROR`).

## Semantics

Byte-for-byte with the C engine (gated by a differential corpus in `tests/conformance/`):
the middleware's comparison rules (`==`/`!=` total with a `bool ⊂ int ⊂ float` numeric tower;
`<`/`>`/… raise on incomparable operands), the operator set (`= != > >= < <= in nin rin rnin
^ !^ $ !$`, plus the `C` case-insensitive prefix), `OR`/`AND` nesting, dotted / indexed /
`*`-wildcard / escaped-dot paths, and `order_by` (`-` / `nulls_first:` / `nulls_last:`,
multi-key, stable).

The engine builds a `serde_json::Value` view of each row only for the fields a query reads
(often none); a struct's other fields are never serialized.

## Deviations (deliberate, documented)

- `query-options.select` is not supported (it is the only option that reshapes a row; omitting
  it keeps the row shape stable and the engine read-only).
- The `~` regex operator is not supported (no byte-identical guarantee against the middleware's
  regex dialect, and it
  would pull in a regex dependency). Use `^`/`!^`/`$`/`!$` or `in`/`rin`.

## Dependencies

`serde`, `serde_json`. `#![forbid(unsafe_code)]`; near-total line-coverage gated.
