# truenas_jsonrpc — Rust implementation

A Rust port of the TrueNAS JSON-RPC 2.0 stack (the Python reference lives in
[`../python/`](../python/)). This is a Cargo workspace; the language-agnostic wire contract is
in [`../ARCHITECTURE.md`](../ARCHITECTURE.md) and the project overview in
[`../README.md`](../README.md).

## Crates

- **`truenas-jsonrpc`** — the transport-agnostic **dispatch core** (Python's `JSONRPCProtocol`):
  envelope parse/validation, the session lifecycle + gate, the authorize → handler → audit
  pipeline, the `$/` control messages, pub/sub (`SERVER_CLIENT` subscriptions), and filterable
  (query) methods. Sync handlers run on `spawn_blocking`; async handlers are awaited (a
  Rust-only addition — Python has no async methods).
- **`truenas-filter`** — the `query-filters` / `query-options` **engine**, a port of the
  `truenas_pyfilter` C extension. Consumed by `truenas-jsonrpc`'s filterable methods; also
  usable standalone.

## Parity & proof

A/B **differential conformance** against the Python reference is the gating proof: Python
generators (`conformance/generate.py` and `truenas-filter/conformance/generate.py`) run a
fixed corpus through the reference implementation / C oracle and emit golden JSON; the Rust
tests replay it and assert **byte-identical** results. Line coverage is gated at 100%
(`./coverage.sh`).

## Filter-engine deviations

`truenas-filter` matches the C engine (`truenas_pyfilter`) byte-for-byte for `query-filters`
and `query-options` — **with two deliberate exceptions:**

- **`query-options.select` is not supported.** `select` is the only option that *reshapes* a
  row (project / rename / sub-select fields). Omitting it keeps every returned row's shape
  stable — equal to the method's declared `entry` type — and lets the engine stay
  **read-only**: it filters, orders, and slices, then passes rows through **unchanged**.
  Concretely, `tnfilter` takes `IntoIterator<Item = Value>` and *moves* a matched row into the
  result; it never re-serializes a row per item or builds a projected object, which a
  `select`-capable dynamic engine would force. Clients that need column projection do it
  client-side.

- **The `~` regex operator is not supported.** It is the only operator whose semantics can't
  be guaranteed byte-identical — Rust's `regex` crate is not Python's `re` (no
  backreferences/lookaround, a different dialect) — and the only one that would pull in a
  regex dependency. Use `^` / `!^` / `$` / `!$` (starts/ends-with) or `in` / `rin`
  (containment) instead, or filter client-side.

Both are parity gaps vs. the Python/middleware `filter_list`. Everything else is identical to
the oracle: the remaining filter operators (`=` `!=` `>` `>=` `<` `<=` `in` `nin` `rin` `rnin`
`^` `!^` `$` `!$`, incl. the `C` case-insensitive prefix), `OR`/`AND` nesting, dotted /
indexed / `*`-wildcard / escaped-dot path traversal, `order_by` (`-` / `nulls_first:` /
`nulls_last:`, multi-key, stable), `get`, `count`, `offset`, `limit`, and the Python
comparison semantics (numeric tower; `==`/`!=` total; `<`/`>`/… raise on incomparable operands).

## Build & test

```sh
cargo test --all-features --locked          # spine + pub/sub + filterable + both A/B goldens
cargo clippy --all-targets --all-features -- -D warnings
./coverage.sh 100                            # native source-based coverage, gated at 100%
```

Regenerating the golden corpora (requires the Python reference + the installed
`truenas_pyfilter`):

```sh
python3 conformance/generate.py                  # protocol A/B golden
python3 truenas-filter/conformance/generate.py   # filter-engine A/B golden
```
