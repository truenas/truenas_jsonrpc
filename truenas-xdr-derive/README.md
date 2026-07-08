# truenas-xdr-derive

Proc-macro crate for `truenas-xdr`: `#[derive(XdrEnum)]` and `#[derive(XdrUnion)]`.

## Why it exists

XDR enum/union discriminants are explicit `#[repr(i32)]` values, but stock serde only exposes
a variant's *declaration index* — wrong for any enum with a gap (e.g. a value of `4` at the
third variant). These derives read the declared `#[repr(i32)]` discriminants and encode them
byte-exactly. Limitation: literal discriminants only; non-literal const expressions fall back
to the manual `XdrEnum<E>` wrapper in `truenas-xdr`.

A proc-macro must be its own crate (a language rule), which is the only reason this is separate.

## Use it through `truenas-xdr`

Do not depend on this crate directly. Enable `truenas-xdr`'s `derive` feature (on by default),
which re-exports the macros:

```toml
truenas-xdr = "*"                       # derive on by default
# or, if default-features were disabled:
truenas-xdr = { version = "*", features = ["derive"] }
```

## Dependencies

`syn`, `quote`, `proc-macro2` (already in the workspace lock via other derives, so no new
transitive crates). Excluded from the line-coverage gate — proc-macro output is covered
behaviorally by `truenas-xdr`'s tests.
