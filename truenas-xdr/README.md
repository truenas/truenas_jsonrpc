# truenas-xdr

A serde-based XDR (RFC 4506) codec plus the TXDR binary frame — the **Codec** layer (layer 3) of the
[layer stack](../../ARCHITECTURE.md#layers) — for the TrueNAS JSON-RPC binary wire. Byte-exact against
the cross-language golden vectors.

## Public API

- `to_bytes` / `to_writer` / `serialized_size` — serialize.
- `from_bytes` / `from_bytes_exact` / `from_bytes_with(Strictness, …)` — deserialize.
- `XdrError`, `Strictness` (`Lenient` default / `Strict`).
- Opaque wrappers: `VarOpaque` (length-prefixed) and `FixedOpaque<N>` (fixed, no prefix) —
  needed because stock serde would encode `[u8; N]` / `Vec<u8>` as 4-byte ints.
- `frame` module: the TXDR request/reply **frame** — the in-body XDR envelope (`MAGIC`, `VERSION`,
  `RESERVED_PROC_MAX`, `build_request`, `parse_reply`, …).
- With the `derive` feature (default): `#[derive(XdrEnum)]` / `#[derive(XdrUnion)]` (re-exported
  from `truenas-xdr-derive`).

## Model

bincode-style and **non-self-describing**: the `Deserializer` is type-driven, so
`deserialize_any` / `deserialize_ignored_any` are unsupported — `#[serde(flatten)]` and
`serde_json::Value` cannot be decoded from XDR (matches the Zig/Python design; dynamic data
rides as a JSON-text `string<>`). `is_human_readable()` is `false`. XDR has no map type;
model dictionaries as `Vec<(K, V)>`. Range checks are always on; `Strict` additionally rejects
nonzero opaque padding and embedded NULs (the ZFS rules).

## Features

- `derive` (default) — pull the proc-macros. Opt out with `default-features = false` to drop
  the `truenas-xdr-derive` dependency entirely; then encode enums/unions with the manual
  `XdrEnum<E>` wrapper.

## Dependencies

`serde` (`default-features = false`, `+std`), `thiserror`, and (with `derive`)
`truenas-xdr-derive`. No `serde_json` at runtime. `#![forbid(unsafe_code)]`; 100% line-coverage
gated (the derive crate is excluded — its output is covered behaviorally here).
