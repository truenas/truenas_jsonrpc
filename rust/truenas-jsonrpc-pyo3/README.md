# truenas-jsonrpc-pyo3

The optional PyO3 bridge that runs `truenas-jsonrpc` `python:true` method bodies in an
embedded CPython interpreter. The Rust analogue of the Zig `pybridge`.

## What it provides

- `PyBridge` — implements the core's `PyDispatcher` seam. It holds a Python `dispatch`
  callable and, for each python-backed method, invokes
  `dispatch(name, params_json, session_json) -> (status, payload, audit)` inside
  `Python::with_gil`. The dispatch core runs python bodies on its blocking pool, so the GIL is
  only ever held off the async path (never across an `.await`).
- `BridgeError` — a bridge-level failure (e.g. the Python call raised or returned the wrong
  shape).

Params cross the boundary as JSON bytes (the same contract `api-specs/gen.py --python-out`
emits — Python decodes them with its own `msgspec`), so there is no `serde_json` ↔ `PyDict`
conversion. Per-method routing happens in Python via its `_METHODS` table; only the one
`dispatch` callable is registered.

## Dependencies / opt-in

`truenas-jsonrpc`, `serde_json`, and `pyo3` (`auto-initialize`, which starts the embedded
interpreter on first use). `pyo3` transitively links libpython.

This crate is **not** in the workspace `default-members`: a plain `cargo build` / `cargo test`
links zero libpython. Opt in by depending on it (the consumer's choice, like Zig's `-Dpython`).
The core's python *pipeline* is covered by a mock `PyDispatcher` in `truenas-jsonrpc`'s tests;
this crate is excluded from the line-coverage gate and tested with
`cargo test -p truenas-jsonrpc-pyo3` (needs libpython + `msgspec`).
