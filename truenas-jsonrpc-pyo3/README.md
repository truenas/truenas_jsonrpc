# truenas-jsonrpc-pyo3

The optional embedded-CPython bridge that runs `truenas-jsonrpc` `python:true` method bodies in
an embedded CPython interpreter, speaking the raw CPython C-API directly through `pyo3-ffi` (no
pyo3 framework, no proc-macros).

## What it provides

- `PyBridge` — implements the core's `PyDispatcher` seam. It holds a Python `dispatch`
  callable and, for each python-backed method, invokes
  `dispatch(name, params_json, session_json) -> (status, payload, audit)` while holding the GIL
  (a per-call `PyGILState_Ensure`/`Release` guard). The dispatch core runs python bodies on its
  blocking pool, so the GIL is only ever held off the async path (never across an `.await`).
- `BridgeError` — a bridge-level failure (e.g. the Python call raised or returned the wrong
  shape).

Params cross the boundary as JSON bytes (the same contract `api-specs/gen.py --python-out`
emits — Python decodes them with its own `msgspec`), so there is no `serde_json` ↔ `PyDict`
conversion. Per-method routing happens in Python via its `_METHODS` table; only the one
`dispatch` callable is registered.

## Dependencies / opt-in

`truenas-jsonrpc`, `serde_json`, and `pyo3-ffi` — the raw CPython C-API bindings plus libpython
linking (via its `pyo3-build-config` build dependency); **no** pyo3 framework and **no**
proc-macros. We call `Py_InitializeEx` ourselves, lazily on first use.

This crate is **not** in the workspace `default-members`: a plain `cargo build` / `cargo test`
links zero libpython. Opt in by depending on it — off by default, the consumer's choice.
The core's python *pipeline* is covered by a mock `PyDispatcher` in `truenas-jsonrpc`'s tests;
this crate is excluded from the line-coverage gate and tested with
`cargo test -p truenas-jsonrpc-pyo3` (needs libpython + `msgspec`).
