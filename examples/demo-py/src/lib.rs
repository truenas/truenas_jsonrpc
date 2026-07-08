//! `demo-py` — an end-to-end proof of the generated **Python (msgspec)** surface for
//! `examples/demo`'s spec.
//!
//! `build.rs` emits `demo_{types,client,server}.py` into `$OUT_DIR`; the integration tests under
//! `tests/` add `$OUT_DIR` to `sys.path` and drive them against the live Rust core:
//!
//! - [`client_roundtrip`](../../tests/client_roundtrip.rs): the generated `DemoClient` (msgspec) over
//!   a `truenas-rpc-pyclient` `RawClient`, against a live `TruenasRpcServer`.
//! - [`server_dispatch`](../../tests/server_dispatch.rs): a `python:true` body run by the embedded
//!   `truenas-rpc-pyo3` bridge through the generated `dispatch(name, params, session, call)`, calling
//!   back into the core via `call`.
//!
//! The two live in separate test binaries so each drives the interpreter through exactly one of the
//! Python-linking crates (the client shim vs the embedded bridge) — no shared-process init to
//! coordinate. The lib itself is empty (the artifacts are `.py` text, not Rust).
