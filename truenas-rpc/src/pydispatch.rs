//! The `PyDispatcher` seam — routes a `python:true` method's body to a Python handler.
//!
//! This is the pure, dependency-free contract (no PyO3): the dispatch core calls
//! [`PyDispatcher::dispatch`] for a python method, having already done routing, the
//! session gate, authorization, and audit — only the handler **body** crosses into Python.
//! The actual PyO3 implementation (acquire the GIL, call the Python callable, convert) lives
//! in a separate opt-in crate (`truenas-rpc-pyo3`); this trait is what it implements,
//! and a closure `impl` lets the core's python pipeline be unit-tested with a mock — with no
//! libpython linked.

use std::sync::Arc;

use serde_json::value::RawValue;

use crate::error::JsonRpcError;

/// The result of a python method body: either an encoded result or a JSON-RPC error,
/// plus an optional audit detail the body set (the Python `request_state.set_audit`).
pub struct PyResult {
    /// The success result or the error.
    pub outcome: PyOutcome,
    /// A runtime audit detail (joined with the method's static `audit_message`), if the
    /// body recorded one.
    pub audit_message: Option<String>,
}

/// The success/error half of a [`PyResult`].
pub enum PyOutcome {
    /// The handler's result, already encoded as JSON (spliced into the reply envelope).
    Ok(Box<RawValue>),
    /// The handler raised a `JsonRpcError` (status + message + optional data).
    Error(JsonRpcError),
}

/// A synchronous, `S`-erased in-process caller handed to a python body (via
/// [`PyDispatcher::dispatch`]) so it can call other registered methods — the `call(...)` path, the
/// analogue of a Rust handler's [`RequestCtx::call_named`](crate::RequestCtx::call_named). Sync
/// because the python side is sync and runs on the blocking pool; an **async** target isn't callable
/// this way and errors. `params_json` and the result are **JSON bytes** — the python side (msgspec)
/// owns the types, so the boundary is bytes and no `S` leaks across the (deliberately `S`-erased) seam.
pub trait InProcessCaller: Send + Sync {
    /// Call registered method `name` with JSON-encoded `params_json`, returning its result as bare
    /// JSON. `elevated` skips the role gate (full admin); otherwise it's applied against the session.
    fn call_json(
        &self,
        name: &str,
        params_json: &[u8],
        elevated: bool,
    ) -> Result<Box<RawValue>, JsonRpcError>;
}

/// Routes a python method's body to a Python handler. Implemented by the PyO3 bridge
/// crate; blanket-implemented for closures so the core can be tested with a mock.
pub trait PyDispatcher: Send + Sync {
    /// Run the `name` method's Python body with the (already JSON-encoded) `params_json`, a
    /// `session_view_json` snapshot, and `caller` — the in-process call handle a body uses to reach
    /// other registered methods. The core has already gated + authorized the call.
    fn dispatch(
        &self,
        name: &str,
        params_json: &[u8],
        session_view_json: &[u8],
        caller: Arc<dyn InProcessCaller>,
    ) -> PyResult;
}

impl<F> PyDispatcher for F
where
    F: Fn(&str, &[u8], &[u8], Arc<dyn InProcessCaller>) -> PyResult + Send + Sync,
{
    fn dispatch(
        &self,
        name: &str,
        params_json: &[u8],
        session_view_json: &[u8],
        caller: Arc<dyn InProcessCaller>,
    ) -> PyResult {
        (self)(name, params_json, session_view_json, caller)
    }
}
