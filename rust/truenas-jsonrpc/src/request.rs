//! [`RequestCtx`] — the per-request handle a handler receives: progress emission,
//! audit-detail accumulation, and cooperative cancellation. Mirrors Python's
//! `RequestState`.

use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use async_trait::async_trait;
use serde::Serialize;

use crate::error::JsonRpcError;
use crate::session::Session;
use crate::JSONRPC_VERSION;

/// The dispatch-core seam that lets a handler invoke another **registered method in-process**
/// (see [`RequestCtx::call_op`]). Implemented by the protocol over its op-table; held by
/// [`RequestCtx`] only when the ctx was built by `dispatch` (`None` otherwise). Kept here, as a
/// trait, so this module needs no concrete protocol type.
#[async_trait]
pub(crate) trait InternalCaller<S>: Send + Sync {
    /// Invoke the method registered at op-table key `op_id` on already-decoded `args`, returning
    /// its boxed typed result. `elevated` skips the role gate (full-admin); otherwise the gate is
    /// applied against `cx`'s session. `cx` is the (cloned) caller context the inner handler runs
    /// under, so nested internal calls and progress/cancel all work.
    async fn call_op(
        &self,
        op_id: u32,
        args: Box<dyn Any + Send>,
        cx: RequestCtx<S>,
        elevated: bool,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError>;
    /// Like [`call_op`](Self::call_op) but selects the method by name (the JSON op-table key).
    async fn call_named(
        &self,
        name: String,
        args: Box<dyn Any + Send>,
        cx: RequestCtx<S>,
        elevated: bool,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError>;
}

/// A request id held in its wire-native form, formatted to text only on demand. The JSON wire's
/// id is already a string; the XDR wire's is 16 raw bytes (a UUID), which we format to the
/// canonical hyphenated string lazily — so a request that never reads its id (no audit, and the
/// handler ignores it) pays no stringification. (Authorization never reads the id; only the audit
/// record and a handler's [`id`](RequestCtx::id) / [`update_progress`](RequestCtx::update_progress)
/// do.)
#[derive(Clone)]
enum ReqId {
    /// A notification (no id), or an id no consumer has materialized.
    None,
    /// The JSON wire's id — already text. `Arc<str>` so [`RequestCtx`] clones cheaply (internal
    /// calls clone the ctx to dispatch a sync op onto `spawn_blocking`).
    Str(Arc<str>),
    /// The XDR wire's 16 raw id bytes, formatted to the canonical UUID string on first read; the
    /// `OnceLock` is `Arc`-shared so a clone shares the cached formatting.
    Xdr([u8; 16], Arc<OnceLock<String>>),
}

impl ReqId {
    /// The id as text, formatting the XDR byte form on first access (then cached).
    fn as_str(&self) -> Option<&str> {
        match self {
            ReqId::None => None,
            ReqId::Str(s) => Some(s),
            ReqId::Xdr(bytes, cell) => {
                Some(cell.get_or_init(|| uuid::Uuid::from_bytes(*bytes).to_string()))
            }
        }
    }
}

/// Per-request context handed to a handler.
///
/// `update_progress` emits a `$/progress` notification on the session's back channel;
/// `set_audit` accumulates a runtime audit detail; `is_cancelled`/`raise_if_cancelled`
/// observe a `$/cancelRequest` (cooperative — the handler must check it).
pub struct RequestCtx<S> {
    id: ReqId,
    session: Arc<Session<S>>,
    cancel: Arc<AtomicBool>,
    audit_detail: Option<Arc<Mutex<Option<String>>>>,
    /// The in-process call seam — `Some` only for a ctx built by `dispatch`. Lets a handler invoke
    /// other registered methods via [`call_op`](Self::call_op).
    caller: Option<Arc<dyn InternalCaller<S>>>,
}

// Manual `Clone` (not derived) so it holds for any `S` — every field is `Arc`/small, no `S: Clone`.
// A clone is cheap (Arc bumps); the in-process call path clones the ctx to run a sync op on the
// blocking pool.
impl<S> Clone for RequestCtx<S> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            session: self.session.clone(),
            cancel: self.cancel.clone(),
            audit_detail: self.audit_detail.clone(),
            caller: self.caller.clone(),
        }
    }
}

#[derive(Serialize)]
struct ProgressParams<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ProgressEnvelope<'a> {
    jsonrpc: &'static str,
    method: &'static str,
    params: ProgressParams<'a>,
}

impl<S> RequestCtx<S> {
    pub(crate) fn new(
        id: Option<String>,
        session: Arc<Session<S>>,
        cancel: Arc<AtomicBool>,
        audit: bool,
        caller: Option<Arc<dyn InternalCaller<S>>>,
    ) -> Self {
        let id = id.map_or(ReqId::None, |s| ReqId::Str(s.into()));
        Self {
            id,
            session,
            cancel,
            audit_detail: audit.then(|| Arc::new(Mutex::new(None))),
            caller,
        }
    }

    /// Like [`new`](Self::new) but from the XDR wire's raw 16 id bytes — formatted to the
    /// canonical UUID string lazily (only if a handler reads [`id`](Self::id) or emits progress),
    /// so the hot path pays no stringification. `None` for an XDR notification.
    pub(crate) fn new_xdr(
        rid: Option<[u8; 16]>,
        session: Arc<Session<S>>,
        cancel: Arc<AtomicBool>,
        audit: bool,
        caller: Option<Arc<dyn InternalCaller<S>>>,
    ) -> Self {
        let id = rid.map_or(ReqId::None, |b| ReqId::Xdr(b, Arc::new(OnceLock::new())));
        Self {
            id,
            session,
            cancel,
            audit_detail: audit.then(|| Arc::new(Mutex::new(None))),
            caller,
        }
    }

    /// A shared handle to the audit-detail slot, so the dispatch pipeline can read the
    /// runtime detail after the handler has run (and possibly moved `cx`).
    pub(crate) fn audit_handle(&self) -> Option<Arc<Mutex<Option<String>>>> {
        self.audit_detail.clone()
    }

    /// The owning session.
    pub fn session(&self) -> &Arc<Session<S>> {
        &self.session
    }

    /// This request's id (`None` for a notification). On the XDR wire this lazily formats the
    /// raw id bytes to the canonical UUID string on first call.
    pub fn id(&self) -> Option<&str> {
        self.id.as_str()
    }

    /// Whether this request has been cancelled (cooperative).
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// `Err(REQUEST_CANCELLED)` if cancelled, else `Ok(())` — for `?` in a handler.
    pub fn raise_if_cancelled(&self) -> Result<(), JsonRpcError> {
        if self.is_cancelled() {
            Err(JsonRpcError::cancelled())
        } else {
            Ok(())
        }
    }

    /// Record a runtime audit detail (joined with the method's static `audit_message`).
    /// Last write wins.
    pub fn set_audit(&self, message: impl Into<String>) {
        // Only audited methods allocate the slot; for the rest the detail is never read, so drop it.
        if let Some(detail) = &self.audit_detail {
            *detail.lock().unwrap_or_else(PoisonError::into_inner) = Some(message.into());
        }
    }

    /// Call another **registered method in-process** by its op-table key, on already-decoded `args`
    /// (a `Box<dyn Any + Send>` of the method's `Accepts`), returning its boxed typed result
    /// (`Box<dyn Any + Send>` of `Returns`) — no wire round-trip, no re-encode. Runs **as the
    /// authenticated caller**: the method's role gate is applied against this request's session, so
    /// a caller lacking the role is denied. A **sync** target runs on the blocking pool (a blocking
    /// handler can't stall the runtime, and concurrent internal calls run in parallel); an **async**
    /// target runs inline. Errors if the ctx has no call seam (built outside `dispatch`), the op is
    /// unknown, or the target is not a plain request/response method.
    pub async fn call_op(
        &self,
        op_id: u32,
        args: Box<dyn Any + Send>,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        self.caller()?.call_op(op_id, args, self.clone(), false).await
    }

    /// Like [`call_op`](Self::call_op) but **elevated** — full privileges, skipping the role gate,
    /// for when a handler needs privileged internal state to serve a lesser-privileged caller. The
    /// named call site is the security-review surface; internal calls are **not audited** by default
    /// (only under the server's opt-in elevated-audit policy).
    pub async fn call_op_elevated(
        &self,
        op_id: u32,
        args: Box<dyn Any + Send>,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        self.caller()?.call_op(op_id, args, self.clone(), true).await
    }

    /// [`call_op`](Self::call_op) by method **name** (the JSON op-table key).
    pub async fn call_named(
        &self,
        name: &str,
        args: Box<dyn Any + Send>,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        self.caller()?.call_named(name.to_owned(), args, self.clone(), false).await
    }

    /// [`call_op_elevated`](Self::call_op_elevated) by method **name**.
    pub async fn call_named_elevated(
        &self,
        name: &str,
        args: Box<dyn Any + Send>,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        self.caller()?.call_named(name.to_owned(), args, self.clone(), true).await
    }

    fn caller(&self) -> Result<&Arc<dyn InternalCaller<S>>, JsonRpcError> {
        self.caller
            .as_ref()
            .ok_or_else(|| JsonRpcError::internal("no in-process call context"))
    }

    /// Emit a `$/progress` notification for this request. A no-op for a notification
    /// (no id) — mirrors Python.
    pub fn update_progress(
        &self,
        percent: Option<f64>,
        description: Option<&str>,
        extra: Option<serde_json::Value>,
    ) {
        let Some(id) = self.id.as_str() else { return };
        let env = ProgressEnvelope {
            jsonrpc: JSONRPC_VERSION,
            method: "$/progress",
            params: ProgressParams { id, percent, description, extra },
        };
        if let Ok(bytes) = serde_json::to_vec(&env) {
            self.session.outbound().send(bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{NullOutbound, Session, SessionId};

    fn ctx(id: Option<String>) -> RequestCtx<()> {
        let session =
            Arc::new(Session::new(SessionId::nil(), "t".into(), Some(()), Arc::new(NullOutbound)));
        RequestCtx::new(id, session, Arc::new(AtomicBool::new(false)), false, None)
    }

    #[test]
    fn id_text_passthrough_and_notification_is_none() {
        // A JSON-wire id is text as-is (`ReqId::Str`); a request with no id is a notification —
        // `id()` is `None` and `update_progress` is a no-op (both reaching `ReqId::None`).
        assert_eq!(ctx(Some("abc".into())).id(), Some("abc"));
        let note = ctx(None);
        assert_eq!(note.id(), None);
        note.update_progress(Some(50.0), None, None); // no id → no notification emitted
    }

    #[test]
    fn audit_detail_slot_is_allocated_only_when_audited() {
        let mk =
            || Arc::new(Session::new(SessionId::nil(), "t".into(), Some(()), Arc::new(NullOutbound)));
        // Audited: the slot exists; `set_audit` records it and the pipeline reads it back.
        let audited = RequestCtx::<()>::new(None, mk(), Arc::new(AtomicBool::new(false)), true, None);
        assert!(audited.audit_handle().is_some());
        audited.set_audit("did the thing");
        let got = audited.audit_handle().unwrap().lock().unwrap().clone();
        assert_eq!(got.as_deref(), Some("did the thing"));
        // Unaudited: no slot — `set_audit` is a silent no-op and the handle is `None`.
        let plain = ctx(None);
        assert!(plain.audit_handle().is_none());
        plain.set_audit("dropped");
    }

    #[tokio::test]
    async fn in_process_call_without_a_dispatch_context_errors() {
        // A ctx built outside `dispatch` carries no caller seam (`caller = None`), so an in-process
        // call has nothing to dispatch into.
        let cx = ctx(None);
        cx.call_op(1, Box::new(())).await.unwrap_err();
    }
}
