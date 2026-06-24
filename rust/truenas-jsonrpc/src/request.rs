//! [`RequestCtx`] — the per-request handle a handler receives: progress emission,
//! audit-detail accumulation, and cooperative cancellation. Mirrors Python's
//! `RequestState`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde::Serialize;

use crate::error::JsonRpcError;
use crate::session::Session;
use crate::JSONRPC_VERSION;

/// A request id held in its wire-native form, formatted to text only on demand. The JSON wire's
/// id is already a string; the XDR wire's is 16 raw bytes (a UUID), which we format to the
/// canonical hyphenated string lazily — so a request that never reads its id (no audit, and the
/// handler ignores it) pays no stringification. (Authorization never reads the id; only the audit
/// record and a handler's [`id`](RequestCtx::id) / [`update_progress`](RequestCtx::update_progress)
/// do.)
enum ReqId {
    /// A notification (no id), or an id no consumer has materialized.
    None,
    /// The JSON wire's id — already text.
    Str(String),
    /// The XDR wire's 16 raw id bytes, formatted to the canonical UUID string on first read.
    Xdr([u8; 16], OnceLock<String>),
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
    audit_detail: Arc<Mutex<Option<String>>>,
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
    pub(crate) fn new(id: Option<String>, session: Arc<Session<S>>, cancel: Arc<AtomicBool>) -> Self {
        let id = id.map_or(ReqId::None, ReqId::Str);
        Self { id, session, cancel, audit_detail: Arc::new(Mutex::new(None)) }
    }

    /// Like [`new`](Self::new) but from the XDR wire's raw 16 id bytes — formatted to the
    /// canonical UUID string lazily (only if a handler reads [`id`](Self::id) or emits progress),
    /// so the hot path pays no stringification. `None` for an XDR notification.
    pub(crate) fn new_xdr(
        rid: Option<[u8; 16]>,
        session: Arc<Session<S>>,
        cancel: Arc<AtomicBool>,
    ) -> Self {
        let id = rid.map_or(ReqId::None, |b| ReqId::Xdr(b, OnceLock::new()));
        Self { id, session, cancel, audit_detail: Arc::new(Mutex::new(None)) }
    }

    /// A shared handle to the audit-detail slot, so the dispatch pipeline can read the
    /// runtime detail after the handler has run (and possibly moved `cx`).
    pub(crate) fn audit_handle(&self) -> Arc<Mutex<Option<String>>> {
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
        *self.audit_detail.lock().unwrap_or_else(PoisonError::into_inner) = Some(message.into());
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
        RequestCtx::new(id, session, Arc::new(AtomicBool::new(false)))
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
}
