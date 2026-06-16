//! [`RequestCtx`] — the per-request handle a handler receives: progress emission,
//! audit-detail accumulation, and cooperative cancellation. Mirrors Python's
//! `RequestState`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::error::JsonRpcError;
use crate::session::Session;
use crate::JSONRPC_VERSION;

/// Per-request context handed to a handler.
///
/// `update_progress` emits a `$/progress` notification on the session's back channel;
/// `set_audit` accumulates a runtime audit detail; `is_cancelled`/`raise_if_cancelled`
/// observe a `$/cancelRequest` (cooperative — the handler must check it).
pub struct RequestCtx<S> {
    id: Option<String>,
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

    /// This request's id (`None` for a notification).
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
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
        *self.audit_detail.lock().unwrap() = Some(message.into());
    }

    /// Emit a `$/progress` notification for this request. A no-op for a notification
    /// (no id) — mirrors Python.
    pub fn update_progress(
        &self,
        percent: Option<f64>,
        description: Option<&str>,
        extra: Option<serde_json::Value>,
    ) {
        let Some(id) = self.id.as_deref() else { return };
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
