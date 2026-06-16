//! [`JsonRpcProtocol`] — the dispatch core (Python's `JSONRPCProtocol`), its
//! [`JsonRpcProtocolBuilder`], the async [`JsonRpcProtocol::dispatch`] seam, and the `$/`
//! control messages.
//!
//! `dispatch` is `async` and **branches on the method kind**: a sync [`JsonRpcMethod`]
//! runs its whole pipeline (decode → authorize → handler → audit) on a `spawn_blocking`
//! worker (Python's `ThreadPoolExecutor`); an [`AsyncJsonRpcMethod`] is awaited.

use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::{to_raw_value, RawValue};
use serde_json::{json, Value};

use crate::envelope::{self, ParsedRequest};
use crate::error::{Error, ErrorCode, JsonRpcError, Result};
use crate::method::{
    decode_params, encode_result, AsyncJsonRpcMethod, JsonRpcMethod, Method, MethodDef, MethodImpl,
    MethodMeta,
};
use crate::request::RequestCtx;
use crate::session::{Clock, IdGen, Outbound, Session, SessionId, SystemClock, UuidGen};
use crate::types::{AuthorizationResponse, JsonRpcRequest, MessageDirection, SessionLifecycle};

const CANCEL_METHOD: &str = "$/cancelRequest";
const SERVERINFO_METHOD: &str = "$/serverInfo";
const SESSION_SETUP_METHOD: &str = "$/sessionSetup";
const SESSION_SETUP_CONTINUE_METHOD: &str = "$/sessionSetupContinue";
const SESSION_CLOSE_METHOD: &str = "$/sessionClose";

/// The result of dispatching one inbound message.
pub enum Dispatched {
    /// Send these wire bytes back (a success or error response).
    Reply(Vec<u8>),
    /// Nothing to send (a notification, or a suppressed reply).
    Nothing,
}

impl Dispatched {
    /// The reply bytes, if any (`None` for [`Dispatched::Nothing`]).
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            Dispatched::Reply(b) => Some(b),
            Dispatched::Nothing => None,
        }
    }
}

/// The target of a `$/cancelRequest`, passed to the authorizer so policy can enforce
/// session-scoped "cancel only your own" rules.
#[derive(Clone, Copy, Debug)]
pub enum CancelTarget {
    Request { session_id: SessionId },
    Subscription { session_id: SessionId },
}

// --- configurable hooks (mirroring Python's register_* handlers) -------------

/// Authorizes a call. `target` is `Some` only for `$/cancelRequest`. Returning a denial
/// yields `NOT_AUTHORIZED` and skips the handler. Implemented for any matching closure.
pub trait Authorizer<S>: Send + Sync {
    fn authorize(
        &self,
        request: &JsonRpcRequest,
        session: &Session<S>,
        target: Option<CancelTarget>,
    ) -> AuthorizationResponse;
}

impl<S, F> Authorizer<S> for F
where
    F: Fn(&JsonRpcRequest, &Session<S>, Option<CancelTarget>) -> AuthorizationResponse + Send + Sync,
{
    fn authorize(
        &self,
        request: &JsonRpcRequest,
        session: &Session<S>,
        target: Option<CancelTarget>,
    ) -> AuthorizationResponse {
        (self)(request, session, target)
    }
}

/// Audit sink. Called for every audited method call + control op (success, error, or
/// denial). `response` is the response envelope as a `Value`, with secret fields redacted.
pub trait AuditSink<S>: Send + Sync {
    fn audit(
        &self,
        request: &JsonRpcRequest,
        response: &Value,
        session: &Session<S>,
        audit_message: Option<&str>,
    );
}

impl<S, F> AuditSink<S> for F
where
    F: Fn(&JsonRpcRequest, &Value, &Session<S>, Option<&str>) + Send + Sync,
{
    fn audit(
        &self,
        request: &JsonRpcRequest,
        response: &Value,
        session: &Session<S>,
        audit_message: Option<&str>,
    ) {
        (self)(request, response, session, audit_message)
    }
}

/// Optional active-abort callback, invoked after an authorized `$/cancelRequest` sets the
/// target request's cooperative cancel flag (e.g. close a socket to unblock I/O).
pub trait Canceller<S>: Send + Sync {
    fn cancel(&self, request: &JsonRpcRequest, session: &Session<S>);
}

impl<S, F> Canceller<S> for F
where
    F: Fn(&JsonRpcRequest, &Session<S>) + Send + Sync,
{
    fn cancel(&self, request: &JsonRpcRequest, session: &Session<S>) {
        (self)(request, session)
    }
}

/// Handler for the unauthenticated `$/serverInfo` probe.
pub trait ServerInfoHandler<S>: Send + Sync {
    fn server_info(&self, session: &Session<S>) -> std::result::Result<Value, JsonRpcError>;
}

impl<S, F> ServerInfoHandler<S> for F
where
    F: Fn(&Session<S>) -> std::result::Result<Value, JsonRpcError> + Send + Sync,
{
    fn server_info(&self, session: &Session<S>) -> std::result::Result<Value, JsonRpcError> {
        (self)(session)
    }
}

/// Erased `$/sessionSetup` / `$/sessionSetupContinue` handler: authenticates, sets the
/// session's server-internal identity as a side effect, and returns the next lifecycle +
/// the client-facing result. Provided as a closure
/// `Fn(Accepts, &Session<S>) -> Result<(SessionLifecycle, Returns), JsonRpcError>`.
trait ErasedSetup<S>: Send + Sync {
    fn handle(
        &self,
        params: Option<&RawValue>,
        session: &Session<S>,
    ) -> std::result::Result<(SessionLifecycle, Box<RawValue>), JsonRpcError>;
}

struct ClosureSetup<A, R, F> {
    f: F,
    _p: PhantomData<fn() -> (A, R)>,
}

impl<S, A, R, F> ErasedSetup<S> for ClosureSetup<A, R, F>
where
    S: Send + Sync + 'static,
    A: DeserializeOwned + Send + 'static,
    R: Serialize,
    F: Fn(A, &Session<S>) -> std::result::Result<(SessionLifecycle, R), JsonRpcError>
        + Send
        + Sync,
{
    fn handle(
        &self,
        params: Option<&RawValue>,
        session: &Session<S>,
    ) -> std::result::Result<(SessionLifecycle, Box<RawValue>), JsonRpcError> {
        let accepts: A = decode_params(params)?;
        let (lifecycle, returns) = (self.f)(accepts, session)?;
        Ok((lifecycle, encode_result(&returns)?))
    }
}

struct SetupSlot<S> {
    meta: MethodMeta,
    handler: Arc<dyn ErasedSetup<S>>,
}

struct Inflight {
    cancel: Arc<AtomicBool>,
    session_id: SessionId,
}

// --- builder -----------------------------------------------------------------

/// Builds a [`JsonRpcProtocol`] (Python's `JSONRPCProtocol(...)` + `register_*`). Frozen
/// by [`build`](Self::build); the result is safe for concurrent dispatch.
pub struct JsonRpcProtocolBuilder<S> {
    name: Arc<str>,
    version: Arc<str>,
    methods: HashMap<Arc<str>, Arc<Method<S>>>,
    authorizer: Option<Arc<dyn Authorizer<S>>>,
    audit_sink: Option<Arc<dyn AuditSink<S>>>,
    canceller: Option<Arc<dyn Canceller<S>>>,
    server_info: Option<Arc<dyn ServerInfoHandler<S>>>,
    setup: Option<SetupSlot<S>>,
    setup_continue: Option<SetupSlot<S>>,
    id_gen: Arc<dyn IdGen>,
    clock: Arc<dyn Clock>,
}

impl<S: Send + Sync + 'static> JsonRpcProtocolBuilder<S> {
    /// `name` (the `$/negotiate` discriminator) and `version` form the protocol identity.
    pub fn new(name: impl Into<Arc<str>>, version: impl Into<Arc<str>>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            methods: HashMap::new(),
            authorizer: None,
            audit_sink: None,
            canceller: None,
            server_info: None,
            setup: None,
            setup_continue: None,
            id_gen: Arc::new(UuidGen),
            clock: Arc::new(SystemClock),
        }
    }

    fn insert(&mut self, method: Method<S>) -> Result<()> {
        let name = method.meta.name.clone();
        if name.starts_with("rpc.") || name.starts_with("$/") {
            return Err(Error::ReservedName(name.to_string()));
        }
        if self.methods.contains_key(&name) {
            return Err(Error::DuplicateMethod(name.to_string()));
        }
        self.methods.insert(name, Arc::new(method));
        Ok(())
    }

    /// Register a synchronous request method.
    pub fn method<F, A, R>(mut self, method: JsonRpcMethod<F>) -> Result<Self>
    where
        F: Fn(A, &RequestCtx<S>) -> std::result::Result<R, JsonRpcError> + Send + Sync + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
    {
        self.insert(method.erase::<S, A, R>())?;
        Ok(self)
    }

    /// Register an async request method.
    pub fn async_method<F, A, R, Fut>(mut self, method: AsyncJsonRpcMethod<F>) -> Result<Self>
    where
        F: Fn(A, RequestCtx<S>) -> Fut + Send + Sync + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + Send + 'static,
        Fut: Future<Output = std::result::Result<R, JsonRpcError>> + Send + 'static,
    {
        self.insert(method.erase::<S, A, R, Fut>())?;
        Ok(self)
    }

    /// Set the authorization handler.
    pub fn authorizer(mut self, authorizer: impl Authorizer<S> + 'static) -> Self {
        self.authorizer = Some(Arc::new(authorizer));
        self
    }

    /// Set the audit sink.
    pub fn audit_sink(mut self, sink: impl AuditSink<S> + 'static) -> Self {
        self.audit_sink = Some(Arc::new(sink));
        self
    }

    /// Set the active-abort cancellation handler.
    pub fn cancellation(mut self, canceller: impl Canceller<S> + 'static) -> Self {
        self.canceller = Some(Arc::new(canceller));
        self
    }

    /// Enable the unauthenticated `$/serverInfo` probe.
    pub fn server_info(mut self, handler: impl ServerInfoHandler<S> + 'static) -> Self {
        self.server_info = Some(Arc::new(handler));
        self
    }

    /// Enable `$/sessionSetup` (and optionally `$/sessionSetupContinue`) authentication.
    /// `def` carries audit/secret-field metadata (setup is always audited, redacted).
    pub fn session_setup<F, A, R>(mut self, def: MethodDef, handler: F) -> Self
    where
        F: Fn(A, &Session<S>) -> std::result::Result<(SessionLifecycle, R), JsonRpcError>
            + Send
            + Sync
            + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
    {
        self.setup = Some(SetupSlot {
            meta: def.into_meta(MessageDirection::ClientServer),
            handler: Arc::new(ClosureSetup { f: handler, _p: PhantomData }),
        });
        self
    }

    /// Set the multi-step `$/sessionSetupContinue` handler.
    pub fn session_setup_continue<F, A, R>(mut self, def: MethodDef, handler: F) -> Self
    where
        F: Fn(A, &Session<S>) -> std::result::Result<(SessionLifecycle, R), JsonRpcError>
            + Send
            + Sync
            + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
    {
        self.setup_continue = Some(SetupSlot {
            meta: def.into_meta(MessageDirection::ClientServer),
            handler: Arc::new(ClosureSetup { f: handler, _p: PhantomData }),
        });
        self
    }

    /// Override the id generator (for deterministic tests / the A/B harness).
    pub fn id_gen(mut self, id_gen: impl IdGen + 'static) -> Self {
        self.id_gen = Arc::new(id_gen);
        self
    }

    /// Override the clock (for deterministic audit timestamps).
    pub fn clock(mut self, clock: impl Clock + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Freeze into a [`JsonRpcProtocol`].
    pub fn build(self) -> JsonRpcProtocol<S> {
        let has_session_setup = self.setup.is_some();
        JsonRpcProtocol {
            name: self.name,
            version: self.version,
            methods: self.methods,
            authorizer: self.authorizer,
            audit_sink: self.audit_sink,
            canceller: self.canceller,
            server_info: self.server_info,
            setup: self.setup,
            setup_continue: self.setup_continue,
            has_session_setup,
            id_gen: self.id_gen,
            clock: self.clock,
            inflight: Mutex::new(HashMap::new()),
            never_cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

// --- protocol ----------------------------------------------------------------

/// The dispatch core — Python's `JSONRPCProtocol`. Build once; drive
/// [`dispatch`](Self::dispatch) with framed bytes + a per-connection [`Session`].
pub struct JsonRpcProtocol<S> {
    name: Arc<str>,
    version: Arc<str>,
    methods: HashMap<Arc<str>, Arc<Method<S>>>,
    authorizer: Option<Arc<dyn Authorizer<S>>>,
    audit_sink: Option<Arc<dyn AuditSink<S>>>,
    canceller: Option<Arc<dyn Canceller<S>>>,
    server_info: Option<Arc<dyn ServerInfoHandler<S>>>,
    setup: Option<SetupSlot<S>>,
    setup_continue: Option<SetupSlot<S>>,
    has_session_setup: bool,
    id_gen: Arc<dyn IdGen>,
    #[allow(dead_code)] // used by audit timestamping once the audit record carries time
    clock: Arc<dyn Clock>,
    inflight: Mutex<HashMap<String, Inflight>>,
    /// A shared always-false flag handed to non-cancellable requests so they don't each
    /// allocate a cancel `Arc`.
    never_cancel: Arc<AtomicBool>,
}

impl<S: Send + Sync + 'static> JsonRpcProtocol<S> {
    /// Start building a protocol.
    pub fn builder(
        name: impl Into<Arc<str>>,
        version: impl Into<Arc<str>>,
    ) -> JsonRpcProtocolBuilder<S> {
        JsonRpcProtocolBuilder::new(name, version)
    }

    /// The protocol's `name` (the `$/negotiate` discriminator).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The protocol/API contract version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Whether `$/sessionSetup` authentication is configured (a network transport
    /// requires this).
    pub fn has_session_setup(&self) -> bool {
        self.has_session_setup
    }

    /// Create a fresh [`Session`] for a connection. `out` is the back-channel sink.
    pub fn new_session(&self, server_state: Option<S>, out: Arc<dyn Outbound>) -> Arc<Session<S>> {
        Arc::new(Session::new(self.id_gen.new_id(), self.name.clone(), server_state, out))
    }

    /// Mark a session `CLOSED` (and, later, drop its subscriptions). Call on socket drop.
    pub fn close_session(&self, session: &Session<S>) {
        session.set_lifecycle(SessionLifecycle::Closed);
    }

    /// Publish to a `SERVER_CLIENT` topic. (Subscriptions are a later phase; currently a
    /// no-op with no subscribers.)
    pub fn send_notification<P: Serialize>(&self, _topic: &str, _payload: &P) -> Result<()> {
        Ok(())
    }

    /// Dispatch one framed JSON-RPC message. Total — never returns an error; every
    /// protocol/handler fault becomes a wire error object inside [`Dispatched::Reply`].
    pub async fn dispatch(&self, wire: &[u8], session: &Arc<Session<S>>) -> Dispatched {
        let parsed = match envelope::parse(wire) {
            Ok(p) => p,
            // Parse / id / structural errors are always replied to (never suppressed).
            Err(pe) => return Dispatched::Reply(envelope::error_from_parse(&pe)),
        };
        self.dispatch_parsed(parsed, session).await
    }

    async fn dispatch_parsed(&self, parsed: ParsedRequest, session: &Arc<Session<S>>) -> Dispatched {
        let note = parsed.id.is_none();
        let rid = parsed.id.clone();

        // A CLOSED session accepts nothing further.
        if session.lifecycle() == SessionLifecycle::Closed {
            return finish(
                note,
                envelope::error(
                    rid.as_deref(),
                    ErrorCode::SessionNotEstablished.code(),
                    "Session is closed",
                    None,
                ),
            );
        }

        // Control messages (each enforces its own lifecycle).
        match parsed.method.as_str() {
            CANCEL_METHOD => return self.handle_cancel(parsed, session),
            SERVERINFO_METHOD => return self.handle_server_info(parsed, session).await,
            SESSION_SETUP_METHOD => return self.handle_setup(parsed, session, true).await,
            SESSION_SETUP_CONTINUE_METHOD => return self.handle_setup(parsed, session, false).await,
            SESSION_CLOSE_METHOD => return self.handle_close(parsed, session),
            _ => {}
        }

        let method = match self.methods.get(parsed.method.as_str()) {
            Some(m) => m.clone(),
            None => {
                return finish(
                    note,
                    envelope::error(
                        rid.as_deref(),
                        ErrorCode::MethodNotFound.code(),
                        "Method not found",
                        None,
                    ),
                )
            }
        };

        // A subscribe (SERVER_CLIENT) request must carry an id.
        if method.meta.direction == MessageDirection::ServerClient && note {
            return Dispatched::Reply(envelope::error(
                None,
                ErrorCode::InvalidRequest.code(),
                "Invalid request",
                Some(&json!("a subscribe request requires an 'id'")),
            ));
        }

        // Session-established gate (only when session setup is configured).
        if self.has_session_setup
            && !method.meta.pre_auth
            && session.lifecycle() != SessionLifecycle::Established
        {
            return finish(
                note,
                envelope::error(
                    rid.as_deref(),
                    ErrorCode::SessionNotEstablished.code(),
                    "Session not established",
                    None,
                ),
            );
        }

        let response = self.run_method(method, parsed, session.clone()).await;
        finish(note, response)
    }

    async fn run_method(
        &self,
        method: Arc<Method<S>>,
        parsed: ParsedRequest,
        session: Arc<Session<S>>,
    ) -> Vec<u8> {
        let rid = parsed.id.clone();
        // Only cancellable methods need a fresh cancel flag + in-flight registration;
        // everything else shares the protocol's never-cancelled flag (no per-request alloc).
        let cancel = if method.meta.cancellable {
            let flag = Arc::new(AtomicBool::new(false));
            if let Some(id) = &rid {
                self.inflight.lock().unwrap().insert(
                    id.clone(),
                    Inflight { cancel: flag.clone(), session_id: session.id() },
                );
            }
            flag
        } else {
            self.never_cancel.clone()
        };
        let cx = RequestCtx::new(rid.clone(), session.clone(), cancel);
        // The authz/audit snapshot (a full re-parse of params into a `Value`) is only
        // needed when an authorizer or an audited method will actually read it.
        let need_snapshot = self.authorizer.is_some() || method.meta.audit;
        let req = JsonRpcRequest {
            method: parsed.method.clone(),
            id: rid.clone(),
            params: if need_snapshot { raw_to_value(parsed.params.as_deref()) } else { Value::Null },
            roles: if need_snapshot { method.meta.roles.to_vec() } else { Vec::new() },
        };
        let authorizer = self.authorizer.clone();
        let audit_sink = self.audit_sink.clone();

        let is_sync = matches!(method.imp, MethodImpl::Sync(_));
        let response = if is_sync {
            let method2 = method.clone();
            let params = parsed.params;
            let session2 = session.clone();
            let req2 = req;
            let rid2 = rid.clone();
            let join = tokio::task::spawn_blocking(move || {
                sync_pipeline(
                    &method2,
                    params.as_deref(),
                    cx,
                    &session2,
                    &req2,
                    &rid2,
                    authorizer.as_deref(),
                    audit_sink.as_deref(),
                )
            });
            match join.await {
                Ok(bytes) => bytes,
                Err(_panicked) => envelope::error(
                    rid.as_deref(),
                    ErrorCode::InternalError.code(),
                    "Internal error",
                    None,
                ),
            }
        } else {
            async_pipeline(
                &method,
                parsed.params,
                cx,
                &session,
                &req,
                &rid,
                authorizer.as_deref(),
                audit_sink.as_deref(),
            )
            .await
        };

        if method.meta.cancellable {
            if let Some(id) = &rid {
                self.inflight.lock().unwrap().remove(id);
            }
        }
        response
    }

    // --- control messages ----------------------------------------------------

    async fn handle_server_info(&self, parsed: ParsedRequest, session: &Arc<Session<S>>) -> Dispatched {
        let note = parsed.id.is_none();
        let rid = parsed.id.clone();
        let Some(handler) = self.server_info.clone() else {
            // Not configured: behave like any unknown `$/` method.
            return finish(
                note,
                envelope::error(
                    rid.as_deref(),
                    ErrorCode::MethodNotFound.code(),
                    "Method not found",
                    None,
                ),
            );
        };
        // No authz, no gate, not audited. Run on the blocking pool (it is a user callback).
        let session2 = session.clone();
        let outcome =
            tokio::task::spawn_blocking(move || handler.server_info(&session2)).await;
        let bytes = match outcome {
            Ok(Ok(value)) => match to_raw_value(&value) {
                Ok(raw) => envelope::success(rid.as_deref(), &raw),
                Err(e) => envelope::error(
                    rid.as_deref(),
                    ErrorCode::InternalError.code(),
                    "Internal error",
                    Some(&json!(e.to_string())),
                ),
            },
            Ok(Err(e)) => envelope::error(rid.as_deref(), e.code, &e.message, e.data.as_ref()),
            Err(_panicked) => envelope::error(
                rid.as_deref(),
                ErrorCode::InternalError.code(),
                "Internal error",
                None,
            ),
        };
        finish(note, bytes)
    }

    async fn handle_setup(
        &self,
        parsed: ParsedRequest,
        session: &Arc<Session<S>>,
        first: bool,
    ) -> Dispatched {
        let note = parsed.id.is_none();
        let rid = parsed.id.clone();
        let slot = if first { self.setup.as_ref() } else { self.setup_continue.as_ref() };
        let Some(slot) = slot else {
            return finish(
                note,
                envelope::error(
                    rid.as_deref(),
                    ErrorCode::MethodNotFound.code(),
                    "Method not found",
                    None,
                ),
            );
        };

        // Lifecycle gate: setup in NONE, continue in INIT.
        let allowed = matches!(
            (first, session.lifecycle()),
            (true, SessionLifecycle::None) | (false, SessionLifecycle::Init)
        );
        if !allowed {
            return finish(
                note,
                envelope::error(
                    rid.as_deref(),
                    ErrorCode::RequestFailed.code(),
                    "Request failed",
                    Some(&json!("session setup not allowed in the current state")),
                ),
            );
        }

        let snapshot = raw_to_value(parsed.params.as_deref());
        let handler = slot.handler.clone();
        let session2 = session.clone();
        let params = parsed.params;
        // Setup bypasses authz; crypto is blocking → the blocking pool.
        let outcome = tokio::task::spawn_blocking(move || handler.handle(params.as_deref(), &session2)).await;

        let bytes = match outcome {
            Ok(Ok((new_lifecycle, raw))) => {
                session.set_lifecycle(new_lifecycle);
                if let Ok(v) = serde_json::from_str::<Value>(raw.get()) {
                    session.set_external(v);
                }
                envelope::success(rid.as_deref(), &raw)
            }
            Ok(Err(e)) => envelope::error(rid.as_deref(), e.code, &e.message, e.data.as_ref()),
            Err(_panicked) => envelope::error(
                rid.as_deref(),
                ErrorCode::InternalError.code(),
                "Internal error",
                None,
            ),
        };

        // Setup is always audited (credentials redacted).
        if let Some(sink) = &self.audit_sink {
            let mut req = JsonRpcRequest {
                method: parsed.method.clone(),
                id: rid.clone(),
                params: snapshot,
                roles: Vec::new(),
            };
            redact_value(&mut req.params, &slot.meta.secret_fields);
            let mut resp_value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            if let Some(result) = resp_value.get_mut("result") {
                redact_value(result, &slot.meta.secret_fields);
            }
            sink.audit(&req, &resp_value, session, slot.meta.audit_message.as_deref());
        }

        finish(note, bytes)
    }

    fn handle_close(&self, parsed: ParsedRequest, session: &Arc<Session<S>>) -> Dispatched {
        let note = parsed.id.is_none();
        let rid = parsed.id.clone();
        let lifecycle = session.lifecycle();
        if lifecycle != SessionLifecycle::Init && lifecycle != SessionLifecycle::Established {
            return finish(
                note,
                envelope::error(
                    rid.as_deref(),
                    ErrorCode::RequestFailed.code(),
                    "Request failed",
                    Some(&json!("no session to close")),
                ),
            );
        }
        self.close_session(session);
        let raw = to_raw_value(&true).expect("encoding `true` cannot fail");
        finish(note, envelope::success(rid.as_deref(), &raw))
    }

    fn handle_cancel(&self, parsed: ParsedRequest, session: &Arc<Session<S>>) -> Dispatched {
        let note = parsed.id.is_none();
        let rid = parsed.id.clone();

        #[derive(Deserialize)]
        struct CancelParams {
            target_id: String,
        }
        let target_id = match parsed.params.as_deref().map(|r| serde_json::from_str::<CancelParams>(r.get())) {
            Some(Ok(p)) => p.target_id,
            _ => {
                return finish(
                    note,
                    envelope::error(
                        rid.as_deref(),
                        ErrorCode::InvalidParams.code(),
                        "Invalid params",
                        Some(&json!("'target_id' is required")),
                    ),
                )
            }
        };

        let target = self
            .inflight
            .lock()
            .unwrap()
            .get(&target_id)
            .map(|e| (e.cancel.clone(), e.session_id));

        let req = JsonRpcRequest {
            method: parsed.method.clone(),
            id: rid.clone(),
            params: raw_to_value(parsed.params.as_deref()),
            roles: Vec::new(),
        };

        match target {
            Some((cancel, session_id)) => {
                if let Err(denied) = check_authz(
                    self.authorizer.as_deref(),
                    &req,
                    session,
                    Some(CancelTarget::Request { session_id }),
                ) {
                    return finish(
                        note,
                        envelope::error(rid.as_deref(), denied.code, &denied.message, denied.data.as_ref()),
                    );
                }
                cancel.store(true, Ordering::Relaxed);
                if let Some(c) = &self.canceller {
                    c.cancel(&req, session);
                }
                let raw = to_raw_value(&true).expect("encoding `true` cannot fail");
                finish(note, envelope::success(rid.as_deref(), &raw))
            }
            None => finish(
                note,
                envelope::error(
                    rid.as_deref(),
                    ErrorCode::RequestFailed.code(),
                    "Request failed",
                    Some(&json!("no active request or subscription for the given id")),
                ),
            ),
        }
    }
}

// --- shared pipeline helpers -------------------------------------------------

fn finish(note: bool, bytes: Vec<u8>) -> Dispatched {
    if note {
        Dispatched::Nothing
    } else {
        Dispatched::Reply(bytes)
    }
}

fn raw_to_value(params: Option<&RawValue>) -> Value {
    match params {
        Some(r) => serde_json::from_str(r.get()).unwrap_or(Value::Null),
        None => Value::Object(serde_json::Map::new()),
    }
}

fn check_authz<S>(
    authorizer: Option<&dyn Authorizer<S>>,
    req: &JsonRpcRequest,
    session: &Session<S>,
    target: Option<CancelTarget>,
) -> std::result::Result<(), JsonRpcError> {
    match authorizer {
        None => Ok(()),
        Some(a) => {
            let resp = a.authorize(req, session, target);
            if resp.authorized {
                Ok(())
            } else {
                let message = if resp.message.is_empty() {
                    "Not authorized".to_string()
                } else {
                    resp.message
                };
                let mut e = JsonRpcError::not_authorized(message);
                if let Some(data) = resp.data {
                    e = e.with_data(data);
                }
                Err(e)
            }
        }
    }
}

fn response_bytes(
    rid: &Option<String>,
    outcome: &std::result::Result<Box<RawValue>, JsonRpcError>,
) -> Vec<u8> {
    match outcome {
        Ok(raw) => envelope::success(rid.as_deref(), raw),
        Err(e) => envelope::error(rid.as_deref(), e.code, &e.message, e.data.as_ref()),
    }
}

fn join_audit_message(static_msg: Option<&str>, detail: Option<&str>) -> Option<String> {
    match (static_msg, detail) {
        (Some(s), Some(d)) => Some(format!("{s} {d}")),
        (Some(s), None) => Some(s.to_string()),
        (None, Some(d)) => Some(d.to_string()),
        (None, None) => None,
    }
}

fn redact_value(value: &mut Value, secret_fields: &[String]) {
    if secret_fields.is_empty() {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if secret_fields.iter().any(|s| s == key) {
                    *val = Value::String("********".to_string());
                } else {
                    redact_value(val, secret_fields);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value(item, secret_fields);
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn do_audit<S>(
    method: &Method<S>,
    req: &JsonRpcRequest,
    response: &[u8],
    audit_detail: &Arc<Mutex<Option<String>>>,
    session: &Session<S>,
    audit_sink: Option<&dyn AuditSink<S>>,
) {
    if !method.meta.audit {
        return;
    }
    let Some(sink) = audit_sink else { return };
    let detail = audit_detail.lock().unwrap().take();
    let message = join_audit_message(method.meta.audit_message.as_deref(), detail.as_deref());
    let mut audit_req = req.clone();
    redact_value(&mut audit_req.params, &method.meta.secret_fields);
    let mut resp_value: Value = serde_json::from_slice(response).unwrap_or(Value::Null);
    if let Some(result) = resp_value.get_mut("result") {
        redact_value(result, &method.meta.secret_fields);
    }
    sink.audit(&audit_req, &resp_value, session, message.as_deref());
}

#[allow(clippy::too_many_arguments)]
fn sync_pipeline<S: Send + Sync + 'static>(
    method: &Method<S>,
    params: Option<&RawValue>,
    cx: RequestCtx<S>,
    session: &Session<S>,
    req: &JsonRpcRequest,
    rid: &Option<String>,
    authorizer: Option<&dyn Authorizer<S>>,
    audit_sink: Option<&dyn AuditSink<S>>,
) -> Vec<u8> {
    let MethodImpl::Sync(erased) = &method.imp else {
        unreachable!("sync_pipeline on a non-sync method")
    };
    let audit_detail = cx.audit_handle();
    // 1. typed decode (INVALID_PARAMS) — before authz, so it takes precedence; no audit.
    let decoded = match erased.decode(params) {
        Ok(d) => d,
        Err(e) => return envelope::error(rid.as_deref(), e.code, &e.message, e.data.as_ref()),
    };
    // 2. authorize, 3. run handler.
    let outcome: std::result::Result<Box<RawValue>, JsonRpcError> =
        match check_authz(authorizer, req, session, None) {
            Err(denied) => Err(denied),
            Ok(()) => erased.run(decoded, &cx),
        };
    let response = response_bytes(rid, &outcome);
    // 4. audit (success / handler error / authz denial — never decode failure).
    do_audit(method, req, &response, &audit_detail, session, audit_sink);
    response
}

#[allow(clippy::too_many_arguments)]
async fn async_pipeline<S: Send + Sync + 'static>(
    method: &Method<S>,
    params: Option<Box<RawValue>>,
    cx: RequestCtx<S>,
    session: &Session<S>,
    req: &JsonRpcRequest,
    rid: &Option<String>,
    authorizer: Option<&dyn Authorizer<S>>,
    audit_sink: Option<&dyn AuditSink<S>>,
) -> Vec<u8> {
    let MethodImpl::Async(erased) = &method.imp else {
        unreachable!("async_pipeline on a non-async method")
    };
    let audit_detail = cx.audit_handle();
    // 1. typed decode (INVALID_PARAMS) — before authz; no audit on decode failure.
    let decoded = match erased.decode(params.as_deref()) {
        Ok(d) => d,
        Err(e) => return envelope::error(rid.as_deref(), e.code, &e.message, e.data.as_ref()),
    };
    // 2. authorize, 3. await handler (cx is moved in; audit reads the shared handle).
    let outcome: std::result::Result<Box<RawValue>, JsonRpcError> =
        match check_authz(authorizer, req, session, None) {
            Err(denied) => Err(denied),
            Ok(()) => erased.run(decoded, cx).await,
        };
    let response = response_bytes(rid, &outcome);
    do_audit(method, req, &response, &audit_detail, session, audit_sink);
    response
}
