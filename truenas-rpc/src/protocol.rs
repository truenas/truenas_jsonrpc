//! [`JsonRpcProtocol`] — the dispatch core, its
//! [`JsonRpcProtocolBuilder`], the async [`JsonRpcProtocol::dispatch`] seam, and the `$/`
//! control messages — the **Envelope** (4), **Dispatch** (5), **Authorization** gate, and
//! **Control-plane** of the `ARCHITECTURE.md` layer stack.
//!
//! `dispatch` is `async` and **branches on the method kind**: a sync [`JsonRpcMethod`]
//! runs its whole pipeline (decode → authorize → handler → audit) on a `spawn_blocking`
//! worker; an [`AsyncJsonRpcMethod`] is awaited.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::{to_raw_value, RawValue};
use serde_json::{json, Value};

use crate::envelope::{self, ParsedRequest};
use crate::error::{BuildResult, Error, ErrorCode, JsonRpcError};
use crate::method::{
    decode_params, encode_result, AsyncJsonRpcMethod, Codec, ErasedTransfer, FilterableJsonRpcMethod,
    JsonRpcFdPassMethod, JsonRpcFdTransferMethod, JsonRpcMethod, Method, MethodDef, MethodImpl,
    MethodMeta, SubscriptionDef, SubscriptionImpl, WireParams, WireReply,
};
use crate::pydispatch::{PyDispatcher, PyOutcome, PyResult};
use crate::request::{InternalCaller, RequestCtx};
use crate::role::{RoleMask, Roles};
use crate::session::{Clock, IdGen, Outbound, Session, SessionId, SessionOrigin, SystemClock, UuidGen};
use crate::setup::{SetupHandoff, SetupOutcome, SetupTakeover};
use crate::transfer::{FileTransfer, Transfer, TransferDirection};
use crate::types::{JsonRpcRequest, MessageDirection, SessionLifecycle};
use truenas_filter::{CompiledFilters, CompiledOptions, Filtered};

const CANCEL_METHOD: &str = "$/cancelRequest";
const SERVERINFO_METHOD: &str = "$/serverInfo";
const SESSION_SETUP_METHOD: &str = "$/sessionSetup";
const SESSION_SETUP_CONTINUE_METHOD: &str = "$/sessionSetupContinue";
const SESSION_CLOSE_METHOD: &str = "$/sessionClose";
const DESCRIBE_METHOD: &str = "$/describe";
const SESSIONS_METHOD: &str = "$/sessions";
const TRANSFER_READY_METHOD: &str = "$/transferReady";

/// The result of dispatching one inbound message.
pub enum Dispatched {
    /// Send these wire bytes back (a success or error response).
    Reply(Vec<u8>),
    /// Nothing to send (a notification, or a suppressed reply).
    Nothing,
    /// A raw-fd transfer method was authorized + negotiated: the server must run the wire
    /// handshake and fd handoff (see [`Transfer`]). Returned only by the JSON wire — the XDR
    /// binary wire does not offer transfer methods.
    Transfer(Transfer),
    /// A `$/sessionSetup` handler took over the connection to finish authentication out-of-band
    /// (passthrough): the server gates the connection and runs the [`SetupTakeover`] with the
    /// connection's fd. The broker replies to the client over that fd, so there is no envelope to
    /// send here. JSON wire only.
    Passthrough(SetupTakeover),
    /// A FULL_ADMIN `$/sessions` listing: the core gated + audited the call, but the listing is
    /// **server-wide** (across every negotiated protocol), which only the server can assemble. The
    /// server walks each protocol's [`JsonRpcProtocol::render_sessions`], concatenates them, and
    /// replies with `id == rid`. Returned only for an authorized request that carried an id.
    Sessions {
        /// The request id to reply to.
        rid: String,
        /// The calling session's id — the server marks the matching listing entry `current`.
        caller: SessionId,
    },
}

impl Dispatched {
    /// The reply bytes, if any (`None` for [`Dispatched::Nothing`]; a [`Dispatched::Transfer`]
    /// has no single reply — it yields the `$/transferReady` envelope then a final response
    /// via the server's handshake, so this is `None`; a [`Dispatched::Sessions`] is fulfilled by
    /// the server, so it has no core-built reply either).
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            Dispatched::Reply(b) => Some(b),
            Dispatched::Nothing
            | Dispatched::Transfer(_)
            | Dispatched::Passthrough(_)
            | Dispatched::Sessions { .. } => None,
        }
    }
}

/// The resolved owner of a `$/cancelRequest`'s target — used by the native ownership check
/// ("cancel only your own, unless `FULL_ADMIN`").
#[derive(Clone, Copy, Debug)]
pub enum CancelTarget {
    /// An in-flight request, owned by the given session.
    Request {
        /// The session that issued the targeted request.
        session_id: SessionId,
    },
    /// A subscription, owned by the given session.
    Subscription {
        /// The session that owns the targeted subscription.
        session_id: SessionId,
    },
}

// --- configurable hooks ------------------------------------------------------

/// The structured result of an audited dispatch, handed to an [`AuditSink`] in place of a
/// re-parsed response envelope.
///
/// The success *result* is intentionally **not** carried: an audit record captures that a call
/// happened and whether it succeeded — not the (potentially large) payload. This lets the dispatch
/// path hand the sink the `Result` it already holds, instead of serializing the reply and then
/// re-parsing it back into a [`Value`] (and, on the XDR wire, reflecting the result to a `Value`
/// only to serialize + re-parse it). It also means there is no result to scan for secrets — the
/// only secret-bearing surface is the request params, which the core redacts before the sink runs.
#[derive(Debug, Clone, Copy)]
pub enum AuditOutcome<'a> {
    /// The call succeeded.
    Success,
    /// The call failed with this error (already classified by [`JsonRpcError::code`]).
    Failure(&'a JsonRpcError),
}

impl AuditOutcome<'_> {
    /// `true` for [`Success`](AuditOutcome::Success) — drives `res=success|failed`.
    pub fn succeeded(&self) -> bool {
        matches!(self, AuditOutcome::Success)
    }

    /// The error, when the call failed.
    pub fn error(&self) -> Option<&JsonRpcError> {
        match self {
            AuditOutcome::Failure(e) => Some(e),
            AuditOutcome::Success => None,
        }
    }
}

/// Map a dispatch `Result` to an [`AuditOutcome`] without touching the success payload.
fn audit_outcome<T>(outcome: &Result<T, JsonRpcError>) -> AuditOutcome<'_> {
    match outcome {
        Ok(_) => AuditOutcome::Success,
        Err(e) => AuditOutcome::Failure(e),
    }
}

/// Audit sink. Called for every audited method call + control op (success, error, or denial).
/// `request.params` already has its secret fields redacted; `outcome` is the structured result.
pub trait AuditSink<S>: Send + Sync {
    /// Record one audit entry (`request.params` is redacted; `outcome` carries success/failure).
    fn audit(
        &self,
        request: &JsonRpcRequest,
        outcome: AuditOutcome<'_>,
        session: &Session<S>,
        audit_message: Option<&str>,
    );
}

impl<S, F> AuditSink<S> for F
where
    F: Fn(&JsonRpcRequest, AuditOutcome<'_>, &Session<S>, Option<&str>) + Send + Sync,
{
    fn audit(
        &self,
        request: &JsonRpcRequest,
        outcome: AuditOutcome<'_>,
        session: &Session<S>,
        audit_message: Option<&str>,
    ) {
        (self)(request, outcome, session, audit_message)
    }
}

/// Optional active-abort callback, invoked after an authorized `$/cancelRequest` sets the
/// target request's cooperative cancel flag (e.g. close a socket to unblock I/O).
pub trait Canceller<S>: Send + Sync {
    /// Actively abort the in-flight `request` (e.g. close a socket to unblock its I/O).
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
    /// Produce the `$/serverInfo` payload for `session`.
    fn server_info(&self, session: &Session<S>) -> Result<Value, JsonRpcError>;
}

impl<S, F> ServerInfoHandler<S> for F
where
    F: Fn(&Session<S>) -> Result<Value, JsonRpcError> + Send + Sync,
{
    fn server_info(&self, session: &Session<S>) -> Result<Value, JsonRpcError> {
        (self)(session)
    }
}

/// Augments a `$/sessions` listing entry with per-connection fields the generic core can't see (the
/// identity held in `S`). The core always builds the base entry (`session_id`, `age_seconds`,
/// `created_at`, `lifecycle`, `protocol`, `current`, and — when the server/auth set them — `origin`,
/// `secure_transport`, `internal`, `credential`); the value returned here is **merged on top** of
/// that base (its keys win on collision). Return a JSON **object** of extra fields; a non-object is
/// ignored. The same pattern as the audit principal extractor.
pub trait SessionInfo<S>: Send + Sync {
    /// Produce the **extra** fields (a JSON object) to merge into `session`'s listing entry.
    fn render(&self, session: &Session<S>) -> Value;
}

impl<S, F> SessionInfo<S> for F
where
    F: Fn(&Session<S>) -> Value + Send + Sync,
{
    fn render(&self, session: &Session<S>) -> Value {
        (self)(session)
    }
}

/// Erased `$/sessionSetup` / `$/sessionSetupContinue` handler: authenticates, sets the
/// session's server-internal identity as a side effect, and returns the next lifecycle +
/// the client-facing result. Provided as a closure
/// `Fn(Accepts, &Session<S>) -> Result<(SessionLifecycle, Returns), JsonRpcError>`.
/// A setup handler's outcome with the reply already encoded: either commit synchronously, or take
/// over the connection (passthrough).
enum RawSetupOutcome {
    Commit(SessionLifecycle, Box<RawValue>),
    Takeover(SetupHandoff),
}

trait ErasedSetup<S>: Send + Sync {
    fn handle(&self, params: Option<&RawValue>, session: &Arc<Session<S>>) -> Result<RawSetupOutcome, JsonRpcError>;
}

/// Adapter for a takeover-capable `$/sessionSetup` handler (returns a [`SetupOutcome`]).
struct ClosureSetup<A, R, F> {
    f: F,
    _p: PhantomData<fn() -> (A, R)>,
}

impl<S, A, R, F> ErasedSetup<S> for ClosureSetup<A, R, F>
where
    S: Send + Sync + 'static,
    A: DeserializeOwned + Send + 'static,
    R: Serialize,
    F: Fn(A, &Arc<Session<S>>) -> Result<SetupOutcome<R>, JsonRpcError> + Send + Sync,
{
    fn handle(&self, params: Option<&RawValue>, session: &Arc<Session<S>>) -> Result<RawSetupOutcome, JsonRpcError> {
        let accepts: A = decode_params(params)?;
        Ok(match (self.f)(accepts, session)? {
            SetupOutcome::Commit(lifecycle, returns) => RawSetupOutcome::Commit(lifecycle, encode_result(&returns)?),
            SetupOutcome::Takeover(handoff) => RawSetupOutcome::Takeover(handoff),
        })
    }
}

/// Adapter for a commit-only handler (`$/sessionSetupContinue`, which never takes over): the user
/// closure returns `(lifecycle, R)` and gets `&Session<S>`.
struct ClosureCommit<A, R, F> {
    f: F,
    _p: PhantomData<fn() -> (A, R)>,
}

impl<S, A, R, F> ErasedSetup<S> for ClosureCommit<A, R, F>
where
    S: Send + Sync + 'static,
    A: DeserializeOwned + Send + 'static,
    R: Serialize,
    F: Fn(A, &Session<S>) -> Result<(SessionLifecycle, R), JsonRpcError> + Send + Sync,
{
    fn handle(&self, params: Option<&RawValue>, session: &Arc<Session<S>>) -> Result<RawSetupOutcome, JsonRpcError> {
        let accepts: A = decode_params(params)?;
        let (lifecycle, returns) = (self.f)(accepts, session)?;
        Ok(RawSetupOutcome::Commit(lifecycle, encode_result(&returns)?))
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

/// A registered subscription to a SERVER_CLIENT topic: the owning session (for fan-out via
/// its [`Outbound`] sink and for session-scoped cancel) plus a snapshot of the subscribe
/// params.
struct Subscription<S> {
    session: Arc<Session<S>>,
    #[allow(dead_code)] // forward-compat (per-subscription filtering)
    params: Value,
}

/// Topic → {sub_id → [`Subscription`]} (alias keeps the registry field type readable).
type Subscriptions<S> = HashMap<Arc<str>, HashMap<String, Subscription<S>>>;

// --- builder -----------------------------------------------------------------

/// Builds a [`JsonRpcProtocol`]. Frozen
/// by [`build`](Self::build); the result is safe for concurrent dispatch.
pub struct JsonRpcProtocolBuilder<S> {
    name: Arc<str>,
    version: Arc<str>,
    methods: HashMap<Arc<str>, Arc<Method<S>>>,
    /// XDR-enabled methods, keyed by proc-id (a subset of `methods`, sharing the `Arc`).
    xdr_methods: HashMap<u32, Arc<Method<S>>>,
    /// Opt-in: emit one audit record per **elevated** in-process call. Off by default.
    audit_elevated: bool,
    /// The role registry: interns each method's declared role names → a `required` mask at build.
    role_registry: Option<Roles>,
    audit_sink: Option<Arc<dyn AuditSink<S>>>,
    canceller: Option<Arc<dyn Canceller<S>>>,
    server_info: Option<Arc<dyn ServerInfoHandler<S>>>,
    session_info: Option<Arc<dyn SessionInfo<S>>>,
    setup: Option<SetupSlot<S>>,
    setup_continue: Option<SetupSlot<S>>,
    describe: Option<Box<RawValue>>,
    py_dispatcher: Option<Arc<dyn PyDispatcher>>,
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
            xdr_methods: HashMap::new(),
            audit_elevated: false,
            role_registry: None,
            audit_sink: None,
            canceller: None,
            server_info: None,
            session_info: None,
            setup: None,
            setup_continue: None,
            describe: None,
            py_dispatcher: None,
            id_gen: Arc::new(UuidGen),
            clock: Arc::new(SystemClock),
        }
    }

    /// Emit one audit record per **elevated** in-process call ([`RequestCtx::call_op_elevated`]).
    /// Off by default — internal calls are otherwise unaudited, so routine privileged housekeeping
    /// creates no audit churn; enable only where every privilege elevation must be logged.
    pub fn audit_internal_elevated(mut self, on: bool) -> Self {
        self.audit_elevated = on;
        self
    }

    fn insert(&mut self, mut method: Method<S>) -> BuildResult<()> {
        let name = method.meta.name.clone();
        if name.starts_with("rpc.") || name.starts_with("$/") {
            return Err(Error::ReservedName(name.to_string()));
        }
        if self.methods.contains_key(&name) {
            return Err(Error::DuplicateMethod(name.to_string()));
        }
        // Intern the declared role names into the method's `required` subset-gate mask.
        if !method.meta.roles.is_empty() {
            let registry = self.role_registry.as_ref().ok_or_else(|| {
                Error::Config(format!(
                    "method {name:?} declares roles but no role registry is set; call .roles(...) first"
                ))
            })?;
            method.meta.required = registry.mask(method.meta.roles.iter()).map_err(|unknown| {
                Error::Config(format!("method {name:?} requires unregistered role {unknown:?}"))
            })?;
        }
        match method.meta.xdr_id {
            None => {
                self.methods.insert(name, Arc::new(method));
            }
            Some(id) => {
                // 0..=RESERVED_PROC_MAX are reserved for control messages over the binary wire.
                if id <= truenas_xdr::frame::RESERVED_PROC_MAX {
                    return Err(Error::Config(format!(
                        "xdr_id {id} for method {name:?} is reserved (must be > {})",
                        truenas_xdr::frame::RESERVED_PROC_MAX
                    )));
                }
                if self.xdr_methods.contains_key(&id) {
                    return Err(Error::Config(format!(
                        "duplicate xdr_id {id} for method {name:?}"
                    )));
                }
                // The same `Arc<Method>` lives in both maps (JSON by name, XDR by proc-id).
                let arc = Arc::new(method);
                self.xdr_methods.insert(id, arc.clone());
                self.methods.insert(name, arc);
            }
        }
        Ok(())
    }

    /// Register a synchronous request method.
    pub fn method<F, A, R>(mut self, method: JsonRpcMethod<F>) -> BuildResult<Self>
    where
        F: Fn(A, &RequestCtx<S>) -> Result<R, JsonRpcError> + Send + Sync + 'static,
        A: DeserializeOwned + Serialize + Send + 'static,
        R: Serialize + Send + 'static,
    {
        self.insert(method.erase::<S, A, R>())?;
        Ok(self)
    }

    /// Register an async request method.
    pub fn async_method<F, A, R, Fut>(mut self, method: AsyncJsonRpcMethod<F>) -> BuildResult<Self>
    where
        F: Fn(A, RequestCtx<S>) -> Fut + Send + Sync + 'static,
        A: DeserializeOwned + Serialize + Send + 'static,
        R: Serialize + Send + 'static,
        Fut: Future<Output = Result<R, JsonRpcError>> + Send + 'static,
    {
        self.insert(method.erase::<S, A, R, Fut>())?;
        Ok(self)
    }

    /// Register a subscribable SERVER_CLIENT topic (no handler). Clients subscribe with a
    /// normal request (which returns a subscription id); the server publishes with
    /// [`JsonRpcProtocol::send_notification`].
    pub fn subscription<A, N>(mut self, def: SubscriptionDef<A, N>) -> BuildResult<Self>
    where
        A: DeserializeOwned + 'static,
        N: DeserializeOwned + Serialize + 'static,
    {
        self.insert(def.erase::<S>())?;
        Ok(self)
    }

    /// Register a filterable (query) request method. The handler receives the compiled
    /// `query-filters` / `query-options` and applies them at its source via
    /// [`truenas_filter::tnfilter`]; the framework applies the `get`/`count` finalize.
    pub fn filterable<F, A, E>(
        mut self,
        method: FilterableJsonRpcMethod<A, E, F>,
    ) -> BuildResult<Self>
    where
        F: Fn(A, &RequestCtx<S>, &CompiledFilters, &CompiledOptions) -> Result<Filtered<E>, JsonRpcError>
            + Send
            + Sync
            + 'static,
        A: DeserializeOwned + Serialize + Send + 'static,
        E: Serialize + 'static,
    {
        self.insert(method.erase::<S>())?;
        Ok(self)
    }

    /// Register a raw-fd transfer method (e.g. `zfs send`/`recv` via libzfs). After
    /// authorization the `negotiate` callback runs and a [`Transfer`] directive is handed back
    /// for the server to drive the wire handshake + fd handoff; the `transfer` callback then
    /// streams over the connection's raw fd.
    pub fn fd_transfer_method<A, N, R, FN, FT>(
        mut self,
        method: JsonRpcFdTransferMethod<A, N, R, FN, FT>,
    ) -> BuildResult<Self>
    where
        A: DeserializeOwned + Send + 'static,
        N: Serialize + 'static,
        R: Serialize + 'static,
        FN: Fn(&A, &RequestCtx<S>) -> Result<N, JsonRpcError> + Send + Sync + 'static,
        FT: Fn(A, &dyn FileTransfer) -> Result<R, JsonRpcError> + Send + Sync + 'static,
    {
        self.insert(method.erase::<S>())?;
        Ok(self)
    }

    /// Register an `SCM_RIGHTS` file-descriptor-passing method (**AF_UNIX only**). Like
    /// [`fd_transfer_method`](Self::fd_transfer_method), but the `transfer` callback passes /
    /// receives open fds rather than streaming bytes.
    pub fn fd_pass_method<A, N, R, FN, FT>(
        mut self,
        method: JsonRpcFdPassMethod<A, N, R, FN, FT>,
    ) -> BuildResult<Self>
    where
        A: DeserializeOwned + Send + 'static,
        N: Serialize + 'static,
        R: Serialize + 'static,
        FN: Fn(&A, &RequestCtx<S>) -> Result<N, JsonRpcError> + Send + Sync + 'static,
        FT: Fn(A, &dyn FileTransfer) -> Result<R, JsonRpcError> + Send + Sync + 'static,
    {
        self.insert(method.erase::<S>())?;
        Ok(self)
    }

    /// Set the role registry — the canonical role taxonomy. Each registered method's declared role
    /// names are interned against it into a `required` [`RoleMask`] at registration, and the
    /// per-call gate checks `required ⊆ granted`. Must be set **before** registering methods that
    /// declare roles (a declared role with no registry, or an unregistered name, is a build error).
    pub fn roles(mut self, roles: Roles) -> Self {
        self.role_registry = Some(roles);
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

    /// Customize how each session is rendered in the FULL_ADMIN `$/sessions` listing — e.g. to add
    /// the authenticated user / origin read from the per-connection state `S`. Without it, entries
    /// carry only the core-visible fields (`session_id`, `age_seconds`, `lifecycle`, `protocol`).
    pub fn session_info(mut self, renderer: impl SessionInfo<S> + 'static) -> Self {
        self.session_info = Some(Arc::new(renderer));
        self
    }

    /// Provide the OpenRPC service description served by the unauthenticated `$/describe`
    /// introspection method (typically the generated `openrpc.json`, embedded with
    /// `include_str!` and parsed once into a [`RawValue`]). Without it, `$/describe`
    /// reports method-not-found.
    pub fn describe(mut self, doc: Box<RawValue>) -> Self {
        self.describe = Some(doc);
        self
    }

    /// Register a python-backed method (`python:true`): no Rust handler — the body runs via
    /// the configured [`PyDispatcher`]. The core still routes/gates/authorizes/audits it;
    /// only the body crosses into Python. Set the dispatcher with
    /// [`python_dispatcher`](Self::python_dispatcher).
    pub fn python_method(mut self, def: MethodDef) -> BuildResult<Self> {
        self.insert(Method::python(def))?;
        Ok(self)
    }

    /// Set the [`PyDispatcher`] that runs `python:true` method bodies. Without it, a python
    /// method dispatches to `INTERNAL_ERROR` (degrading safely).
    pub fn python_dispatcher(mut self, dispatcher: impl PyDispatcher + 'static) -> Self {
        self.py_dispatcher = Some(Arc::new(dispatcher));
        self
    }

    /// Enable `$/sessionSetup` (and optionally `$/sessionSetupContinue`) authentication.
    /// `def` carries audit/secret-field metadata (setup is always audited, redacted). The handler
    /// finishes synchronously, returning `(lifecycle, reply)`. For a handler that may **take over**
    /// the connection (passthrough), use [`session_setup_takeover`](Self::session_setup_takeover).
    pub fn session_setup<F, A, R>(mut self, def: MethodDef, handler: F) -> Self
    where
        F: Fn(A, &Session<S>) -> Result<(SessionLifecycle, R), JsonRpcError>
            + Send
            + Sync
            + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
    {
        self.setup = Some(SetupSlot {
            meta: def.into_meta(MessageDirection::ClientServer),
            handler: Arc::new(ClosureCommit { f: handler, _p: PhantomData }),
        });
        self
    }

    /// Enable `$/sessionSetup` with a handler that may **take over** the connection. The handler
    /// returns a [`SetupOutcome`]: `Commit(lifecycle, reply)` for the synchronous case, or
    /// `Takeover(handoff)` to hand the connection fd to an out-of-band authenticator (the
    /// passthrough broker). It receives the session as an `&Arc` so a takeover closure can capture
    /// it to commit the result once the fd is available. The synchronous
    /// [`session_setup`](Self::session_setup) covers the common case.
    pub fn session_setup_takeover<F, A, R>(mut self, def: MethodDef, handler: F) -> Self
    where
        F: Fn(A, &Arc<Session<S>>) -> Result<SetupOutcome<R>, JsonRpcError> + Send + Sync + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
    {
        self.setup = Some(SetupSlot {
            meta: def.into_meta(MessageDirection::ClientServer),
            handler: Arc::new(ClosureSetup { f: handler, _p: PhantomData }),
        });
        self
    }

    /// Set the multi-step `$/sessionSetupContinue` handler. A continue always finishes
    /// synchronously (no takeover), so it returns `(lifecycle, reply)`.
    pub fn session_setup_continue<F, A, R>(mut self, def: MethodDef, handler: F) -> Self
    where
        F: Fn(A, &Session<S>) -> Result<(SessionLifecycle, R), JsonRpcError>
            + Send
            + Sync
            + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
    {
        self.setup_continue = Some(SetupSlot {
            meta: def.into_meta(MessageDirection::ClientServer),
            handler: Arc::new(ClosureCommit { f: handler, _p: PhantomData }),
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
        let registry = Arc::new(Registry { methods: self.methods, xdr_methods: self.xdr_methods });
        let caller: Arc<dyn InternalCaller<S>> = Arc::new(Caller {
            registry: registry.clone(),
            audit_sink: self.audit_sink.clone(),
            audit_elevated: self.audit_elevated,
        });
        let service = Arc::new(Service {
            name: self.name,
            registry,
            caller,
            audit_sink: self.audit_sink,
            py_dispatcher: self.py_dispatcher,
            has_session_setup,
            id_gen: self.id_gen,
            clock: self.clock,
            sessions: Mutex::new(HashMap::new()),
            never_cancel: Arc::new(AtomicBool::new(false)),
        });
        JsonRpcProtocol {
            service,
            version: self.version,
            canceller: self.canceller,
            server_info: self.server_info,
            session_info: self.session_info,
            setup: self.setup,
            setup_continue: self.setup_continue,
            describe: self.describe,
            inflight: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(HashMap::new()),
        }
    }
}

// --- protocol ----------------------------------------------------------------

/// The **wire-neutral op-table** — the registered methods, the decode→authorize→run→audit run core,
/// and the session registry. Every wire-view shares one: the JSON-RPC and TXDR wires
/// ([`JsonRpcProtocol`]) and a binary engine (e.g. ONC RPC, via [`run_proc`](Self::run_proc)) both
/// consume it, so a method registered once is reachable over any wire. Built by
/// [`JsonRpcProtocolBuilder::build`].
pub struct Service<S> {
    name: Arc<str>,
    registry: Arc<Registry<S>>,
    /// The in-process call seam threaded into each request's [`RequestCtx`]: looks up + runs a
    /// registered method from within a handler. Built once over `registry` at
    /// [`build`](JsonRpcProtocolBuilder::build).
    caller: Arc<dyn InternalCaller<S>>,
    audit_sink: Option<Arc<dyn AuditSink<S>>>,
    py_dispatcher: Option<Arc<dyn PyDispatcher>>,
    has_session_setup: bool,
    id_gen: Arc<dyn IdGen>,
    #[allow(dead_code)] // used by audit timestamping once the audit record carries time
    clock: Arc<dyn Clock>,
    /// Active sessions by id → a `Weak` handle. The connection task owns the `Arc`, so a dropped
    /// session's `Weak` simply fails to upgrade — this never leaks or keeps a connection alive.
    /// Inserted in [`new_session`](Self::new_session), pruned in [`close_session`](Self::close_session);
    /// read by the FULL_ADMIN `$/sessions` control method.
    sessions: Mutex<HashMap<SessionId, Weak<Session<S>>>>,
    /// A shared always-false flag handed to non-cancellable requests so they don't each
    /// allocate a cancel `Arc`.
    never_cancel: Arc<AtomicBool>,
}

impl<S: Send + Sync + 'static> Service<S> {
    /// Create a fresh [`Session`] for a connection (and track it in the session registry). `out`
    /// is the back-channel sink.
    pub fn new_session(&self, server_state: Option<S>, out: Arc<dyn Outbound>) -> Arc<Session<S>> {
        let session =
            Arc::new(Session::new(self.id_gen.new_id(), self.name.clone(), server_state, out));
        // Register a `Weak` handle — the caller (connection task) owns the returned `Arc`.
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session.id(), Arc::downgrade(&session));
        session
    }

    /// Mark a session `CLOSED` and remove it from the session registry. (Subscription teardown is
    /// the JSON-RPC wire's concern — see [`JsonRpcProtocol::close_session`].)
    pub fn close_session(&self, session: &Session<S>) {
        session.set_lifecycle(SessionLifecycle::Closed);
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner).remove(&session.id());
    }

    /// Run a registered method by its XDR proc-id over raw XDR-encoded `params`, returning the
    /// XDR-encoded result bytes (or the [`JsonRpcError`]). The **engine-facing** op-table entry: a
    /// binary transport decodes its own envelope to `(proc_id, params)`, calls this, and wraps the
    /// outcome in its own reply framing — so a method registered once (with `.xdr(proc_id)`) is
    /// reachable over *any* binary wire, not only the built-in TXDR framing.
    ///
    /// `rid` is the optional 16-byte request id surfaced to the handler (read lazily as a UUID via
    /// `cx.id()`) and to the audit record; pass `None` when the wire carries no UUID id. The
    /// returned error's `code` lets a caller map a failure onto its own status (e.g. a
    /// `METHOD_NOT_FOUND` onto an ONC RPC `PROC_UNAVAIL`). Decode → authorize → run → audit, minus
    /// any wire framing.
    pub async fn run_proc(
        &self,
        proc_id: u32,
        rid: Option<[u8; 16]>,
        params: &[u8],
        session: &Arc<Session<S>>,
    ) -> Result<Vec<u8>, JsonRpcError> {
        let (pipeline, cx, is_async) = self.prepare_xdr(proc_id, rid, session)?;
        if is_async {
            pipeline.run_xdr_async(params, cx).await
        } else {
            let params = params.to_vec();
            match tokio::task::spawn_blocking(move || pipeline.run_xdr(&params, cx)).await {
                Ok(result) => result,
                Err(_panicked) => Err(JsonRpcError::new(ErrorCode::InternalError, "Internal error")),
            }
        }
    }

    /// The synchronous prelude shared by the binary-wire dispatch paths
    /// ([`JsonRpcProtocol::dispatch_xdr`] and [`run_proc`](Self::run_proc)): reject a closed session,
    /// look the method up by proc-id, apply the session-established gate, and build the per-request
    /// pipeline + context. Returns the ready-to-run pieces, or the [`JsonRpcError`] to reply with.
    ///
    /// **`#[inline(always)]` is load-bearing, not cosmetic.** This returns the ~100-byte pipeline by
    /// value; with two callers a plain `#[inline]` is *declined* by LLVM, leaving a real call plus a
    /// return-slot memcpy on the dispatch hot path — ~2% on the XDR cell, confirmed back-to-back.
    /// Forcing the inline folds it into each caller, so the hot path keeps the exact shape it had
    /// before this seam existed (see `PERF.md`).
    #[inline(always)]
    fn prepare_xdr(
        &self,
        proc_id: u32,
        rid: Option<[u8; 16]>,
        session: &Arc<Session<S>>,
    ) -> Result<(Pipeline<S>, RequestCtx<S>, bool), JsonRpcError> {
        if session.lifecycle() == SessionLifecycle::Closed {
            return Err(JsonRpcError::session_not_established("Session is closed"));
        }
        let method = match self.registry.xdr_methods.get(&proc_id) {
            Some(m) => m.clone(),
            None => return Err(JsonRpcError::method_not_found("Method not found")),
        };
        if self.has_session_setup
            && !method.meta.pre_auth
            && session.lifecycle() != SessionLifecycle::Established
        {
            return Err(JsonRpcError::session_not_established("Session not established"));
        }
        let audit_id =
            if method.meta.audit { rid.map(|b| uuid::Uuid::from_bytes(b).to_string()) } else { None };
        let req = if method.meta.audit {
            JsonRpcRequest {
                method: method.meta.name.to_string(),
                id: audit_id.clone(),
                params: Value::Null,
                roles: method.meta.roles.to_vec(),
            }
        } else {
            JsonRpcRequest { method: String::new(), id: None, params: Value::Null, roles: Vec::new() }
        };
        let is_async = matches!(method.imp, MethodImpl::Async(_));
        let cx = RequestCtx::new_xdr(
            rid,
            session.clone(),
            self.never_cancel.clone(),
            method.meta.audit,
            Some(self.caller.clone()),
        );
        let pipeline = Pipeline {
            method,
            session: session.clone(),
            req,
            rid: audit_id,
            audit_sink: self.audit_sink.clone(),
            py_dispatcher: None,
        };
        Ok((pipeline, cx, is_async))
    }
}

/// The dispatch core's **JSON-RPC wire-view**: the JSON envelope + the TXDR binary wire + the `$/`
/// control plane over a shared [`Service`] op-table. Build once; drive
/// [`dispatch`](Self::dispatch) with framed bytes + a per-connection [`Session`].
pub struct JsonRpcProtocol<S> {
    /// The wire-neutral op-table this JSON-RPC view serves (shared with any other wire).
    service: Arc<Service<S>>,
    version: Arc<str>,
    canceller: Option<Arc<dyn Canceller<S>>>,
    server_info: Option<Arc<dyn ServerInfoHandler<S>>>,
    session_info: Option<Arc<dyn SessionInfo<S>>>,
    setup: Option<SetupSlot<S>>,
    setup_continue: Option<SetupSlot<S>>,
    describe: Option<Box<RawValue>>,
    inflight: Mutex<HashMap<String, Inflight>>,
    /// SERVER_CLIENT subscriptions: topic -> {sub_id -> Subscription}. Runtime-mutable
    /// (subscribe/unsubscribe during dispatch), like `inflight`.
    subscriptions: Mutex<Subscriptions<S>>,
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
        &self.service.name
    }

    /// The protocol/API contract version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The wire-neutral [`Service`] op-table backing this protocol — the registered methods + run
    /// core a binary engine (e.g. ONC RPC) consumes to serve the *same* methods over its own wire.
    pub fn service(&self) -> &Arc<Service<S>> {
        &self.service
    }

    /// Whether `$/sessionSetup` authentication is configured (a network transport
    /// requires this).
    pub fn has_session_setup(&self) -> bool {
        self.service.has_session_setup
    }

    /// Create a fresh [`Session`] for a connection — delegates to the op-table's session registry
    /// ([`Service::new_session`]). `out` is the back-channel sink.
    pub fn new_session(&self, server_state: Option<S>, out: Arc<dyn Outbound>) -> Arc<Session<S>> {
        self.service.new_session(server_state, out)
    }

    /// Mark a session `CLOSED`, drop all of its subscriptions, and remove it from the session
    /// registry. Call on socket drop. (Subscriptions are JSON-RPC-wire state; the registry half is
    /// the op-table's [`Service::close_session`].)
    pub fn close_session(&self, session: &Session<S>) {
        self.unsubscribe_all(session);
        self.service.close_session(session);
    }

    /// Drop a single subscription by id. Returns `true` if it existed.
    pub fn unsubscribe(&self, sub_id: &str) -> bool {
        let mut subs = self.subscriptions.lock().unwrap_or_else(PoisonError::into_inner);
        for topic in subs.values_mut() {
            if topic.remove(sub_id).is_some() {
                return true;
            }
        }
        false
    }

    /// Drop every subscription owned by `session` (matched by session id). Returns the count.
    pub fn unsubscribe_all(&self, session: &Session<S>) -> usize {
        let sid = session.id();
        let mut removed = 0;
        let mut subs = self.subscriptions.lock().unwrap_or_else(PoisonError::into_inner);
        for topic in subs.values_mut() {
            topic.retain(|_, sub| {
                let keep = sub.session.id() != sid;
                if !keep {
                    removed += 1;
                }
                keep
            });
        }
        removed
    }

    /// The session that owns `sub_id`, if any (without removing it) — used by `$/cancelRequest`.
    fn subscription_owner(&self, sub_id: &str) -> Option<SessionId> {
        let subs = self.subscriptions.lock().unwrap_or_else(PoisonError::into_inner);
        subs.values().find_map(|topic| topic.get(sub_id).map(|s| s.session.id()))
    }

    /// Publish a notification to every subscriber of a `SERVER_CLIENT` topic. The payload is
    /// validated against the topic's notification type, encoded once, and pushed to each
    /// subscriber's [`Outbound`] back-channel (no subscribers → no-op). Returns `Err` if
    /// `topic` is not a registered SERVER_CLIENT topic, or the payload is invalid.
    pub fn send_notification<P: Serialize>(
        &self,
        topic: &str,
        payload: &P,
    ) -> Result<(), JsonRpcError> {
        let sub_impl = match self.service.registry.methods.get(topic).map(|m| &m.imp) {
            Some(MethodImpl::Subscription(s)) => s,
            _ => {
                return Err(JsonRpcError::internal(format!(
                    "{topic:?} is not a registered SERVER_CLIENT (subscribable) method"
                )))
            }
        };
        let value =
            serde_json::to_value(payload).map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
        let params = sub_impl.validate_publish(&value)?;
        let bytes = envelope::notification(topic, &params);
        let subs = self.subscriptions.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(topic_subs) = subs.get(topic) {
            for sub in topic_subs.values() {
                sub.session.outbound().send(bytes.clone());
            }
        }
        Ok(())
    }

    /// Dispatch one framed JSON-RPC message. Total — never returns an error; every
    /// protocol/handler fault becomes a wire error object inside [`Dispatched::Reply`].
    pub async fn dispatch(&self, wire: &[u8], session: &Arc<Session<S>>) -> Dispatched {
        // Wire-selection seam. A leading 4-byte TXDR magic selects the binary wire; otherwise
        // this is the JSON wire, where a frame begins with `{` (a single request object) or `[`
        // (a JSON-RPC 2.0 batch). The discriminator is unambiguous — `[` is never the TXDR magic.
        if truenas_xdr::frame::is_xdr(wire) {
            return self.dispatch_xdr(wire, session).await;
        }
        // A top-level array is a JSON-RPC 2.0 batch — always-on for the JSON wire (it is part of
        // the protocol, not a toggle). Anything else takes the single-request path.
        if first_non_ws(wire) == Some(b'[') {
            return self.dispatch_batch(wire, session).await;
        }
        self.dispatch_json_one(wire, session).await
    }

    /// The single-request JSON path: permissive envelope parse → dispatch. Reused per element by
    /// [`dispatch_batch`](Self::dispatch_batch).
    async fn dispatch_json_one(&self, wire: &[u8], session: &Arc<Session<S>>) -> Dispatched {
        let parsed = match envelope::parse(wire) {
            Ok(p) => p,
            // Parse / id / structural errors are always replied to (never suppressed).
            Err(pe) => return Dispatched::Reply(envelope::error_from_parse(&pe)),
        };
        self.dispatch_parsed(parsed, session).await
    }

    /// Dispatch a JSON-RPC 2.0 **batch**: a top-level array of request objects → an array of
    /// response objects, in one frame (<https://www.jsonrpc.org/specification#batch>). A property
    /// of the JSON wire's Envelope layer — framing, codec, the dispatch op-table, and the binary
    /// wire are all untouched. Each element runs the same single-request path
    /// ([`dispatch_json_one`](Self::dispatch_json_one)); notification elements yield no response,
    /// and the surviving response objects are concatenated into one array.
    ///
    /// Sequential (v1): response order follows request order (concurrent dispatch is spec-legal —
    /// the client matches by id — and a possible follow-on). Per spec, an empty array is itself an
    /// `INVALID_REQUEST`, and a batch of only notifications produces no reply at all.
    async fn dispatch_batch(&self, wire: &[u8], session: &Arc<Session<S>>) -> Dispatched {
        // Parse the array into raw, still-unvalidated elements (each is validated structurally on
        // its own single-request path). A leading `[` that is not a well-formed JSON array is a
        // parse error for the whole batch — one reply, id null (mirrors the single path).
        let elements: Vec<&RawValue> = match serde_json::from_slice(wire) {
            Ok(v) => v,
            Err(e) => {
                return Dispatched::Reply(envelope::error(
                    None,
                    ErrorCode::InvalidJson.code(),
                    "Parse error",
                    Some(&json!(e.to_string())),
                ))
            }
        };
        // An empty batch is itself an invalid request (per spec) — a single error object, id null.
        // Keeps the existing `[]` → INVALID_REQUEST contract; only non-empty arrays now batch.
        if elements.is_empty() {
            return Dispatched::Reply(envelope::error(
                None,
                ErrorCode::InvalidRequest.code(),
                "Invalid request",
                Some(&json!("a batch must contain at least one request")),
            ));
        }
        // Run each element through the single-request path, collecting only the elements that
        // produce a response object (a notification yields `Nothing` and is omitted, per spec).
        let mut objects: Vec<Vec<u8>> = Vec::with_capacity(elements.len());
        for element in elements {
            match self.dispatch_json_one(element.get().as_bytes(), session).await {
                Dispatched::Reply(b) => objects.push(b),
                Dispatched::Nothing => {}
                // Connection-level directives (raw-fd transfer, setup passthrough, the
                // server-assembled `$/sessions` listing) carry no inline reply and have no meaning
                // inside a batch — surface one INVALID_REQUEST per offending element.
                Dispatched::Transfer(_)
                | Dispatched::Passthrough(_)
                | Dispatched::Sessions { .. } => objects.push(envelope::error(
                    None,
                    ErrorCode::InvalidRequest.code(),
                    "Invalid request",
                    Some(&json!("this method cannot be used inside a batch")),
                )),
            }
        }
        // No surviving responses (a batch of only notifications) → no reply at all: per spec the
        // server MUST NOT return an empty array.
        if objects.is_empty() {
            return Dispatched::Nothing;
        }
        // Concatenate the response objects into one array. Each is already a complete JSON object,
        // so this is a byte join — no re-serialization.
        let mut out = Vec::with_capacity(2 + objects.iter().map(|b| b.len() + 1).sum::<usize>());
        out.push(b'[');
        for (i, obj) in objects.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(obj);
        }
        out.push(b']');
        Dispatched::Reply(out)
    }

    /// Dispatch an XDR binary-wire frame (the [`is_xdr`](truenas_xdr::frame::is_xdr) magic was
    /// already matched). v1 scope: plain + filterable methods (subscription/python over XDR reply
    /// method-not-found). Routes through [`Pipeline::run_xdr`], which mirrors the JSON sync path
    /// (`run_sync`): decode → authorize → run → audit, on the blocking pool so a slow or blocking
    /// body can't stall the async runtime. Params are typed-decoded *before* authz (INVALID_PARAMS
    /// precedes NOT_AUTHORIZED) and reflected to a JSON `Value` for the authorizer and the
    /// (redacted) audit record — XDR is non-self-describing, but the type is known here, so we
    /// reflect the decoded value (the binary-wire analogue of `raw_to_value`).
    async fn dispatch_xdr(&self, wire: &[u8], session: &Arc<Session<S>>) -> Dispatched {
        use truenas_xdr::frame;
        let request = match frame::parse_request(wire) {
            Ok(r) => r,
            // Truncated/corrupt frame: no id to echo — reply with an id-less error frame.
            Err(_) => {
                return Dispatched::Reply(
                    self.xdr_error(None, &JsonRpcError::new(ErrorCode::InvalidRequest, "Invalid request")),
                )
            }
        };
        let rid = request.rid;
        let note = rid.is_none();

        // The prelude (closed-session check, proc lookup, gate, pipeline build) is shared with
        // `Service::run_proc` via the force-inlined `Service::prepare_xdr`; its early-exits become a
        // JsonRpcError that the wrap below reframes exactly as the inline version did. The async run
        // stays inline here (the run tail, not the prelude, is the only thing not shared), so this
        // hot path's future gains no extra layer. Decode → authorize → run → audit: async inline on
        // the runtime (no `spawn_blocking` hop, no params copy); sync/filterable on the blocking pool
        // (parity with the JSON `run_sync`) so a CPU-bound or blocking handler can't stall the runtime.
        let outcome = match self.service.prepare_xdr(request.proc_id, rid, session) {
            Ok((pipeline, cx, is_async)) => {
                if is_async {
                    pipeline.run_xdr_async(request.params, cx).await
                } else {
                    let params = request.params.to_vec();
                    match tokio::task::spawn_blocking(move || pipeline.run_xdr(&params, cx)).await {
                        Ok(result) => result,
                        // A handler panic unwinds the worker thread; reply INTERNAL_ERROR (the JSON
                        // sync path does the same via `run_blocking`).
                        Err(_panicked) => {
                            Err(JsonRpcError::new(ErrorCode::InternalError, "Internal error"))
                        }
                    }
                }
            }
            Err(e) => Err(e),
        };
        let reply = match outcome {
            Ok(result_bytes) => {
                frame::build_reply_ok(rid, &result_bytes).expect("XDR reply envelope encodes")
            }
            Err(e) => self.xdr_error(rid, &e),
        };
        finish(note, reply)
    }

    /// Build an XDR error reply frame whose detail is the JSON `{code,message,data?}` object
    /// (the same bytes the JSON wire's `error` member carries).
    fn xdr_error(&self, rid: Option<[u8; 16]>, e: &JsonRpcError) -> Vec<u8> {
        let detail = envelope::error_object(e.code, &e.message, e.data.as_ref());
        truenas_xdr::frame::build_reply_err(rid, e.code, &detail).expect("XDR error frame encodes")
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
            DESCRIBE_METHOD => return self.handle_describe(parsed),
            SESSION_SETUP_METHOD => return self.handle_setup(parsed, session, true).await,
            SESSION_SETUP_CONTINUE_METHOD => return self.handle_setup(parsed, session, false).await,
            SESSION_CLOSE_METHOD => return self.handle_close(parsed, session),
            SESSIONS_METHOD => return self.handle_sessions(parsed, session),
            _ => {}
        }

        let method = match self.service.registry.methods.get(parsed.method.as_str()) {
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
        if self.service.has_session_setup
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

        // A SERVER_CLIENT topic registers a subscription instead of running a handler.
        if let MethodImpl::Subscription(sub_impl) = &method.imp {
            return self.handle_subscribe(&method, sub_impl.as_ref(), parsed, session);
        }

        // A raw-fd transfer method: authorize + negotiate here, then hand a `Transfer`
        // directive back to the server to drive the wire handshake + fd handoff.
        if let MethodImpl::FdTransfer { direction, af_unix, erased } = &method.imp {
            return self.begin_transfer(&method, *direction, *af_unix, erased.clone(), parsed, session);
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
        let cancellable = method.meta.cancellable;
        // Only cancellable methods need a fresh cancel flag + in-flight registration;
        // everything else shares the protocol's never-cancelled flag (no per-request alloc).
        let cancel = if cancellable {
            let flag = Arc::new(AtomicBool::new(false));
            if let Some(id) = &rid {
                self.inflight.lock().unwrap_or_else(PoisonError::into_inner).insert(
                    id.clone(),
                    Inflight { cancel: flag.clone(), session_id: session.id() },
                );
            }
            flag
        } else {
            self.service.never_cancel.clone()
        };
        let cx = RequestCtx::new(
            rid.clone(),
            session.clone(),
            cancel,
            method.meta.audit,
            Some(self.service.caller.clone()),
        );
        // The authz/audit snapshot (a full re-parse of params into a `Value`) is only
        // needed when an authorizer or an audited method will actually read it.
        let need_snapshot = method.meta.audit;
        // `req` (method name + params snapshot) is read only by an audited method's record or a
        // python body (`run_python` reads `req.method`); a plain method never touches it. So move
        // `parsed.method` in only when needed (mirroring the XDR path) rather than cloning it.
        let need_method = need_snapshot || matches!(method.imp, MethodImpl::Python);
        let req = JsonRpcRequest {
            method: if need_method { parsed.method } else { String::new() },
            id: rid.clone(),
            params: if need_snapshot { raw_to_value(parsed.params.as_deref()) } else { Value::Null },
            roles: if need_snapshot { method.meta.roles.to_vec() } else { Vec::new() },
        };

        // Bundle everything the decode → authorize → handler → audit stages share into a
        // single owned value, so the sync path can move it across the `spawn_blocking`
        // boundary as one argument instead of cloning six locals to thread through.
        // Sync, filterable, and python bodies all run on the blocking pool (a python body
        // holds the GIL); only an async method is awaited on the runtime.
        let is_blocking = matches!(
            method.imp,
            MethodImpl::Sync(_) | MethodImpl::Filterable(_) | MethodImpl::Python
        );
        let pipeline = Pipeline {
            method,
            session,
            req,
            rid: rid.clone(),
            audit_sink: self.service.audit_sink.clone(),
            py_dispatcher: self.service.py_dispatcher.clone(),
        };

        let response = if is_blocking {
            let params = parsed.params;
            match tokio::task::spawn_blocking(move || pipeline.run_blocking(params.as_deref(), cx)).await {
                Ok(bytes) => bytes,
                Err(_panicked) => envelope::error(
                    rid.as_deref(),
                    ErrorCode::InternalError.code(),
                    "Internal error",
                    None,
                ),
            }
        } else {
            pipeline.run_async(parsed.params, cx).await
        };

        if cancellable {
            if let Some(id) = &rid {
                self.inflight.lock().unwrap_or_else(PoisonError::into_inner).remove(id);
            }
        }
        response
    }

    /// Handle a subscribe request to a SERVER_CLIENT topic: validate params, authorize,
    /// register a [`Subscription`] (capturing the session for routing), and ack with its id.
    /// No handler runs; audited iff the topic opted in.
    fn handle_subscribe(
        &self,
        method: &Method<S>,
        sub_impl: &dyn SubscriptionImpl,
        parsed: ParsedRequest,
        session: &Arc<Session<S>>,
    ) -> Dispatched {
        let note = parsed.id.is_none();
        let rid = parsed.id;

        // 1. Validate subscribe params against the topic's Accepts (INVALID_PARAMS before authz).
        if let Err(e) = sub_impl.decode_subscribe(parsed.params.as_deref()) {
            return finish(note, envelope::error(rid.as_deref(), e.code, &e.message, e.data.as_ref()));
        }

        // 2. The authz/audit snapshot (also stored on the subscription).
        let snapshot = raw_to_value(parsed.params.as_deref());
        let need_snapshot = method.meta.audit;
        let req = JsonRpcRequest {
            method: parsed.method,
            id: rid.clone(),
            params: if need_snapshot { snapshot.clone() } else { Value::Null },
            roles: if need_snapshot { method.meta.roles.to_vec() } else { Vec::new() },
        };

        // 3. Authorize (a subscribe is a normal request — no CancelTarget).
        if let Err(denied) = role_gate(method.meta.required, session) {
            return finish(
                note,
                envelope::error(rid.as_deref(), denied.code, &denied.message, denied.data.as_ref()),
            );
        }

        // 4. Register the subscription; ack with its id.
        let sub_id = self.service.id_gen.new_id().to_string();
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(method.meta.name.clone())
            .or_default()
            .insert(sub_id.clone(), Subscription { session: session.clone(), params: snapshot });
        let raw = to_raw_value(&sub_id).expect("encoding a string cannot fail");
        let ack = envelope::success(rid.as_deref(), &raw);

        // 5. Audit (subscribe is audited iff the topic opted in; static message, no runtime detail).
        //    Reaching here means the subscribe was authorized and registered → success.
        if method.meta.audit {
            if let Some(sink) = self.service.audit_sink.as_deref() {
                audit_call(sink, &method.meta, &req, AuditOutcome::Success, None, session);
            }
        }

        finish(note, ack)
    }

    // --- raw-fd transfer -----------------------------------------------------

    /// Authorize, run the transfer method's `negotiate` callback, and return a [`Transfer`]
    /// directive (or an error envelope). The server drives the wire handshake and fd handoff
    /// from there, then calls [`Transfer::complete`]. An authorization denial or a `negotiate`
    /// failure is audited here (as a normal method's denial/error is); a transfer that
    /// proceeds is audited inside the directive's `complete` closure.
    fn begin_transfer(
        &self,
        method: &Arc<Method<S>>,
        direction: TransferDirection,
        af_unix: bool,
        erased: Arc<dyn ErasedTransfer<S>>,
        parsed: ParsedRequest,
        session: &Arc<Session<S>>,
    ) -> Dispatched {
        // A transfer has a multi-step reply ($/transferReady + a final response), so it can't
        // be a notification.
        let Some(rid) = parsed.id.clone() else {
            return Dispatched::Reply(envelope::error(
                None,
                ErrorCode::InvalidRequest.code(),
                "Invalid request",
                Some(&json!("a transfer request requires an 'id'")),
            ));
        };

        // Decode + typed-validate (INVALID_PARAMS before authz, like every method); not audited.
        let decoded = match erased.decode(parsed.params.as_deref()) {
            Ok(d) => d,
            Err(e) => return Dispatched::Reply(response_bytes(Some(&rid), &Err(e))),
        };

        let need_snapshot = method.meta.audit;
        let req = JsonRpcRequest {
            method: parsed.method.clone(),
            id: Some(rid.clone()),
            params: if need_snapshot { raw_to_value(parsed.params.as_deref()) } else { Value::Null },
            roles: if need_snapshot { method.meta.roles.to_vec() } else { Vec::new() },
        };

        // Authorize; a denial is audited (like the normal path audits an authorized call).
        if let Err(denied) = role_gate(method.meta.required, session) {
            if method.meta.audit {
                if let Some(sink) = self.service.audit_sink.as_deref() {
                    audit_call(sink, &method.meta, &req, AuditOutcome::Failure(&denied), None, session);
                }
            }
            return Dispatched::Reply(response_bytes(Some(&rid), &Err(denied)));
        }

        // Negotiate → the interim "ready" result (a refusal is audited like a handler error).
        let cx = RequestCtx::new(
            Some(rid.clone()),
            session.clone(),
            self.service.never_cancel.clone(),
            method.meta.audit,
            Some(self.service.caller.clone()),
        );
        let interim = match erased.negotiate(decoded.as_ref(), &cx) {
            Ok(raw) => raw,
            Err(e) => {
                if method.meta.audit {
                    if let Some(sink) = self.service.audit_sink.as_deref() {
                        audit_call(sink, &method.meta, &req, AuditOutcome::Failure(&e), None, session);
                    }
                }
                return Dispatched::Reply(response_bytes(Some(&rid), &Err(e)));
            }
        };

        let ready = build_transfer_ready(&rid, direction, &interim);

        // The deferred completion: after the server's handshake hands over the fd, run
        // `transfer`, build the final reply, and audit.
        let audit = method.meta.audit;
        let audit_sink = self.service.audit_sink.clone();
        let meta = method.meta.clone();
        let session = session.clone();
        let final_rid = rid.clone();
        let complete = Box::new(move |ft: &dyn FileTransfer| -> Vec<u8> {
            let outcome = erased.run_transfer(decoded, ft);
            if audit {
                if let Some(sink) = &audit_sink {
                    audit_call(sink.as_ref(), &meta, &req, audit_outcome(&outcome), None, &session);
                }
            }
            response_bytes(Some(&final_rid), &outcome)
        });

        Dispatched::Transfer(Transfer::new(rid, direction, af_unix, ready, complete))
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
            Ok(Ok(value)) => {
                // `value` is a `serde_json::Value`, which always serializes to a RawValue.
                let raw = to_raw_value(&value).expect("a serde_json::Value always serializes");
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
        finish(note, bytes)
    }

    /// `$/sessions`: a **FULL_ADMIN**-only listing of the active sessions on this protocol, so an
    /// admin can correlate an audit event's `sess=<id>` to a live session. Audited like the other
    /// control ops; a non-admin (including unauthenticated) caller is denied, and the denial is
    /// audited. Each entry is rendered by the configured [`SessionInfo`] (or the default core view).
    fn handle_sessions(&self, parsed: ParsedRequest, session: &Arc<Session<S>>) -> Dispatched {
        let note = parsed.id.is_none();
        let rid = parsed.id.clone();
        let req = JsonRpcRequest {
            method: parsed.method.clone(),
            id: rid.clone(),
            params: Value::Null,
            roles: Vec::new(),
        };

        if !session.granted_roles().is_full_admin() {
            let denied = JsonRpcError::not_authorized("Not authorized");
            self.audit_control(&req, AuditOutcome::Failure(&denied), session);
            return finish(
                note,
                envelope::error(rid.as_deref(), denied.code, &denied.message, denied.data.as_ref()),
            );
        }

        // Authorized. The listing is server-wide (across every protocol), which only the server can
        // assemble — so audit the call here and defer the aggregation to it via a directive (the
        // server walks each protocol's `render_sessions`). A no-id call is a notification → nothing.
        self.audit_control(&req, AuditOutcome::Success, session);
        match rid {
            Some(rid) => Dispatched::Sessions { rid, caller: session.id() },
            None => Dispatched::Nothing,
        }
    }

    /// Snapshot this protocol's active sessions for the `$/sessions` listing (the server calls this
    /// on every protocol and concatenates them). Upgrades each registry `Weak` under the lock (a
    /// dropped session won't upgrade), then renders off the lock via the configured [`SessionInfo`].
    pub fn render_sessions(&self, current: SessionId) -> Vec<Value> {
        // Upgrade live sessions under the lock; a dropped session won't upgrade.
        let mut live: Vec<Arc<Session<S>>> = self
            .service.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        live.sort_by_key(|s| s.created()); // stable output, oldest first (matches the TrueNAS middleware ordering)
        let now_unix = unix_now();
        live.iter().map(|s| self.render_session(s, current, now_unix)).collect()
    }

    /// Render one session for `$/sessions`: the core base entry, `current` marked for the caller,
    /// then the configured [`SessionInfo`]'s **extra** fields merged on top (embedder keys win).
    fn render_session(&self, session: &Session<S>, current: SessionId, now_unix: f64) -> Value {
        let mut base = default_session_entry(session, now_unix);
        base.insert("current".to_string(), Value::Bool(session.id() == current));
        if let Some(renderer) = &self.session_info {
            if let Value::Object(extra) = renderer.render(session) {
                base.extend(extra); // embedder fields augment / override the core base
            }
        }
        Value::Object(base)
    }

    /// `$/describe`: return the configured OpenRPC service description. Unauthenticated and
    /// ungated (like `$/serverInfo`); method-not-found when no description was provided.
    fn handle_describe(&self, parsed: ParsedRequest) -> Dispatched {
        let note = parsed.id.is_none();
        let rid = parsed.id;
        match &self.describe {
            Some(doc) => finish(note, envelope::success(rid.as_deref(), doc)),
            None => finish(
                note,
                envelope::error(
                    rid.as_deref(),
                    ErrorCode::MethodNotFound.code(),
                    "Method not found",
                    None,
                ),
            ),
        }
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

        // The error / panic paths reply + audit synchronously; a successful outcome is either a
        // synchronous commit or a connection takeover (passthrough). Setup is always audited.
        let raw_outcome = match outcome {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                self.audit_setup_outcome(
                    &parsed.method, rid.as_deref(), snapshot, &slot.meta, AuditOutcome::Failure(&e), session,
                );
                return finish(note, envelope::error(rid.as_deref(), e.code, &e.message, e.data.as_ref()));
            }
            Err(_panicked) => {
                let err = JsonRpcError::new(ErrorCode::InternalError, "Internal error");
                self.audit_setup_outcome(
                    &parsed.method, rid.as_deref(), snapshot, &slot.meta, AuditOutcome::Failure(&err), session,
                );
                return finish(note, envelope::error(rid.as_deref(), err.code, &err.message, err.data.as_ref()));
            }
        };

        match raw_outcome {
            RawSetupOutcome::Commit(new_lifecycle, raw) => {
                session.set_lifecycle(new_lifecycle);
                if let Ok(v) = serde_json::from_str::<Value>(raw.get()) {
                    session.set_external(v);
                }
                self.audit_setup_outcome(
                    &parsed.method, rid.as_deref(), snapshot, &slot.meta, AuditOutcome::Success, session,
                );
                finish(note, envelope::success(rid.as_deref(), &raw))
            }
            // Passthrough: defer the lifecycle commit + audit into a directive the server runs once
            // it has gated the connection and supplied the fd (the broker replies to the client).
            RawSetupOutcome::Takeover(handoff) => {
                let session = session.clone();
                let audit_sink = self.service.audit_sink.clone();
                let method = parsed.method.clone();
                let rid2 = rid.clone();
                let secret_fields = slot.meta.secret_fields.clone();
                let audit_message = slot.meta.audit_message.clone();
                let fd_handoff = handoff.fd_handoff;
                let complete = handoff.complete;
                let run = Box::new(move |ft: &dyn FileTransfer| {
                    let outcome = (complete)(ft);
                    if let Ok((new_lifecycle, raw)) = &outcome {
                        session.set_lifecycle(*new_lifecycle);
                        let v: Value = serde_json::from_str(raw.get()).unwrap_or(Value::Null);
                        if !v.is_null() {
                            session.set_external(v);
                        }
                    }
                    if let Some(sink) = &audit_sink {
                        audit_setup(
                            sink.as_ref(),
                            method,
                            rid2,
                            snapshot,
                            &secret_fields,
                            audit_message.as_deref(),
                            audit_outcome(&outcome),
                            &session,
                        );
                    }
                });
                Dispatched::Passthrough(SetupTakeover::new(rid, fd_handoff, run))
            }
        }
    }

    /// Audit a setup call from its structured outcome (the synchronous paths).
    fn audit_setup_outcome(
        &self,
        method: &str,
        rid: Option<&str>,
        snapshot: Value,
        meta: &MethodMeta,
        outcome: AuditOutcome<'_>,
        session: &Session<S>,
    ) {
        if let Some(sink) = &self.service.audit_sink {
            audit_setup(
                sink.as_ref(),
                method.to_string(),
                rid.map(str::to_string),
                snapshot,
                &meta.secret_fields,
                meta.audit_message.as_deref(),
                outcome,
                session,
            );
        }
    }

    /// Audit a control op (`$/sessionClose`, `$/cancelRequest`): no method metadata, so there are
    /// no `secret_fields` to redact (the params are ids, not credentials) and no static message.
    fn audit_control(&self, req: &JsonRpcRequest, outcome: AuditOutcome<'_>, session: &Session<S>) {
        if let Some(sink) = self.service.audit_sink.as_deref() {
            sink.audit(req, outcome, session, None);
        }
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
        // The session was closed → audit the successful control op (no params).
        let req = JsonRpcRequest {
            method: parsed.method,
            id: rid.clone(),
            params: Value::Null,
            roles: Vec::new(),
        };
        self.audit_control(&req, AuditOutcome::Success, session);
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

        // Resolve the target against in-flight requests first, then subscriptions (without
        // removing yet — authorize before acting). `request` carries the cancel flag.
        let request = self
            .inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&target_id)
            .map(|e| (e.cancel.clone(), e.session_id));
        let cancel_target = match &request {
            Some((_, session_id)) => Some(CancelTarget::Request { session_id: *session_id }),
            None => self
                .subscription_owner(&target_id)
                .map(|session_id| CancelTarget::Subscription { session_id }),
        };

        let req = JsonRpcRequest {
            method: parsed.method.clone(),
            id: rid.clone(),
            params: raw_to_value(parsed.params.as_deref()),
            roles: Vec::new(),
        };

        // Authorize natively BEFORE any existence error, so an unauthorized caller is denied
        // without learning whether the target exists: cancel only your own request / subscription,
        // unless you are FULL_ADMIN (who may cancel anything).
        let owns = matches!(
            cancel_target,
            Some(CancelTarget::Request { session_id } | CancelTarget::Subscription { session_id })
                if session_id == session.id()
        );
        if !owns && !session.granted_roles().is_full_admin() {
            let denied = JsonRpcError::not_authorized("Not authorized");
            self.audit_control(&req, AuditOutcome::Failure(&denied), session);
            return finish(
                note,
                envelope::error(rid.as_deref(), denied.code, &denied.message, denied.data.as_ref()),
            );
        }

        match request {
            // An in-flight request: signal cooperative cancellation + optional active abort.
            Some((cancel, _)) => {
                cancel.store(true, Ordering::Relaxed);
                if let Some(c) = &self.canceller {
                    c.cancel(&req, session);
                }
                self.audit_control(&req, AuditOutcome::Success, session);
                let raw = to_raw_value(&true).expect("encoding `true` cannot fail");
                finish(note, envelope::success(rid.as_deref(), &raw))
            }
            // A subscription (when `cancel_target` is set): drop it — a wire-level
            // unsubscribe. The `Canceller` is for in-flight requests only; not invoked here.
            None if cancel_target.is_some() => {
                self.unsubscribe(&target_id);
                self.audit_control(&req, AuditOutcome::Success, session);
                let raw = to_raw_value(&true).expect("encoding `true` cannot fail");
                finish(note, envelope::success(rid.as_deref(), &raw))
            }
            None => {
                let err = JsonRpcError {
                    code: ErrorCode::RequestFailed.code(),
                    message: "Request failed".to_string(),
                    data: Some(json!("no active request or subscription for the given id")),
                };
                self.audit_control(&req, AuditOutcome::Failure(&err), session);
                finish(note, envelope::error(rid.as_deref(), err.code, &err.message, err.data.as_ref()))
            }
        }
    }
}

// --- shared pipeline helpers -------------------------------------------------

/// The first non-whitespace byte of a frame (JSON insignificant whitespace is space, tab, LF, CR),
/// or `None` for an empty/all-whitespace frame. [`JsonRpcProtocol::dispatch`] peeks it to pick the
/// wire shape (`[` → batch) without parsing — the same leading-whitespace tolerance `serde_json`
/// and [`envelope::parse`] already apply to a `{` object.
fn first_non_ws(wire: &[u8]) -> Option<u8> {
    wire.iter().copied().find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
}

fn finish(note: bool, bytes: Vec<u8>) -> Dispatched {
    if note {
        Dispatched::Nothing
    } else {
        Dispatched::Reply(bytes)
    }
}

/// Build the `$/transferReady` notification envelope the server sends before the fd handoff:
/// `{"jsonrpc":"2.0","method":"$/transferReady","params":{"id":<rid>,"direction":<dir>,"result":<interim>}}`
/// (`result` embeds the `negotiate` interim verbatim).
fn build_transfer_ready(rid: &str, direction: TransferDirection, interim: &RawValue) -> Vec<u8> {
    #[derive(Serialize)]
    struct Params<'a> {
        id: &'a str,
        direction: TransferDirection,
        result: &'a RawValue,
    }
    #[derive(Serialize)]
    struct Ready<'a> {
        jsonrpc: &'static str,
        method: &'static str,
        params: Params<'a>,
    }
    serde_json::to_vec(&Ready {
        jsonrpc: crate::JSONRPC_VERSION,
        method: TRANSFER_READY_METHOD,
        params: Params { id: rid, direction, result: interim },
    })
    .expect("encoding the $/transferReady envelope cannot fail")
}

fn raw_to_value(params: Option<&RawValue>) -> Value {
    match params {
        Some(r) => serde_json::from_str(r.get()).unwrap_or(Value::Null),
        None => Value::Object(serde_json::Map::new()),
    }
}

/// The native authorization gate: a method's `required` roles must be a subset of the session's
/// granted roles (`FULL_ADMIN` — all-ones — and an empty requirement both pass). No closure, no
/// request materialization; resource/parameter-level checks are the handler's job.
fn role_gate<S>(required: RoleMask, session: &Session<S>) -> Result<(), JsonRpcError> {
    if session.granted_roles().satisfies(required) {
        Ok(())
    } else {
        Err(JsonRpcError::not_authorized("Not authorized"))
    }
}

/// The op registry — the two keyed tables (`methods` by name, `xdr_methods` by proc-id) sharing one
/// `Arc<Method>` per method. Shared between the protocol's wire dispatch and the in-process call
/// seam ([`Caller`]).
pub(crate) struct Registry<S> {
    pub methods: HashMap<Arc<str>, Arc<Method<S>>>,
    pub xdr_methods: HashMap<u32, Arc<Method<S>>>,
}

/// The [`InternalCaller`] impl: look a method up in the [`Registry`], gate it (unless `elevated`),
/// run it in-process, and — only under the opt-in `audit_elevated` policy — record one audit entry.
struct Caller<S> {
    registry: Arc<Registry<S>>,
    audit_sink: Option<Arc<dyn AuditSink<S>>>,
    audit_elevated: bool,
}

impl<S: Send + Sync + 'static> Caller<S> {
    async fn run(
        &self,
        method: Arc<Method<S>>,
        args: Box<dyn Any + Send>,
        cx: RequestCtx<S>,
        elevated: bool,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        // Caller-privileged by default: the same role gate the wire path applies. `elevated` skips
        // it (full admin) — for a handler that needs privileged internal state.
        if !elevated {
            role_gate(method.meta.required, cx.session())?;
        }
        // Capture what the opt-in elevated-audit record needs before `cx`/`method` are consumed.
        let audit =
            (elevated && self.audit_elevated).then(|| (method.meta.clone(), cx.session().clone()));
        let outcome = run_method_value(method, args, cx).await;
        if let (Some((meta, session)), Some(sink)) = (audit, &self.audit_sink) {
            let req = JsonRpcRequest {
                method: meta.name.to_string(),
                id: None,
                params: Value::Null,
                roles: meta.roles.to_vec(),
            };
            audit_call(sink.as_ref(), &meta, &req, audit_outcome(&outcome), None, &session);
        }
        outcome
    }
}

#[async_trait]
impl<S: Send + Sync + 'static> InternalCaller<S> for Caller<S> {
    async fn call_op(
        &self,
        op_id: u32,
        args: Box<dyn Any + Send>,
        cx: RequestCtx<S>,
        elevated: bool,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        let method = self
            .registry
            .xdr_methods
            .get(&op_id)
            .cloned()
            .ok_or_else(|| JsonRpcError::method_not_found("operation not found"))?;
        self.run(method, args, cx, elevated).await
    }
    async fn call_named(
        &self,
        name: String,
        args: Box<dyn Any + Send>,
        cx: RequestCtx<S>,
        elevated: bool,
    ) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        let method = self
            .registry
            .methods
            .get(name.as_str())
            .cloned()
            .ok_or_else(|| JsonRpcError::method_not_found("method not found"))?;
        self.run(method, args, cx, elevated).await
    }
}

/// Run a registered method on already-decoded `args`, returning its boxed typed result with **no
/// wire encode**. A **sync** (or filterable) target runs on `spawn_blocking` — so a blocking handler
/// can't stall the runtime, and concurrent internal calls run in parallel on the blocking pool; an
/// **async** target runs inline. Other method kinds aren't internally callable.
async fn run_method_value<S: Send + Sync + 'static>(
    method: Arc<Method<S>>,
    args: Box<dyn Any + Send>,
    cx: RequestCtx<S>,
) -> Result<Box<dyn Any + Send>, JsonRpcError> {
    // Async runs inline. Everything else goes to the blocking pool — a sync/filterable handler may
    // block, and concurrent internal calls then run in parallel on that pool; the blocking closure
    // also returns the "not internally callable" error for the remaining kinds (no unreachable arm).
    if let MethodImpl::Async(erased) = &method.imp {
        return erased.run_value(args, cx).await;
    }
    tokio::task::spawn_blocking(move || match &method.imp {
        MethodImpl::Sync(e) | MethodImpl::Filterable(e) => e.run_value(args, &cx),
        _ => Err(JsonRpcError::internal("method is not internally callable")),
    })
    .await
    .map_err(|_| JsonRpcError::internal("internal call handler panicked"))?
}

fn response_bytes(
    rid: Option<&str>,
    outcome: &Result<Box<RawValue>, JsonRpcError>,
) -> Vec<u8> {
    match outcome {
        Ok(raw) => envelope::success(rid, raw),
        Err(e) => envelope::error(rid, e.code, &e.message, e.data.as_ref()),
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

/// Emit one `$/sessionSetup` / `$/sessionSetupContinue` audit record (credentials redacted). A free
/// function (not a method) so the passthrough takeover closure — which runs later and can't borrow
/// the protocol — can call it with cloned bits. `outcome` is the structured setup result; the
/// credentials live in `snapshot` (the params), which is redacted here before the sink runs.
#[allow(clippy::too_many_arguments)]
fn audit_setup<S>(
    sink: &dyn AuditSink<S>,
    method: String,
    rid: Option<String>,
    mut snapshot: Value,
    secret_fields: &[String],
    audit_message: Option<&str>,
    outcome: AuditOutcome<'_>,
    session: &Session<S>,
) {
    redact_value(&mut snapshot, secret_fields);
    let req = JsonRpcRequest { method, id: rid, params: snapshot, roles: Vec::new() };
    sink.audit(&req, outcome, session, audit_message);
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

/// Emit one audit record: redact the method's `secret_fields` in the request params, join the
/// static + runtime audit message, and call the sink with the structured [`AuditOutcome`]. Shared
/// by the request pipeline ([`Pipeline::do_audit`]) and the subscribe path.
fn audit_call<S>(
    sink: &dyn AuditSink<S>,
    meta: &MethodMeta,
    req: &JsonRpcRequest,
    outcome: AuditOutcome<'_>,
    detail: Option<&str>,
    session: &Session<S>,
) {
    let message = join_audit_message(meta.audit_message.as_deref(), detail);
    // Redact the method's secret params before the record is built — the sink only ever sees
    // `********`. A method with no declared secret fields skips the clone+walk entirely.
    if meta.secret_fields.is_empty() {
        sink.audit(req, outcome, session, message.as_deref());
    } else {
        let mut audit_req = req.clone();
        redact_value(&mut audit_req.params, &meta.secret_fields);
        sink.audit(&audit_req, outcome, session, message.as_deref());
    }
}

/// Owned, `'static` context for one request's pipeline. Bundles the data the
/// decode → authorize → handler → audit stages share, so the sync path can move it
/// across the `spawn_blocking` boundary as a single value (rather than threading six
/// arguments through every stage and re-cloning each before the spawn).
struct Pipeline<S> {
    method: Arc<Method<S>>,
    session: Arc<Session<S>>,
    req: JsonRpcRequest,
    rid: Option<String>,
    audit_sink: Option<Arc<dyn AuditSink<S>>>,
    py_dispatcher: Option<Arc<dyn PyDispatcher>>,
}

/// A minimal JSON snapshot of the session handed to a python method body: the session id,
/// the lifecycle as its `u8` discriminant (0=none, 1=init, 2=established, 3=closed), and the
/// client-facing `external` setup result. The server-internal state `S` is **not**
/// serialized (so the protocol needs no `S: Serialize` bound); v1 python bodies see only this.
fn build_session_view<S>(session: &Session<S>) -> Vec<u8> {
    let view = json!({
        "session_id": session.id().to_string(),
        "lifecycle": session.lifecycle() as u8,
        "external": session.external(),
    });
    serde_json::to_vec(&view).expect("a serde_json::Value always serializes")
}

/// The core base `$/sessions` entry, as a JSON object **map** (so [`render_session`] folds in
/// `current` + any [`SessionInfo`] extras without an unreachable non-object branch): `session_id`,
/// the monotonic `age_seconds` plus the derived wall-clock `created_at`, `lifecycle`, `protocol`,
/// and — when the server / auth set them — the connection `origin` / `secure_transport`
/// / `internal` and the authenticated `credential`. An embedder's renderer augments this with the
/// per-connection identity it reads from `S` (which the generic protocol can't see).
fn default_session_entry<S>(session: &Session<S>, now_unix: f64) -> serde_json::Map<String, Value> {
    let age = session.created().elapsed().as_secs_f64();
    let mut entry = serde_json::Map::new();
    entry.insert("session_id".to_string(), json!(session.id().to_string()));
    entry.insert("age_seconds".to_string(), json!(age));
    // Wall-clock creation time derived from the monotonic `created` instant (matches the
    // TrueNAS middleware: store monotonic, present absolute) — unix epoch seconds.
    entry.insert("created_at".to_string(), json!(now_unix - age));
    entry.insert("lifecycle".to_string(), json!(session.lifecycle() as u8));
    entry.insert("protocol".to_string(), json!(session.protocol_name()));
    // Connection origin (set by the server from the peer): origin string, secure transport, and
    // whether this is an internal/system session (root over a local socket).
    if let Some(o) = session.origin() {
        entry.insert("origin".to_string(), Value::String(format_origin(o)));
        entry.insert("secure_transport".to_string(), Value::Bool(o.secure));
        entry.insert("internal".to_string(), Value::Bool(o.transport == "unix" && o.uid == Some(0)));
    }
    // Authenticated credential summary (set by the auth stack at `$/sessionSetup`).
    session.with_credential(|c| {
        if let Some(c) = c {
            entry.insert(
                "credential".to_string(),
                json!({ "description": c.description, "uid": c.uid }),
            );
        }
    });
    entry
}

/// Format a [`SessionOrigin`] for the listing: `unix:uid=N` (AF_UNIX peer-cred) or the TCP remote.
fn format_origin(o: &SessionOrigin) -> String {
    if o.transport == "unix" {
        match o.uid {
            Some(uid) => format!("unix:uid={uid}"),
            None => "unix".to_string(),
        }
    } else {
        o.remote.clone().unwrap_or_else(|| o.transport.to_string())
    }
}

/// Seconds since the Unix epoch — used to derive a wall-clock `created_at` from the monotonic age.
fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl<S: Send + Sync + 'static> Pipeline<S> {
    /// Sync pipeline (runs on a `spawn_blocking` worker): typed decode (INVALID_PARAMS,
    /// before authz so it takes precedence) → authorize → run handler → audit.
    fn run_sync(self, params: Option<&RawValue>, cx: RequestCtx<S>) -> Vec<u8> {
        let (MethodImpl::Sync(erased) | MethodImpl::Filterable(erased)) = &self.method.imp else {
            unreachable!("run_sync on a non-sync method")
        };
        let audit_detail = cx.audit_handle();
        let decoded = match erased.decode(WireParams::Json(params), false) {
            Ok((d, _)) => d,
            Err(e) => return envelope::error(self.rid.as_deref(), e.code, &e.message, e.data.as_ref()),
        };
        let outcome = match role_gate(self.method.meta.required, &self.session) {
            Err(denied) => Err(denied),
            Ok(()) => erased.run(Codec::Json, decoded, &cx).map(WireReply::into_json),
        };
        self.do_audit(audit_outcome(&outcome), &audit_detail);
        response_bytes(self.rid.as_deref(), &outcome)
    }

    /// Blocking-pool entry: route a python body through the `PyDispatcher` seam, everything
    /// else through `run_sync`. Kept here (not in `run_method`) so both share one
    /// `spawn_blocking` call + panic guard.
    fn run_blocking(self, params: Option<&RawValue>, cx: RequestCtx<S>) -> Vec<u8> {
        if matches!(self.method.imp, MethodImpl::Python) {
            self.run_python(params, cx)
        } else {
            self.run_sync(params, cx)
        }
    }

    /// Python pipeline (blocking pool): authorize (a denial is still audited), then run the
    /// body via the `PyDispatcher` seam. There is no Rust-side param decode — Python
    /// validates, so an INVALID_PARAMS comes back from the body *after* authz.
    fn run_python(self, params: Option<&RawValue>, cx: RequestCtx<S>) -> Vec<u8> {
        let audit_detail = cx.audit_handle();
        let outcome = match role_gate(self.method.meta.required, &self.session) {
            Err(denied) => Err(denied),
            Ok(()) => match &self.py_dispatcher {
                None => Err(JsonRpcError::new(ErrorCode::InternalError, "Internal error")),
                Some(dispatcher) => {
                    let params_json = params.map(|r| r.get().as_bytes()).unwrap_or(b"{}");
                    let view = build_session_view(&self.session);
                    let PyResult { outcome, audit_message } =
                        dispatcher.dispatch(self.req.method.as_str(), params_json, &view);
                    if let Some(message) = audit_message {
                        if let Some(detail) = &audit_detail {
                            *detail.lock().unwrap_or_else(PoisonError::into_inner) = Some(message);
                        }
                    }
                    match outcome {
                        PyOutcome::Ok(raw) => Ok(raw),
                        PyOutcome::Error(e) => Err(e),
                    }
                }
            },
        };
        self.do_audit(audit_outcome(&outcome), &audit_detail);
        response_bytes(self.rid.as_deref(), &outcome)
    }

    /// Async pipeline (awaited on the runtime): same stages, but `cx` is moved into the
    /// handler — audit reads the detail through the shared handle taken up front.
    async fn run_async(self, params: Option<Box<RawValue>>, cx: RequestCtx<S>) -> Vec<u8> {
        let MethodImpl::Async(erased) = &self.method.imp else {
            unreachable!("run_async on a non-async method")
        };
        let audit_detail = cx.audit_handle();
        let decoded = match erased.decode(WireParams::Json(params.as_deref()), false) {
            Ok((d, _)) => d,
            Err(e) => return envelope::error(self.rid.as_deref(), e.code, &e.message, e.data.as_ref()),
        };
        let outcome = match role_gate(self.method.meta.required, &self.session) {
            Err(denied) => Err(denied),
            Ok(()) => erased.run(Codec::Json, decoded, cx).await.map(WireReply::into_json),
        };
        self.do_audit(audit_outcome(&outcome), &audit_detail);
        response_bytes(self.rid.as_deref(), &outcome)
    }

    /// XDR pipeline (blocking pool): XDR decode (INVALID_PARAMS, before authz) → authorize → run
    /// → audit — the binary-wire analogue of [`run_sync`](Self::run_sync). The reply stays XDR
    /// bytes (returned for the caller to frame); params/result are reflected to JSON `Value`s for
    /// the authorizer and the (redacted) audit record, since XDR is non-self-describing (see
    /// [`ErasedSync::xdr_decode`]). A subscription/python method that opted into an xdr_id is not
    /// callable here → method-not-found.
    fn run_xdr(mut self, params: &[u8], cx: RequestCtx<S>) -> Result<Vec<u8>, JsonRpcError> {
        let (MethodImpl::Sync(erased) | MethodImpl::Filterable(erased)) = &self.method.imp else {
            // Subscription / python methods are not callable over the binary wire.
            return Err(JsonRpcError::method_not_found("Method not found"));
        };
        let audit_detail = cx.audit_handle();
        // Reflect params for the authorizer and/or audit (mirrors the JSON `need_snapshot`);
        // reflect the result only when the call is actually audited.
        let need_params = self.method.meta.audit;
        let want_audit = self.method.meta.audit && self.audit_sink.is_some();
        // Decode before authz; a decode failure returns here, before the audit point, so it is
        // not audited (matching the JSON path's early return).
        let (decoded, params_value) = erased.decode(WireParams::Xdr(params), need_params)?;
        if need_params {
            self.req.params = params_value;
        }
        // Audit needs the params (reflected at decode) but not the result, so `run` returns just
        // the wire bytes: no result→`Value` reflection, no envelope synthesis, no re-parse.
        let outcome = match role_gate(self.method.meta.required, &self.session) {
            Err(denied) => Err(denied),
            Ok(()) => erased.run(Codec::Xdr, decoded, &cx).map(WireReply::into_xdr),
        };
        if want_audit {
            self.do_audit(audit_outcome(&outcome), &audit_detail);
        }
        outcome
    }

    /// Inline async XDR pipeline (the async-wire analogue of [`run_xdr`](Self::run_xdr)): XDR
    /// decode (INVALID_PARAMS, before authz) → authorize → **await** run → audit, run directly on
    /// the runtime (the async handler yields, so no `spawn_blocking` hop). The reply stays XDR
    /// bytes; params/result reflect to JSON `Value`s for the authorizer / audit record exactly as
    /// the sync path does.
    async fn run_xdr_async(mut self, params: &[u8], cx: RequestCtx<S>) -> Result<Vec<u8>, JsonRpcError> {
        let MethodImpl::Async(erased) = &self.method.imp else {
            unreachable!("run_xdr_async on a non-async method")
        };
        let audit_detail = cx.audit_handle();
        let need_params = self.method.meta.audit;
        let want_audit = self.method.meta.audit && self.audit_sink.is_some();
        // Decode before authz; a decode failure returns here, before the audit point (matching the
        // JSON path's early return), so it is not audited.
        let (decoded, params_value) = erased.decode(WireParams::Xdr(params), need_params)?;
        if need_params {
            self.req.params = params_value;
        }
        // Audit needs the params (reflected at decode) but not the result, so `run` returns just
        // the wire bytes: no result→`Value` reflection, no envelope synthesis, no re-parse.
        let outcome = match role_gate(self.method.meta.required, &self.session) {
            Err(denied) => Err(denied),
            Ok(()) => erased.run(Codec::Xdr, decoded, cx).await.map(WireReply::into_xdr),
        };
        if want_audit {
            self.do_audit(audit_outcome(&outcome), &audit_detail);
        }
        outcome
    }

    /// Audit one call (success / handler error / authz denial — never a decode failure):
    /// redacts the method's `secret_fields` in the params. A no-op when the method isn't audited
    /// or no sink is configured.
    fn do_audit(
        &self,
        outcome: AuditOutcome<'_>,
        audit_detail: &Option<Arc<Mutex<Option<String>>>>,
    ) {
        if !self.method.meta.audit {
            return;
        }
        let Some(sink) = self.audit_sink.as_deref() else { return };
        // The slot is `Some` exactly when the method is audited (we're past the guard above).
        let detail =
            audit_detail.as_ref().and_then(|d| d.lock().unwrap_or_else(PoisonError::into_inner).take());
        audit_call(sink, &self.method.meta, &self.req, outcome, detail.as_deref(), &self.session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::NullOutbound;

    fn dummy_session() -> Arc<Session<()>> {
        Arc::new(Session::new(SessionId::nil(), "t".into(), Some(()), Arc::new(NullOutbound)))
    }
    fn dummy_cx(session: &Arc<Session<()>>) -> RequestCtx<()> {
        RequestCtx::new(None, session.clone(), Arc::new(AtomicBool::new(false)), false, None)
    }
    fn pipeline(method: Method<()>) -> Pipeline<()> {
        Pipeline {
            method: Arc::new(method),
            session: dummy_session(),
            req: JsonRpcRequest { method: "m".into(), id: None, params: Value::Null, roles: Vec::new() },
            rid: None,
            audit_sink: None,
            py_dispatcher: None,
        }
    }

    // Shared no-op handlers as *named functions* (not closures). The panic/subscribe tests
    // reference them without invoking them; a fresh closure there would leave an
    // un-executed closure body in the coverage map. `shared_handlers_execute` runs both so
    // their bodies are covered, and the panic tests reuse the same items.
    fn nil_ok(_a: Value, _c: &RequestCtx<()>) -> Result<Value, JsonRpcError> {
        Ok(Value::Null)
    }
    async fn nil_ok_async(_a: Value, _c: RequestCtx<()>) -> Result<Value, JsonRpcError> {
        Ok(Value::Null)
    }

    #[tokio::test]
    async fn shared_handlers_execute() {
        let proto = JsonRpcProtocol::<()>::builder("t", "1")
            .method(JsonRpcMethod::new(MethodDef::new("s"), nil_ok))
            .unwrap()
            .async_method(AsyncJsonRpcMethod::new(MethodDef::new("a"), nil_ok_async))
            .unwrap()
            .build();
        let s = proto.new_session(Some(()), Arc::new(NullOutbound));
        let id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
        for m in ["s", "a"] {
            let wire = format!(r#"{{"jsonrpc":"2.0","method":"{m}","id":"{id}"}}"#);
            assert!(matches!(proto.dispatch(wire.as_bytes(), &s).await, Dispatched::Reply(_)));
        }
    }

    // The pipeline's variant assertions are unreachable in normal dispatch (`run_method`
    // matches the kind first); call them on a mismatched method directly so the
    // `unreachable!` arms are covered and the invariant stays pinned.
    #[test]
    #[should_panic(expected = "non-sync")]
    fn run_sync_on_async_method_panics() {
        let method =
            AsyncJsonRpcMethod::new(MethodDef::new("a"), nil_ok_async).erase::<(), Value, Value, _>();
        let session = dummy_session();
        let cx = dummy_cx(&session);
        let _ = pipeline(method).run_sync(None, cx);
    }

    #[tokio::test]
    #[should_panic(expected = "non-async")]
    async fn run_async_on_sync_method_panics() {
        let method = JsonRpcMethod::new(MethodDef::new("s"), nil_ok).erase::<(), Value, Value>();
        let session = dummy_session();
        let cx = dummy_cx(&session);
        let _ = pipeline(method).run_async(None, cx).await;
    }

    #[tokio::test]
    #[should_panic(expected = "run_xdr_async on a non-async")]
    async fn run_xdr_async_on_sync_method_panics() {
        let method = JsonRpcMethod::new(MethodDef::new("s"), nil_ok).erase::<(), Value, Value>();
        let session = dummy_session();
        let cx = dummy_cx(&session);
        let _ = pipeline(method).run_xdr_async(&[], cx).await;
    }

    // (The subscribe-without-id guard and all pub/sub behavior are covered via the real
    // `.subscription(...)` API in tests/pubsub.rs.)

    #[tokio::test]
    async fn describe_returns_doc_or_method_not_found() {
        use serde_json::value::RawValue;
        let id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
        let wire = format!(r#"{{"jsonrpc":"2.0","method":"$/describe","id":"{id}"}}"#);

        // Not configured → method not found.
        let proto = JsonRpcProtocol::<()>::builder("t", "1").build();
        let s = proto.new_session(Some(()), Arc::new(NullOutbound));
        let reply = proto.dispatch(wire.as_bytes(), &s).await.into_bytes().unwrap();
        let v: Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(v["error"]["code"], -32601);

        // Configured → returns the OpenRPC doc as the result.
        let doc: Box<RawValue> = serde_json::from_str(r#"{"openrpc":"1.3.2"}"#).unwrap();
        let proto = JsonRpcProtocol::<()>::builder("t", "1").describe(doc).build();
        let s = proto.new_session(Some(()), Arc::new(NullOutbound));
        let reply = proto.dispatch(wire.as_bytes(), &s).await.into_bytes().unwrap();
        let v: Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(v["result"]["openrpc"], "1.3.2");
    }
}
