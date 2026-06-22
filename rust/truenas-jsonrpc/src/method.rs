//! Method definitions + the type-erased registry entry.
//!
//! A consumer registers a [`JsonRpcMethod`] (sync handler — the common case) or an
//! [`AsyncJsonRpcMethod`] (async handler). The handler is any closure / `fn`
//! `Fn(Accepts, &RequestCtx<S>) -> Result<Returns, JsonRpcError>` (or the async form).
//! Each erases to an internal [`Method`] whose [`MethodImpl`] kind tells `dispatch`
//! whether to run the handler on a `spawn_blocking` worker or await it. Mirrors Python
//! `truenas_pyjsonrpc.method`.

use std::any::Any;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::{to_raw_value, RawValue};
use serde_json::Value;
use truenas_filter::{
    compile_filters, compile_options, CompiledFilters, CompiledOptions, Filtered, QueryFilters,
    QueryOptions,
};

use crate::error::{ErrorCode, JsonRpcError};
use crate::request::RequestCtx;
use crate::transfer::{FileTransfer, TransferDirection};
use crate::types::MessageDirection;

pub(crate) fn decode_params<T: DeserializeOwned>(
    params: Option<&RawValue>,
) -> Result<T, JsonRpcError> {
    // Absent params decode from an empty object (Python's `_EMPTY`), so a no-arg or
    // all-optional `Accepts` succeeds and a required field fails with INVALID_PARAMS.
    let text = params.map(|r| r.get()).unwrap_or("{}");
    // Match Python's envelope shape: short message + the detail in `data`.
    serde_json::from_str(text).map_err(|e| {
        JsonRpcError::new(ErrorCode::InvalidParams, "Invalid params")
            .with_data(serde_json::Value::String(e.to_string()))
    })
}

pub(crate) fn encode_result<T: Serialize>(value: &T) -> Result<Box<RawValue>, JsonRpcError> {
    to_raw_value(value)
        .map_err(|e| JsonRpcError::new(ErrorCode::InternalError, format!("Invalid result: {e}")))
}

// --- type erasure ------------------------------------------------------------
//
// Split into `decode` (typed param validation — runs *before* authorization so
// INVALID_PARAMS precedes NOT_AUTHORIZED, matching Python) and `run` (handler + encode).
// `Accepts`/`Returns` live in the erasure struct's *self type* (`ClosureSync<A, R, F>`),
// which keeps the trait impls well-formed (no unconstrained impl params).

pub(crate) trait ErasedSync<S>: Send + Sync {
    fn decode(&self, params: Option<&RawValue>) -> Result<Box<dyn Any + Send>, JsonRpcError>;
    fn run(&self, decoded: Box<dyn Any + Send>, cx: &RequestCtx<S>)
        -> Result<Box<RawValue>, JsonRpcError>;
    /// Decode XDR-encoded params, run the handler, and XDR-encode the result — the binary
    /// wire's analogue of `decode` + `run`. (Only plain methods support it; filterable
    /// returns method-not-found.)
    fn xdr_run(&self, params: &[u8], cx: &RequestCtx<S>) -> Result<Vec<u8>, JsonRpcError>;
}

#[async_trait]
pub(crate) trait ErasedAsync<S>: Send + Sync {
    fn decode(&self, params: Option<&RawValue>) -> Result<Box<dyn Any + Send>, JsonRpcError>;
    async fn run(&self, decoded: Box<dyn Any + Send>, cx: RequestCtx<S>)
        -> Result<Box<RawValue>, JsonRpcError>;
}

struct ClosureSync<A, R, F> {
    f: F,
    _p: PhantomData<fn() -> (A, R)>,
}

impl<S, A, R, F> ErasedSync<S> for ClosureSync<A, R, F>
where
    S: Send + Sync + 'static,
    A: DeserializeOwned + Send + 'static,
    R: Serialize,
    F: Fn(A, &RequestCtx<S>) -> Result<R, JsonRpcError> + Send + Sync,
{
    fn decode(&self, params: Option<&RawValue>) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        let accepts: A = decode_params(params)?;
        Ok(Box::new(accepts))
    }
    fn run(&self, decoded: Box<dyn Any + Send>, cx: &RequestCtx<S>)
        -> Result<Box<RawValue>, JsonRpcError>
    {
        let accepts = *decoded
            .downcast::<A>()
            .expect("decoded params type matches the method");
        let result = (self.f)(accepts, cx)?;
        encode_result(&result)
    }
    fn xdr_run(&self, params: &[u8], cx: &RequestCtx<S>) -> Result<Vec<u8>, JsonRpcError> {
        let accepts: A = truenas_xdr::from_bytes(params)
            .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
        let result = (self.f)(accepts, cx)?;
        truenas_xdr::to_bytes(&result)
            .map_err(|e| JsonRpcError::internal(format!("XDR encode failed: {e}")))
    }
}

struct ClosureAsync<A, R, Fut, F> {
    f: F,
    #[allow(clippy::type_complexity)]
    _p: PhantomData<fn() -> (A, R, Fut)>,
}

#[async_trait]
impl<S, A, R, Fut, F> ErasedAsync<S> for ClosureAsync<A, R, Fut, F>
where
    S: Send + Sync + 'static,
    A: DeserializeOwned + Send + 'static,
    R: Serialize + Send,
    Fut: Future<Output = Result<R, JsonRpcError>> + Send,
    F: Fn(A, RequestCtx<S>) -> Fut + Send + Sync,
{
    fn decode(&self, params: Option<&RawValue>) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        let accepts: A = decode_params(params)?;
        Ok(Box::new(accepts))
    }
    async fn run(&self, decoded: Box<dyn Any + Send>, cx: RequestCtx<S>)
        -> Result<Box<RawValue>, JsonRpcError>
    {
        let accepts = *decoded
            .downcast::<A>()
            .expect("decoded params type matches the method");
        let result = (self.f)(accepts, cx).await?;
        encode_result(&result)
    }
}

// --- subscription (SERVER_CLIENT topic) erasure ------------------------------
//
// A subscribable topic has no handler; it carries only the subscribe-request param type
// `A` (validated like a normal method's `Accepts`) and the published-payload type `N`
// (Python's `notifies`), both living in the erased self type `SubImpl<A, N>`.

/// Erased validators for a SERVER_CLIENT topic. Independent of the server state `S`.
pub(crate) trait SubscriptionImpl: Send + Sync {
    /// Validate subscribe-request params against the topic's `Accepts` (INVALID_PARAMS on fail).
    fn decode_subscribe(&self, params: Option<&RawValue>) -> Result<(), JsonRpcError>;
    /// Validate a publish payload against the topic's `Notifies` and re-encode it canonically
    /// (mirrors Python's `msgspec.convert(payload, type=notifies)` then re-encode).
    fn validate_publish(&self, payload: &serde_json::Value) -> Result<Box<RawValue>, JsonRpcError>;
}

struct SubImpl<A, N> {
    _p: PhantomData<fn() -> (A, N)>,
}

impl<A, N> SubscriptionImpl for SubImpl<A, N>
where
    A: DeserializeOwned + 'static,
    N: DeserializeOwned + Serialize + 'static,
{
    fn decode_subscribe(&self, params: Option<&RawValue>) -> Result<(), JsonRpcError> {
        let _accepts: A = decode_params(params)?;
        Ok(())
    }
    fn validate_publish(&self, payload: &serde_json::Value) -> Result<Box<RawValue>, JsonRpcError> {
        let typed: N = serde_json::from_value(payload.clone())
            .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
        encode_result(&typed)
    }
}

// --- filterable (query) method erasure ---------------------------------------
//
// A filterable method augments its `Accepts` with optional `query-filters` /
// `query-options` (Python's `augment_accepts`), compiles them *after* authorization,
// hands the compiled query to the handler (which applies it at its source via
// `truenas_filter::tnfilter`), and applies the `get`/`count` finalize. It erases to
// `ErasedSync` — the compile/finalize live inside `run`, so dispatch treats it as sync.

/// The augmented accepts: the base `Accepts` plus the two optional query fields. Structural
/// decode (`INVALID_PARAMS`) happens before authz; the *semantic* compile happens in `run`.
#[derive(Deserialize)]
struct AugIn<A> {
    #[serde(flatten)]
    base: A,
    #[serde(rename = "query-filters", default)]
    query_filters: QueryFilters,
    #[serde(rename = "query-options", default)]
    query_options: QueryOptions,
}

struct FilterableErased<A, E, F> {
    f: F,
    _p: PhantomData<fn() -> (A, E)>,
}

impl<S, A, E, F> ErasedSync<S> for FilterableErased<A, E, F>
where
    S: Send + Sync + 'static,
    A: DeserializeOwned + Send + 'static,
    E: Serialize + 'static,
    F: Fn(A, &RequestCtx<S>, &CompiledFilters, &CompiledOptions) -> Result<Filtered<E>, JsonRpcError>
        + Send
        + Sync,
{
    fn decode(&self, params: Option<&RawValue>) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        let aug: AugIn<A> = decode_params(params)?;
        Ok(Box::new(aug))
    }
    fn run(
        &self,
        decoded: Box<dyn Any + Send>,
        cx: &RequestCtx<S>,
    ) -> Result<Box<RawValue>, JsonRpcError> {
        let aug = *decoded
            .downcast::<AugIn<A>>()
            .expect("decoded params type matches the method");
        // Compile after authz (the caller runs `run` only on an allowed request), so a bad
        // query → INVALID_PARAMS (via `From<FilterError>`) lands *after* NOT_AUTHORIZED.
        let cf = compile_filters(&aug.query_filters)?;
        let co = compile_options(&aug.query_options)?;
        let out = (self.f)(aug.base, cx, &cf, &co)?;
        finalize_json(out, &aug.query_options)
    }
    fn xdr_run(&self, params: &[u8], cx: &RequestCtx<S>) -> Result<Vec<u8>, JsonRpcError> {
        // The XDR filterable request is XDR<base> + XDR<XdrQueryOptions> + XDR<query-filters
        // as a JSON-text string> (query-filters are dynamic, so they ride as JSON text on the
        // binary wire). The result is the Zig/Python count-or-(count+entries) shape.
        let (base, xopts, filters_json): (A, XdrQueryOptions, String) =
            truenas_xdr::from_bytes(params).map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
        let filters: QueryFilters = serde_json::from_str(&filters_json)
            .map_err(|e| JsonRpcError::invalid_params(format!("query-filters: {e}")))?;
        let cf = compile_filters(&filters)?;
        let co = compile_options(&xopts.into_query_options())?;
        let out = (self.f)(base, cx, &cf, &co)?;
        finalize_xdr(out)
    }
}

/// Encode a filterable result for the **JSON** wire (Python's `finalize_result`): `count` →
/// the integer; `get` → the single record (or REQUEST_FAILED when none matched); otherwise
/// the array of entries.
fn finalize_json<E: Serialize>(
    out: Filtered<E>,
    opts: &QueryOptions,
) -> Result<Box<RawValue>, JsonRpcError> {
    match out {
        Filtered::Count(n) => encode_result(&n),
        Filtered::Rows(rows) => {
            if opts.get {
                match rows.into_iter().next() {
                    Some(e) => encode_result(&e),
                    None => Err(JsonRpcError::request_failed(
                        "no record matched query with get=True",
                    )),
                }
            } else {
                encode_result(&rows)
            }
        }
    }
}

/// Encode a filterable result for the **XDR** wire: `count` → a hyper; otherwise
/// `u32 count + entries` (the Zig/Python filterable-over-XDR result shape). `get` is not
/// offered over the binary wire (the reduced [`XdrQueryOptions`] has no `get`).
fn finalize_xdr<E: Serialize>(out: Filtered<E>) -> Result<Vec<u8>, JsonRpcError> {
    let bytes = match out {
        Filtered::Count(n) => truenas_xdr::to_bytes(&n),
        Filtered::Rows(rows) => truenas_xdr::to_bytes(&rows),
    };
    bytes.map_err(|e| JsonRpcError::internal(format!("XDR encode failed: {e}")))
}

/// The reduced `query-options` carried on the XDR wire: `count`, `order_by`, and hyper
/// `offset`/`limit` (no `get`/`select`). Field order matches the binary wire (and the Zig/
/// Python `XdrQueryOptions`).
#[derive(Deserialize)]
struct XdrQueryOptions {
    count: bool,
    order_by: Option<Vec<String>>,
    offset: i64,
    limit: i64,
}

impl XdrQueryOptions {
    fn into_query_options(self) -> QueryOptions {
        QueryOptions {
            get: false,
            count: self.count,
            order_by: self.order_by,
            offset: self.offset.max(0) as usize,
            limit: self.limit.max(0) as usize,
        }
    }
}

// --- raw-fd transfer method erasure ------------------------------------------
//
// A transfer method has two callbacks instead of one handler (Python's
// `JSONRPCFdTransferMethod`): `negotiate` runs after authz and returns the interim
// "ready" result (sent as `$/transferReady`); then — after the server's wire handshake —
// `transfer` receives the connection's [`FileTransfer`] (the raw fd) plus the typed request
// and produces the final result. The decoded request `A` is borrowed by `negotiate` and
// then *moved* into `transfer`, so a single decode serves both.

pub(crate) trait ErasedTransfer<S>: Send + Sync {
    /// Decode + validate the request params (before authz, like every other method).
    fn decode(&self, params: Option<&RawValue>) -> Result<Box<dyn Any + Send>, JsonRpcError>;
    /// Run `negotiate` over the decoded request → the interim "ready" result (encoded).
    fn negotiate(
        &self,
        decoded: &(dyn Any + Send),
        cx: &RequestCtx<S>,
    ) -> Result<Box<RawValue>, JsonRpcError>;
    /// Run `transfer` over the decoded request + the connection's fd → the final result.
    fn run_transfer(
        &self,
        decoded: Box<dyn Any + Send>,
        ft: &dyn FileTransfer,
    ) -> Result<Box<RawValue>, JsonRpcError>;
}

struct TransferErased<A, N, R, FN, FT> {
    negotiate: FN,
    transfer: FT,
    #[allow(clippy::type_complexity)]
    _p: PhantomData<fn() -> (A, N, R)>,
}

impl<S, A, N, R, FN, FT> ErasedTransfer<S> for TransferErased<A, N, R, FN, FT>
where
    S: Send + Sync + 'static,
    A: DeserializeOwned + Send + 'static,
    N: Serialize,
    R: Serialize,
    FN: Fn(&A, &RequestCtx<S>) -> Result<N, JsonRpcError> + Send + Sync,
    FT: Fn(A, &dyn FileTransfer) -> Result<R, JsonRpcError> + Send + Sync,
{
    fn decode(&self, params: Option<&RawValue>) -> Result<Box<dyn Any + Send>, JsonRpcError> {
        let accepts: A = decode_params(params)?;
        Ok(Box::new(accepts))
    }
    fn negotiate(
        &self,
        decoded: &(dyn Any + Send),
        cx: &RequestCtx<S>,
    ) -> Result<Box<RawValue>, JsonRpcError> {
        let accepts = decoded.downcast_ref::<A>().expect("decoded params type matches the method");
        let interim = (self.negotiate)(accepts, cx)?;
        encode_result(&interim)
    }
    fn run_transfer(
        &self,
        decoded: Box<dyn Any + Send>,
        ft: &dyn FileTransfer,
    ) -> Result<Box<RawValue>, JsonRpcError> {
        let accepts = *decoded.downcast::<A>().expect("decoded params type matches the method");
        let result = (self.transfer)(accepts, ft)?;
        encode_result(&result)
    }
}

// --- method metadata + flags -------------------------------------------------

/// Static per-method metadata (the non-handler half of Python's `JSONRPCMethod`).
#[derive(Clone)]
pub(crate) struct MethodMeta {
    pub name: Arc<str>,
    pub direction: MessageDirection,
    pub pre_auth: bool,
    pub audit: bool,
    pub audit_message: Option<Arc<str>>,
    pub cancellable: bool,
    pub roles: Arc<[String]>,
    #[allow(dead_code)] // surfaced via codegen/OpenRPC; not used by dispatch
    pub doc: Option<Arc<str>>,
    pub secret_fields: Arc<[String]>,
    /// If set, the method is also reachable over the XDR binary wire at this proc-id.
    pub xdr_id: Option<u32>,
}

/// A method's name + flags — the Rust analogue of Python's keyword-only `JSONRPCMethod`
/// args (`pre_auth`, `audit`, `audit_message`, `cancellable`, `roles`, `doc`,
/// `secret_fields`). Built fluently; passed to [`JsonRpcMethod::new`] /
/// [`AsyncJsonRpcMethod::new`].
pub struct MethodDef {
    name: Arc<str>,
    pre_auth: bool,
    audit: bool,
    audit_message: Option<Arc<str>>,
    cancellable: bool,
    roles: Vec<String>,
    doc: Option<Arc<str>>,
    secret_fields: Vec<String>,
    xdr_id: Option<u32>,
}

impl MethodDef {
    /// Begin a method definition named `name`, with every flag defaulted off.
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        Self {
            name: name.into(),
            pre_auth: false,
            audit: false,
            audit_message: None,
            cancellable: false,
            roles: Vec::new(),
            doc: None,
            secret_fields: Vec::new(),
            xdr_id: None,
        }
    }

    /// Allow the method **before** the session is ESTABLISHED (the pre-auth allowlist).
    pub fn pre_auth(mut self) -> Self {
        self.pre_auth = true;
        self
    }

    /// Audit every call to this method (requires an audit sink to be configured).
    pub fn audit(mut self) -> Self {
        self.audit = true;
        self
    }

    /// A static audit description (never interpolated — a secret param can't leak).
    pub fn audit_message(mut self, message: impl Into<Arc<str>>) -> Self {
        self.audit = true;
        self.audit_message = Some(message.into());
        self
    }

    /// Opt the method into `$/cancelRequest` (a cooperative cancel flag is created).
    pub fn cancellable(mut self) -> Self {
        self.cancellable = true;
        self
    }

    /// Role names the authorizer may require (OR-semantics; metadata only).
    pub fn roles<I, T>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Documentation (feeds codegen / OpenRPC).
    pub fn doc(mut self, doc: impl Into<Arc<str>>) -> Self {
        self.doc = Some(doc.into());
        self
    }

    /// Wire-names of secret fields to redact in the audit view.
    pub fn secret_fields<I, T>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.secret_fields = fields.into_iter().map(Into::into).collect();
        self
    }

    /// Make the method **also** reachable over the XDR binary wire at `proc_id` (which must
    /// be > 1000 — proc-ids 0..=1000 are reserved for control messages). v1 supports the
    /// XDR wire for plain (non-filterable, non-python) methods only.
    pub fn xdr(mut self, proc_id: u32) -> Self {
        self.xdr_id = Some(proc_id);
        self
    }

    pub(crate) fn into_meta(self, direction: MessageDirection) -> MethodMeta {
        MethodMeta {
            name: self.name,
            direction,
            pre_auth: self.pre_auth,
            audit: self.audit,
            audit_message: self.audit_message,
            cancellable: self.cancellable,
            roles: self.roles.into(),
            doc: self.doc,
            secret_fields: self.secret_fields.into(),
            xdr_id: self.xdr_id,
        }
    }
}

// --- registry entry ----------------------------------------------------------

pub(crate) enum MethodImpl<S> {
    Sync(Box<dyn ErasedSync<S>>),
    Async(Box<dyn ErasedAsync<S>>),
    /// A SERVER_CLIENT subscribable topic — no handler; carries the subscribe-param and
    /// notification-payload validators. `S`-independent.
    Subscription(Box<dyn SubscriptionImpl>),
    /// A filterable (query) method. Runs like a sync method (the compile → handler →
    /// finalize logic lives inside the erased `run`); a distinct variant only so a future
    /// `describe()`/codegen can recover its filterable-ness and `entry` type.
    Filterable(Box<dyn ErasedSync<S>>),
    /// A `python:true` method: no Rust handler. The spine routes/gates/authorizes/audits it,
    /// then runs the body via the `PyDispatcher` seam. `S`-independent (like `Subscription`).
    Python,
    /// A raw-fd transfer method. The spine routes/gates/authorizes it, runs `negotiate`, and
    /// returns a [`crate::Transfer`] directive for the server to drive the fd handoff. The
    /// erased callbacks are held in an `Arc` so the directive's deferred `complete` closure
    /// can run `transfer` after the handshake. `direction`/`af_unix` drive that handshake.
    FdTransfer {
        direction: TransferDirection,
        af_unix: bool,
        erased: Arc<dyn ErasedTransfer<S>>,
    },
}

pub(crate) struct Method<S> {
    pub meta: MethodMeta,
    pub imp: MethodImpl<S>,
}

impl<S> Method<S> {
    /// A python-backed method: carries only the method's flags (name/audit/roles/
    /// secret_fields); the body runs via the [`crate::PyDispatcher`] seam.
    pub(crate) fn python(def: MethodDef) -> Self {
        Method { meta: def.into_meta(MessageDirection::ClientServer), imp: MethodImpl::Python }
    }
}

/// A synchronous request method (the common case). Pairs a [`MethodDef`] with a sync
/// handler closure/`fn`. Mirrors Python's `JSONRPCMethod`.
pub struct JsonRpcMethod<F> {
    def: MethodDef,
    handler: F,
}

impl<F> JsonRpcMethod<F> {
    /// Pair a [`MethodDef`] with a synchronous handler.
    pub fn new(def: MethodDef, handler: F) -> Self {
        Self { def, handler }
    }

    pub(crate) fn erase<S, A, R>(self) -> Method<S>
    where
        S: Send + Sync + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(A, &RequestCtx<S>) -> Result<R, JsonRpcError> + Send + Sync + 'static,
    {
        Method {
            meta: self.def.into_meta(MessageDirection::ClientServer),
            imp: MethodImpl::Sync(Box::new(ClosureSync { f: self.handler, _p: PhantomData })),
        }
    }
}

/// An async request method (for awaitable work). Pairs a [`MethodDef`] with an async
/// handler closure. Rust-only addition; Python has no async methods.
pub struct AsyncJsonRpcMethod<F> {
    def: MethodDef,
    handler: F,
}

impl<F> AsyncJsonRpcMethod<F> {
    /// Pair a [`MethodDef`] with an asynchronous handler.
    pub fn new(def: MethodDef, handler: F) -> Self {
        Self { def, handler }
    }

    pub(crate) fn erase<S, A, R, Fut>(self) -> Method<S>
    where
        S: Send + Sync + 'static,
        A: DeserializeOwned + Send + 'static,
        R: Serialize + Send + 'static,
        Fut: Future<Output = Result<R, JsonRpcError>> + Send + 'static,
        F: Fn(A, RequestCtx<S>) -> Fut + Send + Sync + 'static,
    {
        Method {
            meta: self.def.into_meta(MessageDirection::ClientServer),
            imp: MethodImpl::Async(Box::new(ClosureAsync { f: self.handler, _p: PhantomData })),
        }
    }
}

/// A subscribable SERVER_CLIENT topic: pairs a [`MethodDef`] with the subscribe-request
/// param type `A` and the published-payload type `N` (Python's `notifies`). It has **no**
/// handler — the protocol registers a subscription and acks with its id, and the server
/// publishes via [`crate::JsonRpcProtocol::send_notification`]. Mirrors Python's
/// `JSONRPCMethod(direction=SERVER_CLIENT, notifies=...)`.
pub struct SubscriptionDef<A, N> {
    def: MethodDef,
    _p: PhantomData<fn() -> (A, N)>,
}

impl<A, N> SubscriptionDef<A, N> {
    /// Begin a subscribable topic from a [`MethodDef`]. `A` is the subscribe-request param
    /// type, `N` the published-notification payload type.
    pub fn new(def: MethodDef) -> Self {
        Self { def, _p: PhantomData }
    }

    pub(crate) fn erase<S>(self) -> Method<S>
    where
        S: Send + Sync + 'static,
        A: DeserializeOwned + 'static,
        N: DeserializeOwned + Serialize + 'static,
    {
        Method {
            meta: self.def.into_meta(MessageDirection::ServerClient),
            imp: MethodImpl::Subscription(Box::new(SubImpl::<A, N> { _p: PhantomData })),
        }
    }
}

/// A **filterable** (query) request method. Pairs a [`MethodDef`] with a handler that
/// receives the base params plus the compiled `query-filters` / `query-options` and applies
/// them at its source — typically by streaming a lazy source through
/// [`truenas_filter::tnfilter`] — returning a [`Filtered`]. The framework augments
/// `accepts`, compiles the query after authorization, and applies the `get`/`count`
/// finalize. Mirrors Python's `FilterableJSONRPCMethod`.
///
/// `A` is the base accepts type; `E` is the list element (`entry`) type — metadata for a
/// future `describe()`/codegen (Python's `entry`), carried as `PhantomData` and unused at
/// runtime (the result is encoded as-is, like Python's `returns=None`).
pub struct FilterableJsonRpcMethod<A, E, F> {
    def: MethodDef,
    handler: F,
    _p: PhantomData<fn() -> (A, E)>,
}

impl<A, E, F> FilterableJsonRpcMethod<A, E, F> {
    /// Pair a [`MethodDef`] with a filterable handler. The handler is
    /// `Fn(Accepts, &RequestCtx<S>, &CompiledFilters, &CompiledOptions) -> Result<Filtered, JsonRpcError>`.
    pub fn new(def: MethodDef, handler: F) -> Self {
        Self { def, handler, _p: PhantomData }
    }

    pub(crate) fn erase<S>(self) -> Method<S>
    where
        S: Send + Sync + 'static,
        A: DeserializeOwned + Send + 'static,
        E: Serialize + 'static,
        F: Fn(A, &RequestCtx<S>, &CompiledFilters, &CompiledOptions) -> Result<Filtered<E>, JsonRpcError>
            + Send
            + Sync
            + 'static,
    {
        Method {
            meta: self.def.into_meta(MessageDirection::ClientServer),
            imp: MethodImpl::Filterable(Box::new(FilterableErased::<A, E, F> {
                f: self.handler,
                _p: PhantomData,
            })),
        }
    }
}

/// A **raw-fd transfer** method (e.g. `zfs send`/`recv` via libzfs). Two callbacks instead of
/// one handler (mirrors Python's `JSONRPCFdTransferMethod`):
///
/// - `negotiate: Fn(&A, &RequestCtx<S>) -> Result<N, JsonRpcError>` runs after authorization,
///   validates the request, and returns the **interim** "ready" result `N` (sent to the
///   client as `$/transferReady`); return an error to refuse.
/// - `transfer: Fn(A, &dyn FileTransfer) -> Result<R, JsonRpcError>` then receives the
///   connection's raw fd (via the server crate's concrete [`FileTransfer`]) plus the decoded
///   request, streams the bulk data, and returns the final result `R`.
///
/// `direction` is [`TransferDirection::Download`] (server produces) or
/// [`TransferDirection::Upload`] (server consumes). Transfers require a plain or kTLS
/// connection (the fd must carry plaintext) — see `truenas-jsonrpc-server`.
pub struct JsonRpcFdTransferMethod<A, N, R, FN, FT> {
    def: MethodDef,
    direction: TransferDirection,
    negotiate: FN,
    transfer: FT,
    af_unix: bool,
    #[allow(clippy::type_complexity)]
    _p: PhantomData<fn() -> (A, N, R)>,
}

impl<A, N, R, FN, FT> JsonRpcFdTransferMethod<A, N, R, FN, FT> {
    /// Pair a [`MethodDef`] with a transfer `direction` and the `negotiate` / `transfer`
    /// callbacks.
    pub fn new(def: MethodDef, direction: TransferDirection, negotiate: FN, transfer: FT) -> Self {
        Self { def, direction, negotiate, transfer, af_unix: false, _p: PhantomData }
    }

    pub(crate) fn erase<S>(self) -> Method<S>
    where
        S: Send + Sync + 'static,
        A: DeserializeOwned + Send + 'static,
        N: Serialize + 'static,
        R: Serialize + 'static,
        FN: Fn(&A, &RequestCtx<S>) -> Result<N, JsonRpcError> + Send + Sync + 'static,
        FT: Fn(A, &dyn FileTransfer) -> Result<R, JsonRpcError> + Send + Sync + 'static,
    {
        Method {
            meta: self.def.into_meta(MessageDirection::ClientServer),
            imp: MethodImpl::FdTransfer {
                direction: self.direction,
                af_unix: self.af_unix,
                erased: Arc::new(TransferErased::<A, N, R, FN, FT> {
                    negotiate: self.negotiate,
                    transfer: self.transfer,
                    _p: PhantomData,
                }),
            },
        }
    }
}

/// A **file-descriptor passing** method — `SCM_RIGHTS` over an AF_UNIX connection. Identical
/// to [`JsonRpcFdTransferMethod`], but the `transfer` callback passes/receives open fds (via
/// the server crate's `FileTransfer` `SCM_RIGHTS` helpers) instead of streaming bytes.
/// **AF_UNIX only** — the server rejects a call over any other transport with `REQUEST_FAILED`.
pub struct JsonRpcFdPassMethod<A, N, R, FN, FT> {
    inner: JsonRpcFdTransferMethod<A, N, R, FN, FT>,
}

impl<A, N, R, FN, FT> JsonRpcFdPassMethod<A, N, R, FN, FT> {
    /// Pair a [`MethodDef`] with a transfer `direction` and the `negotiate` / `transfer`
    /// callbacks; the connection must be AF_UNIX.
    pub fn new(def: MethodDef, direction: TransferDirection, negotiate: FN, transfer: FT) -> Self {
        let mut inner = JsonRpcFdTransferMethod::new(def, direction, negotiate, transfer);
        inner.af_unix = true;
        Self { inner }
    }

    pub(crate) fn erase<S>(self) -> Method<S>
    where
        S: Send + Sync + 'static,
        A: DeserializeOwned + Send + 'static,
        N: Serialize + 'static,
        R: Serialize + 'static,
        FN: Fn(&A, &RequestCtx<S>) -> Result<N, JsonRpcError> + Send + Sync + 'static,
        FT: Fn(A, &dyn FileTransfer) -> Result<R, JsonRpcError> + Send + Sync + 'static,
    {
        self.inner.erase()
    }
}

impl From<truenas_filter::FilterError> for JsonRpcError {
    /// Bridge a query-engine failure into a JSON-RPC error so a handler can `tnfilter(..)?`:
    /// a compile-time `Compile` is `INVALID_PARAMS`; a runtime `Eval` (incomparable types,
    /// etc.) is `INTERNAL_ERROR` — matching Python, where a `tnfilter` `TypeError` propagates
    /// uncaught out of the handler.
    fn from(e: truenas_filter::FilterError) -> Self {
        match &e {
            // "invalid query: …" (matches Python's `compile_query` wrapping + the C message).
            truenas_filter::FilterError::Compile(_) => JsonRpcError::invalid_params(e.to_string()),
            // Generic message + detail in `data`, like Python's uncaught-handler-exception path.
            truenas_filter::FilterError::Eval(m) => {
                JsonRpcError::new(ErrorCode::InternalError, "Internal error")
                    .with_data(Value::String(m.clone()))
            }
        }
    }
}
