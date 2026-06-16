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
use serde::Serialize;
use serde_json::value::{to_raw_value, RawValue};

use crate::error::{ErrorCode, JsonRpcError};
use crate::request::RequestCtx;
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
}

impl MethodDef {
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
        }
    }
}

// --- registry entry ----------------------------------------------------------

pub(crate) enum MethodImpl<S> {
    Sync(Box<dyn ErasedSync<S>>),
    Async(Box<dyn ErasedAsync<S>>),
}

pub(crate) struct Method<S> {
    pub meta: MethodMeta,
    pub imp: MethodImpl<S>,
}

/// A synchronous request method (the common case). Pairs a [`MethodDef`] with a sync
/// handler closure/`fn`. Mirrors Python's `JSONRPCMethod`.
pub struct JsonRpcMethod<F> {
    def: MethodDef,
    handler: F,
}

impl<F> JsonRpcMethod<F> {
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
