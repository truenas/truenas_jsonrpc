//! Internal boxed storage for the lifecycle hooks. A hook is any `Fn(Ctx<C>) -> impl Future<Output =
//! Result<(), DaemonError>>`; [`hook`] erases one into the stored [`Hook`] shape.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use nix::sys::signal::Signal;

use crate::ctx::Ctx;
use crate::error::DaemonError;

/// The boxed future a hook returns.
pub(crate) type HookFut = Pin<Box<dyn Future<Output = Result<(), DaemonError>> + Send>>;

/// A stored lifecycle hook: takes a [`Ctx`] by value, returns a boxed future.
pub(crate) type Hook<C> = Box<dyn Fn(Ctx<C>) -> HookFut + Send + Sync>;

/// Erase a user closure `Fn(Ctx<C>) -> Fut` into a [`Hook`].
pub(crate) fn hook<C, F, Fut>(f: F) -> Hook<C>
where
    F: Fn(Ctx<C>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), DaemonError>> + Send + 'static,
{
    Box::new(move |ctx| Box::pin(f(ctx)))
}

/// A registered periodic task: run `run` every `every`, until shutdown. `name` is a log label.
pub(crate) struct Periodic<C> {
    pub(crate) name: String,
    pub(crate) every: Duration,
    pub(crate) run: Hook<C>,
}

/// A registered long-running managed task. `name` is a log label.
pub(crate) struct Task<C> {
    pub(crate) name: String,
    pub(crate) run: Hook<C>,
}

/// A registered custom-signal handler.
pub(crate) struct SignalHook<C> {
    pub(crate) sig: Signal,
    pub(crate) run: Hook<C>,
}
