//! [`Ctx`] — the per-hook handle (config snapshot + shutdown), and [`DaemonHandle`] — the handle the
//! `services` closure gets at build time (config only).

use std::future::Future;
use std::sync::Arc;

use tokio::sync::watch;

/// The handle handed (by value) to every lifecycle hook — `on_init` / `on_shutdown` / `on_reload` /
/// `periodic` / `task` / `on_signal`. Cheap to clone (all `Arc`/channel handles inside), so a hook
/// can move it into spawned work.
pub struct Ctx<C> {
    config: watch::Receiver<Arc<C>>,
    shutdown: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
}

// Manual `Clone` (not derived) so it does not require `C: Clone`.
impl<C> Clone for Ctx<C> {
    fn clone(&self) -> Self {
        Ctx {
            config: self.config.clone(),
            shutdown: self.shutdown.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }
}

impl<C> Ctx<C> {
    pub(crate) fn new(
        config: watch::Receiver<Arc<C>>,
        shutdown: watch::Receiver<bool>,
        shutdown_tx: watch::Sender<bool>,
    ) -> Self {
        Ctx {
            config,
            shutdown,
            shutdown_tx,
        }
    }

    /// The current configuration snapshot. On a successful `SIGHUP` reload this returns the new
    /// value; a failed reload leaves the previous value in place.
    pub fn config(&self) -> Arc<C> {
        self.config.borrow().clone()
    }

    /// A receiver that yields a fresh `Arc<C>` on every successful reload — for work that wants to
    /// react to config changes rather than re-reading [`config`](Self::config) each time.
    pub fn config_rx(&self) -> watch::Receiver<Arc<C>> {
        self.config.clone()
    }

    /// Whether graceful shutdown has begun.
    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    /// Resolves once graceful shutdown has begun (immediately if it already has).
    pub async fn shutdown(&self) {
        let mut rx = self.shutdown.clone();
        if *rx.borrow() {
            return;
        }
        // `Err` means the sender was dropped (daemon tearing down) — treat as shutdown.
        let _ = rx.wait_for(|v| *v).await;
    }

    /// Ask the daemon to begin graceful shutdown (as if a `SIGTERM` had arrived).
    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Run `fut` until it completes or shutdown begins, whichever is first. Returns `Some(output)` if
    /// `fut` finished, or `None` if shutdown pre-empted it — the idiom for a long-running `task`.
    pub async fn until_shutdown<F: Future>(&self, fut: F) -> Option<F::Output> {
        tokio::pin!(fut);
        tokio::select! {
            out = &mut fut => Some(out),
            _ = self.shutdown() => None,
        }
    }
}

/// The handle passed to the `services` closure at build time: it exposes the configuration so a
/// service can inject a live-config handle into its session state (e.g. capture
/// [`config_rx`](Self::config_rx) into `state_from_peer`). Cheap to clone.
pub struct DaemonHandle<C> {
    config: watch::Receiver<Arc<C>>,
}

impl<C> Clone for DaemonHandle<C> {
    fn clone(&self) -> Self {
        DaemonHandle {
            config: self.config.clone(),
        }
    }
}

impl<C> DaemonHandle<C> {
    pub(crate) fn new(config: watch::Receiver<Arc<C>>) -> Self {
        DaemonHandle { config }
    }

    /// The current configuration snapshot at build time.
    pub fn config(&self) -> Arc<C> {
        self.config.borrow().clone()
    }

    /// A receiver that yields a fresh `Arc<C>` on every successful reload — capture this into a
    /// service's session state so handlers observe live config.
    pub fn config_rx(&self) -> watch::Receiver<Arc<C>> {
        self.config.clone()
    }
}
