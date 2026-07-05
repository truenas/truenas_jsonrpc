//! [`Daemon`] and [`DaemonBuilder`] — the harness itself: own the runtime, load config, bind + serve
//! the registered [`Service`]s, drive signals, and run the lifecycle.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nix::sys::signal::{SigSet, Signal};
use tokio::sync::watch;
use tokio::task::JoinSet;
use truenas_ros::configfile::ConfigFile;

use crate::config::{self, Loader};
use crate::ctx::{Ctx, DaemonHandle};
use crate::error::DaemonError;
use crate::hooks::{self, Hook, Periodic, SignalHook, Task};
use crate::service::{ServeFn, Service};
use crate::{signals, systemd};

/// The `services` closure: build the servers to serve, once, from the config handle.
type ServicesFn<C> = Box<dyn FnOnce(&DaemonHandle<C>) -> Vec<Service> + Send>;
/// The config mapping: a parsed [`ConfigFile`] to the application config `C`.
type ParseFn<C> = Box<dyn Fn(&ConfigFile) -> Result<C, DaemonError> + Send + Sync>;

/// The signals the daemon always handles itself: graceful shutdown and reload.
const RESERVED: [Signal; 3] = [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP];

/// A built, runnable daemon. Construct one with [`Daemon::builder`], then [`run`](Self::run).
///
/// Generic over the application config type `C` only — each [`Service`] erases its server's session
/// type, so heterogeneous servers coexist under one `Daemon<C>`. `C` defaults to `()` for a
/// server-less / config-less daemon (use `.load_config(|| Ok(()))`).
pub struct Daemon<C = ()> {
    name: String,
    loader: Option<Loader<C>>,
    services: ServicesFn<C>,
    on_init: Vec<Hook<C>>,
    on_shutdown: Vec<Hook<C>>,
    on_reload: Vec<Hook<C>>,
    periodic: Vec<Periodic<C>>,
    tasks: Vec<Task<C>>,
    signal_hooks: Vec<SignalHook<C>>,
    grace: Duration,
    worker_threads: Option<usize>,
}

impl<C: Send + Sync + 'static> Daemon<C> {
    /// Begin building a daemon identified by `name` (used in log lines).
    pub fn builder(name: impl Into<String>) -> DaemonBuilder<C> {
        DaemonBuilder {
            name: name.into(),
            loader: None,
            config_paths: Vec::new(),
            parse: None,
            services: None,
            on_init: Vec::new(),
            on_shutdown: Vec::new(),
            on_reload: Vec::new(),
            periodic: Vec::new(),
            tasks: Vec::new(),
            signal_hooks: Vec::new(),
            grace: Duration::from_secs(10),
            worker_threads: None,
        }
    }

    /// The set of signals to block + handle: the reserved control signals plus every signal with a
    /// registered `on_signal` hook.
    fn signal_set(&self) -> SigSet {
        let mut set = SigSet::empty();
        for s in RESERVED {
            set.add(s);
        }
        for h in &self.signal_hooks {
            set.add(h.sig);
        }
        set
    }

    /// Run the daemon: **owns** a multi-threaded tokio runtime. Blocks the handled signals on the
    /// calling thread *before* the runtime's workers spawn (the race-free signalfd precondition),
    /// builds the runtime, then serves until `SIGTERM`/`SIGINT` (or a fatal task) triggers a graceful
    /// shutdown. This is the recommended entry point — call it from a synchronous `main`.
    pub fn run(self) -> Result<(), DaemonError> {
        let sigset = self.signal_set();
        signals::block(&sigset)?;
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all();
        if let Some(n) = self.worker_threads {
            builder.worker_threads(n);
        }
        let rt = builder.build()?;
        rt.block_on(self.run_inner(sigset))
    }

    /// Run the daemon on the **caller's** runtime (advanced). The caller MUST have already blocked
    /// the handled signals on every worker thread (e.g. via [`SigSet::thread_block`] before the
    /// runtime started); otherwise signal delivery is racy. Prefer [`run`](Self::run), which does
    /// this correctly by owning the runtime.
    pub async fn run_async(self) -> Result<(), DaemonError> {
        let sigset = self.signal_set();
        self.run_inner(sigset).await
    }

    async fn run_inner(self, sigset: SigSet) -> Result<(), DaemonError> {
        let Daemon {
            name,
            loader,
            services,
            on_init,
            on_shutdown,
            on_reload,
            periodic,
            tasks,
            signal_hooks,
            grace,
            worker_threads: _,
        } = self;

        let loader = loader.ok_or_else(|| {
            DaemonError::msg(
                "no config source configured: call .load_config(..), or .config_path(..) + .parse(..)",
            )
        })?;

        // Initial config — a failure here aborts startup (systemd sees a non-zero exit, no READY).
        let initial = loader()?;
        let (cfg_tx, cfg_rx) = watch::channel(Arc::new(initial));
        let (sd_tx, sd_rx) = watch::channel(false);

        let ctx = Ctx::new(cfg_rx.clone(), sd_rx.clone(), sd_tx.clone());
        let handle = DaemonHandle::new(cfg_rx.clone());

        // Build services, then bind every transport BEFORE signalling readiness — a bind failure
        // (e.g. address in use) aborts startup.
        let built = services(&handle);
        let mut serves: Vec<(String, ServeFn)> = Vec::new();
        for svc in built {
            for t in svc.into_transports() {
                let serve = (t.bind)().await?;
                serves.push((t.label, serve));
            }
        }

        // Init hooks in registration order; a failure aborts startup (before READY).
        for h in &on_init {
            h(ctx.clone()).await?;
        }

        // Warn about `on_signal` hooks for reserved signals (they never fire — see RESERVED).
        for h in &signal_hooks {
            if RESERVED.contains(&h.sig) {
                eprintln!(
                    "[{name}] warning: on_signal({}) is ignored — {} is reserved (use on_shutdown/on_reload)",
                    h.sig, h.sig
                );
            }
        }

        let afd = signals::signal_fd(&sigset)?;

        let mut set: JoinSet<()> = JoinSet::new();

        // Serve tasks — a serve error is fatal (triggers shutdown).
        for (label, serve) in serves {
            let sd = sd_rx.clone();
            let sd_tx = sd_tx.clone();
            let name = name.clone();
            set.spawn(async move {
                if let Err(e) = serve(sd).await {
                    eprintln!("[{name}] serve {label} failed: {e}");
                    let _ = sd_tx.send(true);
                }
            });
        }

        // Periodic tasks — each ticks independently; an error is logged and ticking continues.
        for p in periodic {
            let ctx = ctx.clone();
            let name = name.clone();
            set.spawn(async move {
                let start = tokio::time::Instant::now() + p.every;
                let mut interval = tokio::time::interval_at(start, p.every);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            if let Err(e) = (p.run)(ctx.clone()).await {
                                eprintln!("[{name}] periodic {:?} error: {e}", p.name);
                            }
                        }
                        _ = ctx.shutdown() => break,
                    }
                }
            });
        }

        // Managed tasks — a task error is fatal.
        for t in tasks {
            let ctx = ctx.clone();
            let name = name.clone();
            let sd_tx = sd_tx.clone();
            set.spawn(async move {
                if let Err(e) = (t.run)(ctx).await {
                    eprintln!("[{name}] task {:?} failed: {e}", t.name);
                    let _ = sd_tx.send(true);
                }
            });
        }

        // Signal dispatch loop.
        {
            let ctx = ctx.clone();
            let name = name.clone();
            let cfg_tx = cfg_tx.clone();
            let loader = loader.clone();
            let mut sigmap: HashMap<Signal, Vec<Hook<C>>> = HashMap::new();
            for sh in signal_hooks {
                sigmap.entry(sh.sig).or_default().push(sh.run);
            }
            set.spawn(async move {
                loop {
                    tokio::select! {
                        res = signals::wait_signals(&afd) => {
                            let sigs = match res {
                                Ok(s) => s,
                                Err(e) => { eprintln!("[{name}] signalfd error: {e}"); break; }
                            };
                            for sig in sigs {
                                match sig {
                                    Signal::SIGTERM | Signal::SIGINT => ctx.trigger_shutdown(),
                                    Signal::SIGHUP => {
                                        if let Err(e) = systemd::reloading() {
                                            eprintln!("[{name}] sd_notify RELOADING: {e}");
                                        }
                                        match config::reload(&loader, &cfg_tx) {
                                            Ok(()) => for h in &on_reload {
                                                if let Err(e) = h(ctx.clone()).await {
                                                    eprintln!("[{name}] reload hook error: {e}");
                                                }
                                            },
                                            Err(e) => eprintln!(
                                                "[{name}] reload failed, keeping current config: {e}"
                                            ),
                                        }
                                        if let Err(e) = systemd::ready() {
                                            eprintln!("[{name}] sd_notify READY: {e}");
                                        }
                                    }
                                    other => if let Some(hs) = sigmap.get(&other) {
                                        for h in hs {
                                            if let Err(e) = h(ctx.clone()).await {
                                                eprintln!("[{name}] signal {other} hook error: {e}");
                                            }
                                        }
                                    },
                                }
                            }
                        }
                        _ = ctx.shutdown() => break,
                    }
                    if ctx.is_shutting_down() {
                        break;
                    }
                }
            });
        }

        // Ready — listeners are bound and init is done.
        if let Err(e) = systemd::ready() {
            eprintln!("[{name}] sd_notify READY: {e}");
        }

        // Serve until shutdown is triggered (signal, fatal task, or a hook's `trigger_shutdown`).
        ctx.shutdown().await;
        if let Err(e) = systemd::stopping() {
            eprintln!("[{name}] sd_notify STOPPING: {e}");
        }

        // Best-effort drain: tasks observe the shutdown flag and exit; wait up to `grace`, then abort.
        let drain = async { while set.join_next().await.is_some() {} };
        if tokio::time::timeout(grace, drain).await.is_err() {
            eprintln!("[{name}] shutdown grace ({grace:?}) elapsed; aborting remaining tasks");
            set.abort_all();
            while set.join_next().await.is_some() {}
        }

        // Shutdown hooks in reverse registration order.
        for h in on_shutdown.iter().rev() {
            if let Err(e) = h(ctx.clone()).await {
                eprintln!("[{name}] shutdown hook error: {e}");
            }
        }

        Ok(())
    }
}

/// Builder for a [`Daemon`]. Every lifecycle registration accumulates — call `on_init`, `periodic`,
/// etc. as many times as you like.
pub struct DaemonBuilder<C = ()> {
    name: String,
    loader: Option<Loader<C>>,
    config_paths: Vec<PathBuf>,
    parse: Option<ParseFn<C>>,
    services: Option<ServicesFn<C>>,
    on_init: Vec<Hook<C>>,
    on_shutdown: Vec<Hook<C>>,
    on_reload: Vec<Hook<C>>,
    periodic: Vec<Periodic<C>>,
    tasks: Vec<Task<C>>,
    signal_hooks: Vec<SignalHook<C>>,
    grace: Duration,
    worker_threads: Option<usize>,
}

impl<C: Send + Sync + 'static> DaemonBuilder<C> {
    /// Add one INI file to read at startup and on every `SIGHUP` (missing files are skipped, like
    /// `configparser`). Pair with [`parse`](Self::parse). May be called repeatedly.
    #[must_use]
    pub fn config_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_paths.push(path.into());
        self
    }

    /// Add several INI files at once. See [`config_path`](Self::config_path).
    #[must_use]
    pub fn config_paths(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.config_paths.extend(paths);
        self
    }

    /// Map the parsed [`ConfigFile`] to the application config `C`. Runs at startup and on each
    /// `SIGHUP`; a failure at startup aborts, a failure on reload keeps the previous config.
    #[must_use]
    pub fn parse<F>(mut self, f: F) -> Self
    where
        F: Fn(&ConfigFile) -> Result<C, DaemonError> + Send + Sync + 'static,
    {
        self.parse = Some(Box::new(f));
        self
    }

    /// Set the config loader directly (the primitive underlying [`config_path`](Self::config_path) +
    /// [`parse`](Self::parse)) — for programmatic or test config. `SIGHUP` re-runs it.
    #[must_use]
    pub fn load_config<F>(mut self, f: F) -> Self
    where
        F: Fn() -> Result<C, DaemonError> + Send + Sync + 'static,
    {
        self.loader = Some(Arc::new(f));
        self
    }

    /// Register the servers to serve, as an array built once from the [`DaemonHandle`] (so each
    /// server can inject a live-config handle into its session state).
    #[must_use]
    pub fn services<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&DaemonHandle<C>) -> Vec<Service> + Send + 'static,
    {
        self.services = Some(Box::new(f));
        self
    }

    /// Add an init hook — run in registration order before readiness; an error aborts startup.
    #[must_use]
    pub fn on_init<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Ctx<C>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), DaemonError>> + Send + 'static,
    {
        self.on_init.push(hooks::hook(f));
        self
    }

    /// Add a shutdown hook — run in reverse registration order during graceful shutdown.
    #[must_use]
    pub fn on_shutdown<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Ctx<C>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), DaemonError>> + Send + 'static,
    {
        self.on_shutdown.push(hooks::hook(f));
        self
    }

    /// Add a reload hook — run in registration order after a successful `SIGHUP` re-parse + swap.
    #[must_use]
    pub fn on_reload<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Ctx<C>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), DaemonError>> + Send + 'static,
    {
        self.on_reload.push(hooks::hook(f));
        self
    }

    /// Add a periodic task run every `every` until shutdown. Each call registers an independent
    /// task, so many can run concurrently; an error is logged and ticking continues. `name` labels
    /// log lines.
    #[must_use]
    pub fn periodic<F, Fut>(mut self, name: impl Into<String>, every: Duration, f: F) -> Self
    where
        F: Fn(Ctx<C>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), DaemonError>> + Send + 'static,
    {
        self.periodic.push(Periodic {
            name: name.into(),
            every,
            run: hooks::hook(f),
        });
        self
    }

    /// Add a long-running managed task (supervised alongside the serve loops); an error is fatal.
    /// The task should observe [`Ctx::shutdown`] / [`Ctx::until_shutdown`] to exit gracefully.
    #[must_use]
    pub fn task<F, Fut>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: Fn(Ctx<C>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), DaemonError>> + Send + 'static,
    {
        self.tasks.push(Task {
            name: name.into(),
            run: hooks::hook(f),
        });
        self
    }

    /// Handle a custom signal (`SIGUSR1`, `SIGUSR2`, a real-time signal, …). Multiple hooks per
    /// signal run in registration order. `SIGTERM`/`SIGINT`/`SIGHUP` are reserved (use
    /// [`on_shutdown`](Self::on_shutdown) / [`on_reload`](Self::on_reload)).
    #[must_use]
    pub fn on_signal<F, Fut>(mut self, sig: Signal, f: F) -> Self
    where
        F: Fn(Ctx<C>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), DaemonError>> + Send + 'static,
    {
        self.signal_hooks.push(SignalHook {
            sig,
            run: hooks::hook(f),
        });
        self
    }

    /// Set the best-effort drain window given to in-flight work at shutdown (default 10 s).
    #[must_use]
    pub fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Override the runtime's worker-thread count (default: the tokio default, ~one per core). Only
    /// honored by [`Daemon::run`], which owns the runtime.
    #[must_use]
    pub fn worker_threads(mut self, n: usize) -> Self {
        self.worker_threads = Some(n);
        self
    }

    /// Finish building the [`Daemon`].
    #[must_use]
    pub fn build(self) -> Daemon<C> {
        let loader = match (self.loader, self.parse) {
            (Some(l), _) => Some(l),
            (None, Some(p)) => Some(config::ini_loader(self.config_paths, p)),
            (None, None) => None,
        };
        Daemon {
            name: self.name,
            loader,
            services: self.services.unwrap_or_else(|| Box::new(|_| Vec::new())),
            on_init: self.on_init,
            on_shutdown: self.on_shutdown,
            on_reload: self.on_reload,
            periodic: self.periodic,
            tasks: self.tasks,
            signal_hooks: self.signal_hooks,
            grace: self.grace,
            worker_threads: self.worker_threads,
        }
    }
}
