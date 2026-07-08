//! [`LinuxAuditSink`] — the [`AuditSink`] implementation + its drain thread.
//!
//! `audit()` runs on the dispatch path (inline on the async runtime for async methods, on the
//! blocking pool for sync ones), so it must not block: it only extracts the principal, formats the
//! record (cheap, pure string work), and does a **non-blocking** channel push. A dedicated drain
//! thread owns the `NETLINK_AUDIT` socket and performs the (blocking) `sendmsg` + ack off the
//! dispatch path. Auditing must never break or block dispatch, so overflow is dropped and
//! counted, and the sink never panics.
//!
//! **Why a dedicated thread and not an async send?** The kernel audit subsystem applies
//! *backpressure*: when `auditd` can't keep up and the kernel's `audit_queue` grows past
//! `audit_backlog_limit` (default 64), the netlink `sendmsg` neither fails nor yields — instead
//! `kernel/audit.c:audit_receive()` parks the **calling thread** in `TASK_UNINTERRUPTIBLE` for up to
//! `audit_backlog_wait_time` (default `60*HZ`, i.e. 60 s), in the sender's own syscall context. That
//! stall is gated on backlog depth, **not** on the socket's `O_NONBLOCK` flag, so it can't be made
//! non-blocking or driven through `AsyncFd` — inlining the send would freeze a tokio reactor worker
//! for seconds. Confining that (rare, bounded) block to this drain thread is the only safe option,
//! and the bounded queue + drop-and-count is how we shed load when the kernel pushes back on *us*.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use truenas_rpc::{AuditOutcome, AuditSink, IdGen, RequestInfo, Session, UuidGen};

use super::netlink::{AuditSocket, SendStatus};
use super::record::{build_record, lost_record, AuditPrincipal};

type Extractor<S> = Box<dyn Fn(&Session<S>) -> AuditPrincipal + Send + Sync>;

/// An [`AuditSink`] that emits each audited call to the Linux kernel audit subsystem
/// (`NETLINK_AUDIT` → auditd). Build it with [`LinuxAuditSink::builder`] and register it with
/// `JsonRpcProtocolBuilder::audit_sink`.
pub struct LinuxAuditSink<S> {
    tx: SyncSender<(u16, String)>,
    service: String,
    extract: Extractor<S>,
    dropped: Arc<AtomicU64>,
}

impl<S> LinuxAuditSink<S> {
    /// Start building a sink for `service` — the `svc=` value and the `op=<service>:<verb>`
    /// namespace (e.g. `"truenas-api"`).
    pub fn builder(service: impl Into<String>) -> LinuxAuditSinkBuilder<S> {
        LinuxAuditSinkBuilder {
            service: service.into(),
            extract: None,
            queue_bound: 1024,
        }
    }

    /// Records currently dropped-but-not-yet-surfaced because the queue was full (the drain thread
    /// emits a `lost=N` record and resets this as it catches up). A monitoring gauge.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl<S: Send + Sync + 'static> AuditSink<S> for LinuxAuditSink<S> {
    fn audit(
        &self,
        request: &RequestInfo,
        outcome: AuditOutcome<'_>,
        session: &Session<S>,
        audit_message: Option<&str>,
    ) {
        let principal = (self.extract)(session);
        let aid = UuidGen.new_id().to_string();
        let sess = session.id().to_string();
        let record = build_record(
            &self.service,
            &aid,
            &sess,
            request,
            outcome,
            &principal,
            audit_message,
        );
        // Non-blocking: a full queue drops + counts rather than stalling dispatch.
        if self.tx.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Builder for [`LinuxAuditSink`].
pub struct LinuxAuditSinkBuilder<S> {
    service: String,
    extract: Option<Extractor<S>>,
    queue_bound: usize,
}

impl<S: Send + Sync + 'static> LinuxAuditSinkBuilder<S> {
    /// Set the identity extractor: map a session to the [`AuditPrincipal`] (user / uid / origin /
    /// credential) the record describes — read it out of the session's internal state. Required for
    /// non-anonymous records (default: an empty principal).
    #[must_use]
    pub fn identity(
        mut self,
        f: impl Fn(&Session<S>) -> AuditPrincipal + Send + Sync + 'static,
    ) -> Self {
        self.extract = Some(Box::new(f));
        self
    }

    /// Bound the in-flight record queue (default 1024). When full, records are dropped and counted
    /// (surfaced as a `lost=N` audit record) — auditing never blocks dispatch.
    #[must_use]
    pub fn queue_bound(mut self, n: usize) -> Self {
        self.queue_bound = n.max(1);
        self
    }

    /// Spawn the drain thread and freeze the sink. **Infallible** — if the audit socket can't open
    /// (no kernel `NETLINK_AUDIT` support), the drain thread logs once and the sink no-ops.
    pub fn build(self) -> LinuxAuditSink<S> {
        let extract: Extractor<S> = self
            .extract
            .unwrap_or_else(|| Box::new(|_: &Session<S>| AuditPrincipal::default()));
        let (tx, rx) = sync_channel::<(u16, String)>(self.queue_bound);
        let dropped = Arc::new(AtomicU64::new(0));
        let drain_dropped = dropped.clone();
        let drain_service = self.service.clone();
        thread::Builder::new()
            .name("truenas-audit".into())
            .spawn(move || drain_loop(rx, drain_service, drain_dropped))
            .expect("spawn audit drain thread");
        LinuxAuditSink {
            tx,
            service: self.service,
            extract,
            dropped,
        }
    }
}

/// The drain thread: own the audit socket, send each queued record (emitting a `lost=N` record for
/// any overflow drops first), de-duplicating repeated socket errors. Exits when the sink (and its
/// sender) drops and the channel closes.
fn drain_loop(rx: Receiver<(u16, String)>, service: String, dropped: Arc<AtomicU64>) {
    let mut socket = match AuditSocket::open() {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("truenas-audit: cannot open NETLINK_AUDIT socket ({e}); auditing disabled");
            None
        }
    };
    let mut unavailable_logged = false;
    let mut last_err: Option<i32> = None;
    while let Ok((ty, msg)) = rx.recv() {
        let Some(sock) = socket.as_mut() else {
            continue;
        }; // disabled → drain + discard
        let lost = dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let (lt, lm) = lost_record(&service, lost);
            let _ = sock.send(lt, &lm);
        }
        match sock.send(ty, &msg) {
            Ok(SendStatus::Delivered) => last_err = None,
            Ok(SendStatus::Unavailable) => {
                if !unavailable_logged {
                    eprintln!(
                        "truenas-audit: kernel audit unavailable (no CAP_AUDIT_WRITE or audit off); records dropped"
                    );
                    unavailable_logged = true;
                }
            }
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(-1);
                if last_err != Some(code) {
                    eprintln!("truenas-audit: send failed ({e})");
                    last_err = Some(code);
                }
            }
        }
    }
}
