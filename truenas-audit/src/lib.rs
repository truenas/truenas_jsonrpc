//! Linux kernel audit backend for [`truenas_rpc`]'s audit seam.
//!
//! [`LinuxAuditSink`] implements [`truenas_rpc::AuditSink`] by writing one record per audited
//! call to the kernel audit subsystem over a `NETLINK_AUDIT` socket — so audit lands in
//! `/var/log/audit/audit.log` and is queryable with `ausearch`/`aureport`, alongside PAM's records.
//!
//! Records follow linux-PAM's field conventions — `op=<service>:<verb>`, `acct=`, `addr=`,
//! `res=success|failed`, and the right `AUDIT_USER_*` / `AUDIT_TRUSTED_APP` type per event — and
//! then carry the TrueNAS audit payload **flattened** to native, `ausearch`-greppable fields:
//! `svc_*` (service/credential context) and `event_data_<key>` (one field per request param; a
//! nested value is stringified to JSON). Secret fields arrive already redacted by the core, so they
//! flatten to `event_data_<key>=********`.
//!
//! The netlink `sendmsg` runs on a **dedicated drain thread**, so the sink never blocks the dispatch
//! path (`audit()` only formats the record and does a non-blocking queue push). Missing
//! `CAP_AUDIT_WRITE` or a disabled kernel audit is a benign no-op, not an error.
//!
//! Own the `NETLINK_AUDIT` syscall surface directly (audited `unsafe` over `libc`, confined to
//! [`netlink`]) rather than depend on the stale, ~zero-adoption rust-netlink `audit` crate —
//! matching the `truenas-keyring`/`truenas-nss` policy.
//!
//! ```no_run
//! use truenas_audit::{AuditPrincipal, LinuxAuditSink};
//! use truenas_rpc::Session;
//!
//! // `S` is your per-session state; read the identity out of it for the record.
//! let sink = LinuxAuditSink::<()>::builder("truenas-api")
//!     .identity(|_session: &Session<()>| AuditPrincipal {
//!         user: Some("admin".into()),
//!         cred_type: Some("API_KEY".into()),
//!         ..Default::default()
//!     })
//!     .build();
//! // let proto = JsonRpcProtocol::<()>::builder("conf", "1").audit_sink(sink).build();
//! ```

mod netlink;
mod record;
mod sink;

pub use record::AuditPrincipal;
pub use sink::{LinuxAuditSink, LinuxAuditSinkBuilder};
