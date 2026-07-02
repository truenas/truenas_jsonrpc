//! The TrueNAS RPC stack's utilities that require `unsafe` — direct kernel syscalls / FFI — collected
//! in one **opt-in** crate so the core and the rest of the workspace stay `unsafe_code = "forbid"`.
//! Each utility is an independent, feature-gated module pulling only its own dependencies:
//!
//! - [`keyring`] (feature `keyring`) — a config-driven Linux kernel-keyring store for SCRAM verifiers
//!   / peer credentials (`add_key` / `keyctl` via `libc`).
//! - [`audit`] (feature `audit`) — a [`truenas_rpc::AuditSink`](truenas_rpc) backend writing records
//!   to `NETLINK_AUDIT`.
//! - [`gssapi`] (feature `gssapi`) — a minimal hand-written FFI to the system GSSAPI (MIT krb5)
//!   acceptor (~6 functions of the frozen RFC 2744 ABI).
//!
//! `unsafe` is `deny`-by-default with a per-site `#[allow(unsafe_code)]` + `// SAFETY:` at each call.
//! The `gssapi` feature links system krb5, so this crate is not a workspace `default-member`.

#[cfg(feature = "audit")]
pub mod audit;
#[cfg(feature = "gssapi")]
pub mod gssapi;
#[cfg(feature = "keyring")]
pub mod keyring;
