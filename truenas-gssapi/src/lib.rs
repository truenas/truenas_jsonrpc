//! A minimal safe wrapper over the system GSSAPI (MIT krb5) **acceptor**, for the
//! `truenas-rpc-auth` native Kerberos mechanism.
//!
//! Binds ~6 functions of the frozen RFC 2744 C ABI directly (see [`sys`]) instead of depending on
//! `libgssapi` (which pulls `bindgen` → `clang-sys` + a libclang build requirement). The only API
//! is [`ServerCtx`]: create it, drive the handshake with [`step`](ServerCtx::step) until
//! [`is_complete`](ServerCtx::is_complete), then read the authenticated principal with
//! [`source_name`](ServerCtx::source_name).

mod sys;

use std::fmt;
use std::ptr;

/// A GSSAPI failure — the `major` (generic) / `minor` (mechanism) status pair from a failed call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// The GSS major status (generic API error bits).
    pub major: u32,
    /// The mechanism-specific minor status.
    pub minor: u32,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GSSAPI error (major=0x{:08x}, minor={})", self.major, self.minor)
    }
}

impl std::error::Error for Error {}

#[derive(PartialEq, Eq)]
enum State {
    InProgress,
    Complete,
}

/// A server-side (acceptor) GSSAPI security context over the host keytab.
///
/// Drive the handshake by feeding each client token to [`step`](Self::step); while it returns and
/// [`is_complete`](Self::is_complete) is `false`, send the returned reply token back and call again.
/// Once complete, [`source_name`](Self::source_name) yields the authenticated initiator principal.
pub struct ServerCtx {
    ctx: sys::gss_ctx_id_t,
    state: State,
}

// SAFETY: `ServerCtx` owns a `gss_ctx_id_t` (an opaque handle into libgssapi_krb5). The handle is
// only ever touched through `&mut self`/`&self` methods on a single owner — never shared or aliased
// — so moving it to another thread is sound. This is the same guarantee `libgssapi`'s own
// `unsafe impl Send for ServerCtx` relies on. `ServerCtx` is intentionally NOT `Sync`.
#[allow(unsafe_code)]
unsafe impl Send for ServerCtx {}

impl ServerCtx {
    /// A fresh acceptor using the default credential (`GSS_C_NO_CREDENTIAL` → the host keytab, e.g.
    /// `KRB5_KTNAME`).
    pub fn new() -> Self {
        Self { ctx: ptr::null_mut(), state: State::InProgress }
    }

    /// Process the client's `token` (with an optional TLS `channel_binding`) and return the server's
    /// reply token to send back — possibly empty. After this returns `Ok`, check
    /// [`is_complete`](Self::is_complete); an `Err` is a hard GSS failure (bad/forged/expired token,
    /// no keytab, …) and the context must not be used further.
    pub fn step(&mut self, token: &[u8], channel_binding: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let out = sys::accept_step(&mut self.ctx, token, channel_binding);
        if sys::gss_error(out.major) != 0 {
            return Err(Error { major: out.major, minor: out.minor });
        }
        self.state = if out.major & sys::GSS_S_CONTINUE_NEEDED != 0 {
            State::InProgress
        } else {
            State::Complete
        };
        Ok(out.token)
    }

    /// Whether the handshake has completed (the context is established).
    pub fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    /// The authenticated initiator principal (e.g. `alice@EXAMPLE.COM`). Only meaningful once
    /// [`is_complete`](Self::is_complete) is `true`.
    pub fn source_name(&self) -> Result<String, Error> {
        sys::source_name(self.ctx).map_err(|(major, minor)| Error { major, minor })
    }
}

impl Default for ServerCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ServerCtx {
    fn drop(&mut self) {
        sys::delete_context(&mut self.ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_garbage_token_is_rejected() {
        // A malformed GSS token makes `gss_accept_sec_context` return a defective-token error — no
        // KDC/keytab needed to reject it. Exercises the FFI declarations + error path end to end.
        let mut ctx = ServerCtx::new();
        let result = ctx.step(b"this is not a valid GSS token", None);
        assert!(result.is_err(), "a garbage token must be rejected");
        assert!(!ctx.is_complete());
    }
}
