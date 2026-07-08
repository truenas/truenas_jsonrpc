//! `demo-ws` — the end-to-end fixture for the generated **TypeScript** client's CI test. Generated
//! server bindings (from `json-idl/e2e.json`) + hand-written handlers; the `e2e_server` binary serves
//! them over `wss://` with unbound-SCRAM auth and a `ticks` subscription, and a Node client (using the
//! generated TS client) drives it. Not a default workspace member (links OpenSSL via the server's
//! `tls` feature); built + run by the CI `ts` job.

// The generated `$defs` structs + the `Handlers` trait + `register` (wrapped so clippy is silenced on
// generated code), re-exported at the crate root.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/types_gen.rs"));
    include!(concat!(env!("OUT_DIR"), "/server_gen.rs"));
}
pub use generated::*;

use truenas_rpc::{JsonRpcError, RequestCtx};
use truenas_rpc_auth::AuthSession;

/// The E2E handlers — `echo` and `add` (the `ticks` subscription has no handler; the server pushes to
/// it). Implemented over the `AuthSession` state so the protocol can require `$/sessionSetup`.
pub struct E2eHandlers;

impl Handlers<AuthSession> for E2eHandlers {
    fn echo(
        &self,
        req: EchoArgs,
        _cx: &RequestCtx<AuthSession>,
    ) -> Result<EchoResult, JsonRpcError> {
        Ok(EchoResult { msg: req.msg })
    }

    fn add(&self, req: AddArgs, _cx: &RequestCtx<AuthSession>) -> Result<AddResult, JsonRpcError> {
        Ok(AddResult { sum: req.a + req.b })
    }
}
