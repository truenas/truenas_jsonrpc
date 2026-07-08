//! `$/negotiate` — the server-level, unauthenticated protocol selector.
//!
//! A connection begins by sending `$/negotiate` naming the protocol it wants; the server
//! binds one of its named [`JsonRpcProtocol`](truenas_rpc::JsonRpcProtocol)s to the
//! connection and replies with the bound name, the server identity, and the available names.
//! After that the flow is the usual `$/sessionSetup -> API calls` against the bound protocol.
//! `$/negotiate` is handled entirely by the server — the dispatch core never sees it.

use serde::{Deserialize, Serialize};

/// The control-method name. Server-side; reserved like the protocol's `$/` names.
pub(crate) const NEGOTIATE_METHOD: &str = "$/negotiate";

/// `$/negotiate` request params.
#[derive(Deserialize)]
pub(crate) struct NegotiateParams {
    pub protocol: String,
}

/// `$/negotiate` reply: the bound protocol, the server identity, and every protocol offered.
#[derive(Serialize)]
pub(crate) struct NegotiateResult {
    pub protocol: String,
    pub server: Option<String>,
    pub available: Vec<String>,
}
