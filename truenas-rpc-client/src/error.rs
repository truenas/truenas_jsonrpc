//! The client error type.

use truenas_rpc::JsonRpcError;

/// An error from a client engine call. `Rpc` carries a server-returned [`JsonRpcError`]; the rest are
/// local (transport / framing / decode / lifecycle) failures.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The connection closed (EOF, a write failure, or an explicit disconnect) — the call cannot
    /// complete.
    #[error("connection closed")]
    Closed,
    /// A transport I/O error (connect / read / write).
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),
    /// A reply or notification frame could not be decoded.
    #[error("decode error: {0}")]
    Decode(String),
    /// The server returned an error for the call.
    #[error("rpc error: {0}")]
    Rpc(#[from] JsonRpcError),
}

impl ClientError {
    /// Flatten into a [`JsonRpcError`] (the codegen seam returns this). A server `Rpc` error passes
    /// through unchanged; a local failure becomes an `INTERNAL_ERROR` carrying the description.
    pub fn into_jsonrpc(self) -> JsonRpcError {
        match self {
            ClientError::Rpc(e) => e,
            other => JsonRpcError::internal(other.to_string()),
        }
    }
}
