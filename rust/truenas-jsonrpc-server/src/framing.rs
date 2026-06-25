//! Length-prefixed JSON framing over a byte stream — a port of Python's
//! `truenas_pyjsonrpc_server.framing`.
//!
//! Each message is a **4-byte big-endian unsigned length** followed by exactly that many
//! bytes of (compact) JSON. This is self-delimiting regardless of the payload bytes, so —
//! unlike newline framing — it places no constraint on the JSON content. The 4-byte length
//! prefix is byte-identical to the Python framing, so a Rust server and a Python client
//! interoperate on the wire.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Maximum bytes for a single inbound message payload; a larger declared length is rejected
/// with [`FrameError::TooLarge`] before any payload is read. Matches Python's default.
pub const DEFAULT_LIMIT: usize = 4 * 1024 * 1024; // 4 MiB

const HEADER_SIZE: usize = 4;

/// A framing failure while reading an inbound message. A clean EOF (between frames or mid
/// frame) is **not** an error — [`read_message`] returns `Ok(None)` for it.
#[derive(Debug)]
pub enum FrameError {
    /// The frame's declared length exceeded the configured limit (read no payload).
    TooLarge {
        /// The declared payload length.
        len: usize,
        /// The configured limit.
        limit: usize,
    },
    /// An I/O error other than a clean EOF.
    Io(std::io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooLarge { len, limit } => {
                write!(f, "frame of {len} bytes exceeds limit of {limit}")
            }
            FrameError::Io(e) => write!(f, "framing I/O error: {e}"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Io(e) => Some(e),
            FrameError::TooLarge { .. } => None,
        }
    }
}

/// Append `payload`, prefixed with its 4-byte big-endian length, to `buf`. The single source of
/// the wire framing — used by [`frame`] and by the writer's batch-coalescing path.
pub fn frame_into(buf: &mut Vec<u8>, payload: &[u8]) {
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
}

/// Prefix `payload` with its 4-byte big-endian length, ready to write to the stream.
#[must_use]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    frame_into(&mut out, payload);
    out
}

/// Read one length-prefixed message from `reader` and return its payload bytes, or `None` at
/// EOF (a clean close between messages, or a truncated frame — treated as closed, like
/// Python). Returns [`FrameError::TooLarge`] if the declared length exceeds `limit`.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; HEADER_SIZE];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        // EOF before/at the header boundary → a clean close.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > limit {
        return Err(FrameError::TooLarge { len, limit });
    }
    let mut payload = vec![0u8; len];
    match reader.read_exact(&mut payload).await {
        Ok(_) => Ok(Some(payload)),
        // EOF mid-frame → treat as closed (a truncated trailer is not a usable message).
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(FrameError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_prefixes_big_endian_length() {
        assert_eq!(frame(b"hi"), vec![0, 0, 0, 2, b'h', b'i']);
        assert_eq!(frame(b""), vec![0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn round_trips_framed_messages() {
        // Two frames back to back, then EOF.
        let mut buf = frame(b"{\"a\":1}");
        buf.extend_from_slice(&frame(b""));
        let mut r: &[u8] = &buf;
        assert_eq!(read_message(&mut r, DEFAULT_LIMIT).await.unwrap().as_deref(), Some(&b"{\"a\":1}"[..]));
        assert_eq!(read_message(&mut r, DEFAULT_LIMIT).await.unwrap().as_deref(), Some(&b""[..]));
        assert_eq!(read_message(&mut r, DEFAULT_LIMIT).await.unwrap(), None); // clean EOF
    }

    #[tokio::test]
    async fn truncated_header_and_payload_are_eof() {
        // Partial header → None.
        let mut r: &[u8] = &[0, 0];
        assert_eq!(read_message(&mut r, DEFAULT_LIMIT).await.unwrap(), None);
        // Full header promising 8 bytes, only 3 present → None (truncated mid-frame).
        let mut r: &[u8] = &[0, 0, 0, 8, 1, 2, 3];
        assert_eq!(read_message(&mut r, DEFAULT_LIMIT).await.unwrap(), None);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let mut r: &[u8] = &[0, 0, 0, 16]; // declares 16 bytes
        let err = read_message(&mut r, 8).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { len: 16, limit: 8 }));
        assert!(err.to_string().contains("exceeds limit"));
    }
}
