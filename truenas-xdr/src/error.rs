//! The XDR codec error type and its serde `Error` impls.

use std::fmt::Display;

use serde::{de, ser};

/// An error encoding or decoding XDR.
///
/// Stream-exhaustion, range, and (in [`crate::Strictness::Strict`] mode) padding/NUL
/// violations are surfaced as distinct variants; serde's `custom` errors land in
/// [`XdrError::Message`].
#[derive(Debug, thiserror::Error)]
pub enum XdrError {
    /// The input ended before a value could be fully decoded.
    #[error("unexpected end of input (need {need} more byte(s))")]
    Eof {
        /// How many more bytes were required.
        need: usize,
    },
    /// A wire value did not fit the target type (e.g. an `i32`-wire value into an `i16`).
    #[error("value out of range for the target type")]
    Range,
    /// A variable/opaque field's trailing padding byte was non-zero (strict mode only).
    #[error("non-zero opaque padding byte")]
    NonZeroPadding,
    /// A decoded string contained an embedded NUL (strict mode only).
    #[error("embedded NUL in string")]
    EmbeddedNul,
    /// A decoded string was not valid UTF-8.
    #[error("invalid UTF-8 in string")]
    Utf8,
    /// Bytes remained after decoding a value via an `*_exact` entry point.
    #[error("trailing bytes after value")]
    TrailingBytes,
    /// A serde construct XDR cannot represent (maps, unknown-length sequences,
    /// self-describing `deserialize_any`, etc.).
    #[error("XDR does not support {0}")]
    Unsupported(&'static str),
    /// A `serde::ser::Error` / `serde::de::Error` `custom` message.
    #[error("{0}")]
    Message(String),
}

impl ser::Error for XdrError {
    fn custom<T: Display>(msg: T) -> Self {
        XdrError::Message(msg.to_string())
    }
}

impl de::Error for XdrError {
    fn custom<T: Display>(msg: T) -> Self {
        XdrError::Message(msg.to_string())
    }
}
