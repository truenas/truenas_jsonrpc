//! `truenas-xdr` — a byte-exact, dependency-light **serde XDR (RFC 4506)** codec (the **Codec**
//! layer, layer 3, of the `ARCHITECTURE.md` layer stack — the binary TXDR wire).
//!
//! XDR is **not** self-describing, so this is a bincode-style codec: encode walks any
//! `Serialize` value to canonical big-endian bytes; decode is driven entirely by the
//! target type's `Deserialize` impl (the wire carries no type tags). `deserialize_any`
//! is therefore unsupported (so `#[serde(flatten)]` / `serde_json::Value` cannot be
//! decoded from XDR).
//!
//! The full common RFC-4506 type set is supported: bool, 32-bit int/uint, 64-bit
//! hyper, enum, float/double, fixed + variable opaque, string, fixed + variable
//! arrays, optional, discriminated union, and struct — plus a counting "sizeof" path
//! ([`serialized_size`], the analogue of `xdr_sizeof`).
//!
//! Some XDR shapes do not map onto a stock serde call: variable opaque uses
//! [`VarOpaque`], fixed opaque uses [`FixedOpaque`], and enums/unions with explicit
//! `#[repr(i32)]` discriminants should use the `derive` feature's `XdrEnum`/`XdrUnion`
//! macros (a stock `#[derive(Serialize)]` enum encodes the *declaration index*, which is
//! wrong for discriminant gaps). A single-field newtype (e.g. a `Secret<T>`) is
//! wire-transparent automatically.
//!
//! ```
//! # use serde::{Serialize, Deserialize};
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Point { x: i32, y: i32 }
//! let bytes = truenas_xdr::to_bytes(&Point { x: 1, y: -1 }).unwrap();
//! assert_eq!(bytes, [0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff]);
//! assert_eq!(truenas_xdr::from_bytes::<Point>(&bytes).unwrap(), Point { x: 1, y: -1 });
//! ```

mod de;
mod error;
pub mod frame;
mod ser;
mod strict;
mod wrappers;

pub use de::XdrDeserializer;
pub use error::XdrError;
pub use strict::Strictness;
pub use wrappers::{FixedOpaque, VarOpaque};

/// Derive `Serialize`/`Deserialize` encoding a field-less enum as its declared `i32`
/// discriminant (byte-exact for discriminant gaps; the stock derive would use the
/// declaration index). Requires the `derive` feature (enabled by default).
#[cfg(feature = "derive")]
pub use truenas_xdr_derive::{XdrEnum, XdrUnion};

use serde::{Deserialize, Serialize};

/// The number of bytes in one XDR unit (RFC 4506 §3): everything is 4-byte aligned.
pub const BYTES_PER_XDR_UNIT: usize = 4;

/// Sentinel newtype name used by [`FixedOpaque`] to signal "fixed opaque, no length
/// prefix" to the codec. Not part of the public API contract; do not rely on its value.
pub(crate) const SENTINEL_FIXED: &str = "\u{0}truenas-xdr-fixed-opaque";

/// Bytes of zero padding needed to bring `len` up to a 4-byte boundary (0..=3).
pub(crate) const fn pad4(len: usize) -> usize {
    (BYTES_PER_XDR_UNIT - (len % BYTES_PER_XDR_UNIT)) % BYTES_PER_XDR_UNIT
}

/// Encode `value` to canonical XDR bytes.
pub fn to_bytes<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>, XdrError> {
    let mut buf = Vec::new();
    to_writer(&mut buf, value)?;
    Ok(buf)
}

/// Encode `value` into an existing writer (the zero-copy dispatch path).
pub fn to_writer<W: std::io::Write, T: ?Sized + Serialize>(
    mut writer: W,
    value: &T,
) -> Result<(), XdrError> {
    let mut ser = ser::XdrSerializer::new(&mut writer);
    value.serialize(&mut ser)
}

/// The serialized size of `value` in bytes, computed without allocating an output buffer
/// (the analogue of `xdr_sizeof`). Always a multiple of [`BYTES_PER_XDR_UNIT`].
pub fn serialized_size<T: ?Sized + Serialize>(value: &T) -> Result<usize, XdrError> {
    let mut cw = ser::CountWriter { n: 0 };
    to_writer(&mut cw, value)?;
    Ok(cw.n)
}

/// Decode a `T` from `bytes` (FreeBSD-lenient; trailing bytes are allowed, matching
/// `xdr.py`'s lenient `decode`).
pub fn from_bytes<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, XdrError> {
    from_bytes_with(bytes, Strictness::Lenient).map(|(value, _rest)| value)
}

/// Decode a `T` from `bytes`, requiring the whole buffer be consumed.
pub fn from_bytes_exact<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, XdrError> {
    let (value, rest) = from_bytes_with(bytes, Strictness::Lenient)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(XdrError::TrailingBytes)
    }
}

/// Decode a `T` from `bytes` under an explicit [`Strictness`] mode, returning the value
/// and the unconsumed tail (the `frame` module slices request/reply params from the tail).
pub fn from_bytes_with<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    mode: Strictness,
) -> Result<(T, &'de [u8]), XdrError> {
    let mut de = XdrDeserializer::new(bytes, mode);
    let value = T::deserialize(&mut de)?;
    Ok((value, de.remaining()))
}
