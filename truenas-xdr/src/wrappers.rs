//! Wrapper types for XDR shapes that a stock serde call would encode incorrectly.
//!
//! - [`VarOpaque`] — RFC-4506 variable-length opaque (`opaque<>`): a `u32` length, the
//!   bytes, then zero-padding to a 4-byte boundary. (A bare `Vec<u8>` would instead be
//!   encoded as a sequence of 4-byte-per-element ints.)
//! - [`FixedOpaque`] — RFC-4506 fixed-length opaque (`opaque[N]`): exactly `N` bytes plus
//!   padding, with **no** length prefix. It conveys `N` to the decoder through
//!   `deserialize_tuple(N, …)` while a sentinel newtype tells the codec "raw bytes, no
//!   length prefix" (see [`crate::SENTINEL_FIXED`]).

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SENTINEL_FIXED;

/// RFC-4506 variable-length opaque (`opaque<>` / `string<>` of bytes): `u32` length +
/// bytes + zero-pad to a 4-byte boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VarOpaque(
    /// The raw bytes (unpadded).
    pub Vec<u8>,
);

impl Serialize for VarOpaque {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for VarOpaque {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = VarOpaque;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("variable-length opaque bytes")
            }
            // The XDR deserializer routes opaque through `deserialize_byte_buf` →
            // `visit_byte_buf`, so that is the only visit method this type needs.
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<VarOpaque, E> {
                Ok(VarOpaque(v))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// RFC-4506 fixed-length opaque (`opaque[N]`): exactly `N` bytes + zero-pad to a 4-byte
/// boundary, with **no** length prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedOpaque<const N: usize>(
    /// The `N` raw bytes.
    pub [u8; N],
);

impl<const N: usize> Serialize for FixedOpaque<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // The sentinel name tells the XDR serializer "the next `serialize_bytes` is fixed
        // opaque — emit raw bytes + pad, no length prefix". `RawBytes` routes the slice
        // through `serialize_bytes`.
        s.serialize_newtype_struct(SENTINEL_FIXED, &RawBytes(&self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedOpaque<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_newtype_struct(SENTINEL_FIXED, FixedVisitor::<N>)
    }
}

struct FixedVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for FixedVisitor<N> {
    type Value = FixedOpaque<N>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{N} fixed opaque bytes")
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        // `deserialize_tuple` carries the length `N` to the codec, which (seeing the
        // sentinel flag set by `deserialize_newtype_struct`) reads exactly `N` raw bytes
        // + pad and hands them back here via `visit_borrowed_bytes`.
        d.deserialize_tuple(N, self)
    }
    fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        // `v.len() == N` is guaranteed by the codec's `read_fixed(N)`, so this never panics.
        let mut arr = [0u8; N];
        arr.copy_from_slice(v);
        Ok(FixedOpaque(arr))
    }
}

/// Internal: a byte slice that serializes through `serialize_bytes` (so the fixed-opaque
/// sentinel path sees a `serialize_bytes` call rather than a sequence of ints).
struct RawBytes<'a>(&'a [u8]);

impl Serialize for RawBytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}
