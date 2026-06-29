//! The XDR [`serde::Deserializer`] — type-driven decode (the wire carries no tags, so
//! every `deserialize_*` reads exactly the bytes its target type asks for). `deserialize_any`
//! / `deserialize_ignored_any` / `deserialize_identifier` are unsupported (no self-description).

use serde::de::{
    DeserializeSeed, EnumAccess, IntoDeserializer, SeqAccess, VariantAccess, Visitor,
};
use serde::Deserializer;

use crate::{pad4, Strictness, XdrError};

/// A serde `Deserializer` reading XDR from a borrowed byte slice.
pub struct XdrDeserializer<'de> {
    input: &'de [u8],
    pos: usize,
    mode: Strictness,
    /// Set by `deserialize_newtype_struct(SENTINEL_FIXED, ..)` so the following
    /// `deserialize_tuple(N, ..)` reads `N` raw bytes (fixed opaque) rather than a tuple.
    fixed_pending: bool,
}

impl<'de> XdrDeserializer<'de> {
    /// Construct a deserializer over `input` with the given strictness.
    pub fn new(input: &'de [u8], mode: Strictness) -> Self {
        Self { input, pos: 0, mode, fixed_pending: false }
    }

    /// The bytes not yet consumed (used by the `frame` module to slice params/results).
    pub fn remaining(&self) -> &'de [u8] {
        &self.input[self.pos..]
    }

    fn take(&mut self, n: usize) -> Result<&'de [u8], XdrError> {
        // `saturating_add` can't realistically overflow (n is a u32-derived length), and a
        // saturated `end` still trips the bounds check below — so there is no separate
        // (untestable) overflow arm.
        let end = self.pos.saturating_add(n);
        if end > self.input.len() {
            return Err(XdrError::Eof { need: end - self.input.len() });
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<u32, XdrError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn read_u64(&mut self) -> Result<u64, XdrError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Consume the zero pad after a `len`-byte opaque/string field. In strict mode a
    /// non-zero pad byte is an error (ZFS `spl-xdr` rule 4).
    fn read_pad(&mut self, len: usize) -> Result<(), XdrError> {
        let p = pad4(len);
        if p > 0 {
            let pad = self.take(p)?;
            if self.mode == Strictness::Strict && pad.iter().any(|&b| b != 0) {
                return Err(XdrError::NonZeroPadding);
            }
        }
        Ok(())
    }

    /// Variable opaque/string body: `u32` length + bytes + pad.
    fn read_opaque(&mut self) -> Result<&'de [u8], XdrError> {
        let len = self.read_u32()? as usize;
        let data = self.take(len)?;
        self.read_pad(len)?;
        Ok(data)
    }

    /// Fixed opaque: `n` bytes + pad, no length prefix.
    fn read_fixed(&mut self, n: usize) -> Result<&'de [u8], XdrError> {
        let data = self.take(n)?;
        self.read_pad(n)?;
        Ok(data)
    }
}

/// Decode a variable string body to `&str` (UTF-8; in strict mode reject embedded NULs).
fn decode_str(bytes: &[u8], mode: Strictness) -> Result<&str, XdrError> {
    let s = std::str::from_utf8(bytes).map_err(|_| XdrError::Utf8)?;
    if mode == Strictness::Strict && s.as_bytes().contains(&0) {
        return Err(XdrError::EmbeddedNul);
    }
    Ok(s)
}

impl<'de> Deserializer<'de> for &mut XdrDeserializer<'de> {
    type Error = XdrError;

    fn deserialize_any<V: Visitor<'de>>(self, _v: V) -> Result<V::Value, XdrError> {
        Err(XdrError::Unsupported("deserialize_any (XDR is not self-describing)"))
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, XdrError> {
        self.deserialize_any(v)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, v: V) -> Result<V::Value, XdrError> {
        self.deserialize_any(v)
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        visitor.visit_bool(self.read_u32()? != 0)
    }
    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let w = self.read_u32()? as i32;
        visitor.visit_i8(i8::try_from(w).map_err(|_| XdrError::Range)?)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let w = self.read_u32()? as i32;
        visitor.visit_i16(i16::try_from(w).map_err(|_| XdrError::Range)?)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        visitor.visit_i32(self.read_u32()? as i32)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        visitor.visit_i64(self.read_u64()? as i64)
    }
    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let w = self.read_u32()?;
        visitor.visit_u8(u8::try_from(w).map_err(|_| XdrError::Range)?)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let w = self.read_u32()?;
        visitor.visit_u16(u16::try_from(w).map_err(|_| XdrError::Range)?)
    }
    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        visitor.visit_u32(self.read_u32()?)
    }
    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        visitor.visit_u64(self.read_u64()?)
    }
    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        visitor.visit_f32(f32::from_bits(self.read_u32()?))
    }
    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        visitor.visit_f64(f64::from_bits(self.read_u64()?))
    }
    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let w = self.read_u32()?;
        visitor.visit_char(char::try_from(w).map_err(|_| XdrError::Range)?)
    }
    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let bytes = self.read_opaque()?;
        visitor.visit_borrowed_str(decode_str(bytes, self.mode)?)
    }
    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let bytes = self.read_opaque()?;
        visitor.visit_str(decode_str(bytes, self.mode)?)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let bytes = self.read_opaque()?;
        visitor.visit_borrowed_bytes(bytes)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let bytes = self.read_opaque()?;
        visitor.visit_byte_buf(bytes.to_vec())
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        // Lenient like `xdr.py`/`xdr_bool`: zero is absent, any non-zero is present.
        if self.read_u32()? == 0 {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        visitor.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, XdrError> {
        visitor.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, XdrError> {
        if name == crate::SENTINEL_FIXED {
            self.fixed_pending = true;
        }
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, XdrError> {
        let count = self.read_u32()? as usize;
        visitor.visit_seq(SeqReader { de: self, remaining: count })
    }
    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, XdrError> {
        if std::mem::take(&mut self.fixed_pending) {
            // Fixed opaque: read exactly `len` raw bytes + pad (no count, no per-element units).
            let bytes = self.read_fixed(len)?;
            return visitor.visit_borrowed_bytes(bytes);
        }
        visitor.visit_seq(SeqReader { de: self, remaining: len })
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, XdrError> {
        visitor.visit_seq(SeqReader { de: self, remaining: len })
    }
    fn deserialize_map<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, XdrError> {
        Err(XdrError::Unsupported("map"))
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, XdrError> {
        visitor.visit_seq(SeqReader { de: self, remaining: fields.len() })
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, XdrError> {
        let tag = self.read_u32()?;
        visitor.visit_enum(EnumReader { de: self, variant_index: tag })
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

/// Reads `remaining` elements on demand (XDR has no per-element framing). For a variable
/// sequence `remaining` is the decoded `u32` count; for a tuple/struct it is the fixed arity.
struct SeqReader<'a, 'de> {
    de: &'a mut XdrDeserializer<'de>,
    remaining: usize,
}

impl<'de> SeqAccess<'de> for SeqReader<'_, 'de> {
    type Error = XdrError;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, XdrError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

/// Decodes a stock (non-`XdrEnum`) enum/union: the discriminant is the declaration-order
/// variant index (the dual of the serializer's `serialize_*_variant`).
struct EnumReader<'a, 'de> {
    de: &'a mut XdrDeserializer<'de>,
    variant_index: u32,
}

impl<'de> EnumAccess<'de> for EnumReader<'_, 'de> {
    type Error = XdrError;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), XdrError> {
        let variant = seed.deserialize(self.variant_index.into_deserializer())?;
        Ok((variant, self))
    }
}

impl<'de> VariantAccess<'de> for EnumReader<'_, 'de> {
    type Error = XdrError;
    fn unit_variant(self) -> Result<(), XdrError> {
        Ok(())
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, XdrError> {
        seed.deserialize(&mut *self.de)
    }
    fn tuple_variant<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, XdrError> {
        visitor.visit_seq(SeqReader { de: self.de, remaining: len })
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, XdrError> {
        visitor.visit_seq(SeqReader { de: self.de, remaining: fields.len() })
    }
}
