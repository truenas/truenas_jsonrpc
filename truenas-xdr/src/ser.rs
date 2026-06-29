//! The XDR [`serde::Serializer`] — walks any `Serialize` value to canonical big-endian
//! RFC-4506 bytes. Encoding is identical in both [`crate::Strictness`] modes (canonical
//! padding is always zero), so the serializer is mode-independent.
//!
//! [`serialized_size`](crate::serialized_size) reuses this exact serializer over a
//! [`CountWriter`] sink (the analogue of `xdr_sizeof`'s "count instead of write" vtable).

use std::io::Write;

use serde::ser::{
    Impossible, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use serde::{Serialize, Serializer};

use crate::{pad4, XdrError, SENTINEL_FIXED};

/// A serde `Serializer` that writes XDR to an `io::Write` sink.
pub(crate) struct XdrSerializer<W> {
    w: W,
    /// Set by `serialize_newtype_struct(SENTINEL_FIXED, ..)` so the immediately-following
    /// `serialize_bytes` emits fixed opaque (raw bytes + pad, no length prefix).
    fixed_pending: bool,
}

impl<W: Write> XdrSerializer<W> {
    pub(crate) fn new(w: W) -> Self {
        Self { w, fixed_pending: false }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), XdrError> {
        self.w.write_all(bytes).map_err(|e| XdrError::Message(e.to_string()))
    }
    fn put_u32(&mut self, v: u32) -> Result<(), XdrError> {
        self.put(&v.to_be_bytes())
    }
    fn put_u64(&mut self, v: u64) -> Result<(), XdrError> {
        self.put(&v.to_be_bytes())
    }
    /// Write the zero pad bringing `len` up to a 4-byte boundary.
    fn put_pad(&mut self, len: usize) -> Result<(), XdrError> {
        let p = pad4(len);
        if p > 0 {
            self.put(&[0u8; 3][..p])?;
        }
        Ok(())
    }
    /// Variable opaque/string body: bytes + pad (the `u32` length is written by the caller).
    fn put_opaque_body(&mut self, v: &[u8]) -> Result<(), XdrError> {
        self.put(v)?;
        self.put_pad(v.len())
    }
}

/// An `io::Write` that counts bytes instead of storing them (for `serialized_size`).
pub(crate) struct CountWriter {
    pub(crate) n: usize,
}

impl Write for CountWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.n += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Write> Serializer for &mut XdrSerializer<W> {
    type Ok = ();
    type Error = XdrError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Impossible<(), XdrError>;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<(), XdrError> {
        self.put_u32(u32::from(v))
    }
    fn serialize_i8(self, v: i8) -> Result<(), XdrError> {
        self.serialize_i32(i32::from(v))
    }
    fn serialize_i16(self, v: i16) -> Result<(), XdrError> {
        self.serialize_i32(i32::from(v))
    }
    fn serialize_i32(self, v: i32) -> Result<(), XdrError> {
        self.put_u32(v as u32)
    }
    fn serialize_i64(self, v: i64) -> Result<(), XdrError> {
        self.put_u64(v as u64)
    }
    fn serialize_u8(self, v: u8) -> Result<(), XdrError> {
        self.put_u32(u32::from(v))
    }
    fn serialize_u16(self, v: u16) -> Result<(), XdrError> {
        self.put_u32(u32::from(v))
    }
    fn serialize_u32(self, v: u32) -> Result<(), XdrError> {
        self.put_u32(v)
    }
    fn serialize_u64(self, v: u64) -> Result<(), XdrError> {
        self.put_u64(v)
    }
    fn serialize_f32(self, v: f32) -> Result<(), XdrError> {
        self.put_u32(v.to_bits())
    }
    fn serialize_f64(self, v: f64) -> Result<(), XdrError> {
        self.put_u64(v.to_bits())
    }
    fn serialize_char(self, v: char) -> Result<(), XdrError> {
        self.put_u32(v as u32)
    }
    fn serialize_str(self, v: &str) -> Result<(), XdrError> {
        // A string is always variable-length opaque, regardless of `fixed_pending`.
        self.fixed_pending = false;
        self.put_u32(v.len() as u32)?;
        self.put_opaque_body(v.as_bytes())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), XdrError> {
        if std::mem::take(&mut self.fixed_pending) {
            // Fixed opaque: raw bytes + pad, NO length prefix.
            self.put_opaque_body(v)
        } else {
            // Variable opaque: u32 length + bytes + pad.
            self.put_u32(v.len() as u32)?;
            self.put_opaque_body(v)
        }
    }
    fn serialize_none(self) -> Result<(), XdrError> {
        self.put_u32(0)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), XdrError> {
        self.put_u32(1)?;
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), XdrError> {
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), XdrError> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> Result<(), XdrError> {
        // XDR enum/union discriminant. For exact `#[repr(i32)]` values use `#[derive(XdrEnum)]`;
        // the stock path encodes the declaration-order index.
        self.put_u32(variant_index)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<(), XdrError> {
        if name == SENTINEL_FIXED {
            self.fixed_pending = true;
        }
        // Otherwise transparent: a newtype (e.g. a `Secret<T>`) adds no wire bytes.
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<(), XdrError> {
        self.put_u32(variant_index)?;
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, XdrError> {
        let len = len.ok_or(XdrError::Unsupported("sequence with unknown length"))?;
        self.put_u32(len as u32)?;
        Ok(self)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, XdrError> {
        Ok(self)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, XdrError> {
        Ok(self)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, XdrError> {
        self.put_u32(variant_index)?;
        Ok(self)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, XdrError> {
        Err(XdrError::Unsupported("map"))
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, XdrError> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, XdrError> {
        self.put_u32(variant_index)?;
        Ok(self)
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}

// --- compound serializers: each element/field is written immediately, in order ---------
// XDR concatenates fields with no inter-field framing; variable seqs wrote their count up
// front (in `serialize_seq`), tuples/structs/variants have none.

impl<W: Write> SerializeSeq for &mut XdrSerializer<W> {
    type Ok = ();
    type Error = XdrError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), XdrError> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), XdrError> {
        Ok(())
    }
}

impl<W: Write> SerializeTuple for &mut XdrSerializer<W> {
    type Ok = ();
    type Error = XdrError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), XdrError> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), XdrError> {
        Ok(())
    }
}

impl<W: Write> SerializeTupleStruct for &mut XdrSerializer<W> {
    type Ok = ();
    type Error = XdrError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), XdrError> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), XdrError> {
        Ok(())
    }
}

impl<W: Write> SerializeTupleVariant for &mut XdrSerializer<W> {
    type Ok = ();
    type Error = XdrError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), XdrError> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), XdrError> {
        Ok(())
    }
}

impl<W: Write> SerializeStruct for &mut XdrSerializer<W> {
    type Ok = ();
    type Error = XdrError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), XdrError> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), XdrError> {
        Ok(())
    }
}

impl<W: Write> SerializeStructVariant for &mut XdrSerializer<W> {
    type Ok = ();
    type Error = XdrError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), XdrError> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), XdrError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CountWriter;
    use std::io::Write;

    #[test]
    fn count_writer_counts_bytes_and_flush_is_a_noop() {
        let mut w = CountWriter { n: 0 };
        w.write_all(b"abcd").unwrap();
        w.flush().unwrap();
        assert_eq!(w.n, 4);
    }
}
