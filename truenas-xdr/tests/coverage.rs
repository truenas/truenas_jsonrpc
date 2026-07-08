//! Edge-case coverage: the type arms and error paths the round-trip/derive/frame/
//! conformance tests don't already exercise (strict-mode decode, every `XdrError` variant,
//! stock serde enums, the unsupported constructs, the io-error mapping, and the serde
//! `Error` impls). Together with the other test files this drives `src/` to 100% lines.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer};
use truenas_xdr::{
    from_bytes, from_bytes_with, serialized_size, to_bytes, to_writer, Strictness, VarOpaque,
    XdrError,
};

// --- additional scalar / aggregate type arms ---------------------------------

#[test]
fn remaining_scalar_arms() {
    // u16, i16 positive, char, unit, unit-struct, newtype, tuple-struct.
    assert_eq!(to_bytes(&7u16).unwrap(), [0, 0, 0, 7]);
    assert_eq!(from_bytes::<u16>(&[0, 0, 0, 7]).unwrap(), 7);
    assert_eq!(to_bytes(&7i16).unwrap(), [0, 0, 0, 7]);
    assert_eq!(from_bytes::<i16>(&[0, 0, 0, 7]).unwrap(), 7);
    assert_eq!(to_bytes(&'Z').unwrap(), [0, 0, 0, b'Z']);
    assert_eq!(from_bytes::<char>(&[0, 0, 0, b'Z']).unwrap(), 'Z');

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Unit;
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct NewType(u32);
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Pair(i32, bool);

    assert_eq!(to_bytes(&()).unwrap(), [] as [u8; 0]);
    let _: () = from_bytes(&[]).unwrap();
    assert_eq!(to_bytes(&Unit).unwrap(), [] as [u8; 0]);
    assert_eq!(from_bytes::<Unit>(&[]).unwrap(), Unit);
    assert_eq!(to_bytes(&NewType(9)).unwrap(), [0, 0, 0, 9]); // newtype is transparent
    assert_eq!(from_bytes::<NewType>(&[0, 0, 0, 9]).unwrap(), NewType(9));
    assert_eq!(
        to_bytes(&Pair(-1, true)).unwrap(),
        [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1]
    );
    assert_eq!(
        from_bytes::<Pair>(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1]).unwrap(),
        Pair(-1, true)
    );
}

#[test]
fn borrowed_str_uses_deserialize_str() {
    let bytes = to_bytes(&"hey".to_string()).unwrap();
    let s: &str = from_bytes(&bytes).unwrap(); // &str decode goes through deserialize_str
    assert_eq!(s, "hey");
    assert_eq!(serialized_size(&"hey".to_string()).unwrap(), 8); // len(4) + "hey"+pad(4)
}

#[test]
fn borrowed_bytes_use_deserialize_bytes() {
    // `&[u8]` decodes via deserialize_bytes → visit_borrowed_bytes (VarOpaque uses byte_buf).
    let b: &[u8] = from_bytes(&[0, 0, 0, 3, 1, 2, 3, 0]).unwrap();
    assert_eq!(b, &[1, 2, 3]);
}

#[test]
fn codec_is_not_human_readable() {
    // A type that branches on `is_human_readable` proves both the serializer's and the
    // deserializer's report `false` (so `#[serde(with)]` types pick their compact form).
    struct Probe(bool);
    impl Serialize for Probe {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let hr = s.is_human_readable();
            s.serialize_bool(hr)
        }
    }
    impl<'de> Deserialize<'de> for Probe {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let hr = d.is_human_readable();
            Ok(Probe(hr || bool::deserialize(d)?))
        }
    }
    assert_eq!(to_bytes(&Probe(true)).unwrap(), [0, 0, 0, 0]); // serializer: not human-readable
    assert!(!from_bytes::<Probe>(&[0, 0, 0, 0]).unwrap().0); // deserializer: not human-readable
}

#[test]
fn wrapper_visitor_expecting_via_self_describing_format() {
    // The wrappers' `expecting` methods are unreachable through the non-self-describing XDR
    // path, but a self-describing format (serde_json) with a wrong type exercises them.
    assert!(serde_json::from_str::<VarOpaque>("123").is_err());
    assert!(serde_json::from_str::<truenas_xdr::FixedOpaque<4>>("123").is_err());
}

// --- stock (non-XdrEnum) serde enums: exercises serialize_*_variant + deserialize_enum ---

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum Stock {
    Unit,
    New(u32),
    Tup(i32, bool),
    Strukt { a: u32, b: String },
}

#[test]
fn stock_enum_round_trips_by_variant_index() {
    for v in [
        Stock::Unit,
        Stock::New(5),
        Stock::Tup(-1, true),
        Stock::Strukt {
            a: 1,
            b: "x".to_string(),
        },
    ] {
        let bytes = to_bytes(&v).unwrap();
        assert_eq!(from_bytes::<Stock>(&bytes).unwrap(), v);
    }
    // The discriminant is the declaration index.
    assert_eq!(to_bytes(&Stock::Unit).unwrap(), [0, 0, 0, 0]);
    assert_eq!(to_bytes(&Stock::New(5)).unwrap(), [0, 0, 0, 1, 0, 0, 0, 5]);
    assert_eq!(
        to_bytes(&Stock::Tup(7, false)).unwrap(),
        [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 0]
    );
}

// --- unsupported constructs --------------------------------------------------

#[test]
fn maps_are_unsupported() {
    let mut m = BTreeMap::new();
    m.insert("k".to_string(), 1u32);
    assert!(matches!(to_bytes(&m), Err(XdrError::Unsupported("map"))));
    assert!(matches!(
        from_bytes::<BTreeMap<String, u32>>(&[0, 0, 0, 0]),
        Err(XdrError::Unsupported("map"))
    ));
}

#[test]
fn unknown_length_sequence_is_unsupported() {
    struct UnsizedSeq;
    impl Serialize for UnsizedSeq {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let seq = s.serialize_seq(None)?; // errors here
            serde::ser::SerializeSeq::end(seq)
        }
    }
    assert!(matches!(
        to_bytes(&UnsizedSeq),
        Err(XdrError::Unsupported("sequence with unknown length"))
    ));
}

#[test]
fn self_describing_decode_is_unsupported() {
    // deserialize_any
    assert!(matches!(
        from_bytes::<serde_json::Value>(&[0, 0, 0, 0]),
        Err(XdrError::Unsupported(_))
    ));
    // deserialize_ignored_any
    assert!(matches!(
        from_bytes::<serde::de::IgnoredAny>(&[0, 0, 0, 0]),
        Err(XdrError::Unsupported(_))
    ));
    // deserialize_identifier
    struct AskIdent;
    impl<'de> Deserialize<'de> for AskIdent {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_identifier(serde::de::IgnoredAny)?;
            Ok(AskIdent)
        }
    }
    assert!(from_bytes::<AskIdent>(&[0, 0, 0, 0]).is_err());
}

// --- decode error paths ------------------------------------------------------

#[test]
fn integer_range_errors() {
    assert!(matches!(
        from_bytes::<i8>(&to_bytes(&200i32).unwrap()),
        Err(XdrError::Range)
    ));
    assert!(matches!(
        from_bytes::<i16>(&to_bytes(&70000i32).unwrap()),
        Err(XdrError::Range)
    ));
    assert!(matches!(
        from_bytes::<u16>(&to_bytes(&70000u32).unwrap()),
        Err(XdrError::Range)
    ));
    // 0xD800 is a lone surrogate — not a valid char scalar value.
    assert!(matches!(
        from_bytes::<char>(&[0, 0, 0xD8, 0x00]),
        Err(XdrError::Range)
    ));
}

#[test]
fn invalid_utf8_string_is_an_error() {
    // len 1 + a 0xff byte (invalid UTF-8) + 3 pad.
    assert!(matches!(
        from_bytes::<String>(&[0, 0, 0, 1, 0xff, 0, 0, 0]),
        Err(XdrError::Utf8)
    ));
}

#[test]
fn strict_mode_rejects_nonzero_padding_and_embedded_nul() {
    // "abc" with a non-zero pad byte: accepted lenient, rejected strict.
    let bad_pad = [0, 0, 0, 3, b'a', b'b', b'c', 0xff];
    assert_eq!(from_bytes::<String>(&bad_pad).unwrap(), "abc"); // lenient ignores the pad
    assert!(matches!(
        from_bytes_with::<String>(&bad_pad, Strictness::Strict).map(|(v, _)| v),
        Err(XdrError::NonZeroPadding)
    ));

    // A string with an embedded NUL: accepted lenient, rejected strict.
    let embedded_nul = to_bytes(&"a\0b".to_string()).unwrap();
    assert_eq!(from_bytes::<String>(&embedded_nul).unwrap(), "a\0b");
    assert!(matches!(
        from_bytes_with::<String>(&embedded_nul, Strictness::Strict).map(|(v, _)| v),
        Err(XdrError::EmbeddedNul)
    ));

    // VarOpaque pad is checked the same way.
    let opaque_bad_pad = [0, 0, 0, 1, 0x41, 0xff, 0xff, 0xff];
    assert_eq!(
        from_bytes::<VarOpaque>(&opaque_bad_pad).unwrap(),
        VarOpaque(vec![0x41])
    );
    assert!(from_bytes_with::<VarOpaque>(&opaque_bad_pad, Strictness::Strict).is_err());
}

// --- the io-error mapping in the serializer ----------------------------------

#[test]
fn writer_errors_map_to_xdr_error() {
    struct FailWriter;
    impl std::io::Write for FailWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(matches!(
        to_writer(FailWriter, &1u32),
        Err(XdrError::Message(_))
    ));
}

// --- the serde Error impls + every XdrError Display arm ----------------------

#[test]
fn error_display_and_custom() {
    let variants = [
        XdrError::Eof { need: 4 },
        XdrError::Range,
        XdrError::NonZeroPadding,
        XdrError::EmbeddedNul,
        XdrError::Utf8,
        XdrError::TrailingBytes,
        XdrError::Unsupported("x"),
        XdrError::Message("m".to_string()),
    ];
    for v in &variants {
        assert!(!format!("{v}").is_empty());
    }
    // Both serde `Error::custom` impls.
    assert!(matches!(
        <XdrError as serde::ser::Error>::custom("s"),
        XdrError::Message(_)
    ));
    assert!(matches!(
        <XdrError as serde::de::Error>::custom("d"),
        XdrError::Message(_)
    ));
}
