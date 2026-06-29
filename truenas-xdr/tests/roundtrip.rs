//! Round-trip + byte-exact tests for the XDR codec's full type surface.
//!
//! (Conformance against the committed `xdr_cases` golden vectors and the FreeBSD
//! `sctrl` union goldens live in `conformance.rs` / `golden_sctrl.rs`.)

use serde::{Deserialize, Serialize};
use truenas_xdr::{from_bytes, from_bytes_exact, serialized_size, to_bytes, FixedOpaque, VarOpaque};

/// Encode `value`, assert the exact bytes, assert `serialized_size` agrees, then decode
/// and assert the value round-trips.
fn check<T>(value: &T, expected: &[u8])
where
    T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let bytes = to_bytes(value).expect("encode");
    assert_eq!(bytes, expected, "encoded bytes for {value:?}");
    assert_eq!(bytes.len() % 4, 0, "XDR output must be 4-aligned");
    assert_eq!(serialized_size(value).expect("size"), bytes.len(), "serialized_size for {value:?}");
    let decoded: T = from_bytes(&bytes).expect("decode");
    assert_eq!(&decoded, value, "round-trip for {value:?}");
}

#[test]
fn scalars_are_big_endian_4byte_words() {
    check(&true, &[0, 0, 0, 1]);
    check(&false, &[0, 0, 0, 0]);
    check(&1u32, &[0, 0, 0, 1]);
    check(&(-1i32), &[0xff, 0xff, 0xff, 0xff]);
    // i8/i16 sign-extend into one 4-byte word.
    check(&(-1i16), &[0xff, 0xff, 0xff, 0xff]);
    check(&(-2i8), &[0xff, 0xff, 0xff, 0xfe]);
    check(&255u8, &[0, 0, 0, 0xff]);
}

#[test]
fn hyper_is_eight_bytes_high_word_first() {
    check(&5i64, &[0, 0, 0, 0, 0, 0, 0, 5]);
    check(&(-1i64), &[0xff; 8]);
    check(&0x0102_0304_0506_0708u64, &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn floats_are_ieee_big_endian() {
    check(&1.0f32, &1.0f32.to_bits().to_be_bytes());
    check(&1.5f64, &1.5f64.to_bits().to_be_bytes());
}

#[test]
fn strings_are_length_prefixed_and_padded_no_nul() {
    // u32 len 3 + "abc" + 1 pad byte; NO NUL terminator.
    check(&"abc".to_string(), &[0, 0, 0, 3, b'a', b'b', b'c', 0]);
    check(&"".to_string(), &[0, 0, 0, 0]);
    check(&"四".to_string(), &[0, 0, 0, 3, 0xe5, 0x9b, 0x9b, 0]); // 3 UTF-8 bytes + 1 pad
}

#[test]
fn options_use_a_presence_word() {
    check(&Some(5u32), &[0, 0, 0, 1, 0, 0, 0, 5]);
    check(&Option::<u32>::None, &[0, 0, 0, 0]);
}

#[test]
fn variable_seq_has_a_count_prefix() {
    check(&vec![1u32, 2], &[0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]);
    check(&Vec::<u32>::new(), &[0, 0, 0, 0]);
}

#[test]
fn fixed_array_has_no_count() {
    // `[u32; 3]` (fixed) is three words with no length prefix...
    check(&[1u32, 2, 3], &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
    // ...whereas a tuple is its elements concatenated.
    check(&(1u32, true), &[0, 0, 0, 1, 0, 0, 0, 1]);
}

#[test]
fn var_opaque_is_length_prefixed_padded() {
    check(&VarOpaque(vec![1, 2, 3]), &[0, 0, 0, 3, 1, 2, 3, 0]);
    check(&VarOpaque(vec![]), &[0, 0, 0, 0]);
}

#[test]
fn fixed_opaque_has_no_length_prefix() {
    check(&FixedOpaque([0xaa, 0xbb, 0xcc, 0xdd]), &[0xaa, 0xbb, 0xcc, 0xdd]);
    // 2 bytes + 2 pad, no length prefix.
    check(&FixedOpaque([1u8, 2]), &[1, 2, 0, 0]);
    // 6 bytes + 2 pad.
    check(&FixedOpaque([1u8, 2, 3, 4, 5, 6]), &[1, 2, 3, 4, 5, 6, 0, 0]);
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Inner {
    x: i64,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Demo {
    name: String,
    count: i64,
    active: bool,
    note: Option<String>,
    tags: Vec<String>,
    inner: Inner,
}

#[test]
fn nested_struct_concatenates_fields_in_order() {
    let d = Demo {
        name: "hi".to_string(),
        count: 7,
        active: true,
        note: None,
        tags: vec!["a".to_string()],
        inner: Inner { x: -1 },
    };
    let bytes = to_bytes(&d).unwrap();
    #[rustfmt::skip]
    let expected = [
        0,0,0,2, b'h', b'i', 0, 0,        // name "hi" (len2 + 2 pad)
        0,0,0,0, 0,0,0,7,                 // count i64 = 7
        0,0,0,1,                          // active = true
        0,0,0,0,                          // note = None
        0,0,0,1, 0,0,0,1, b'a',0,0,0,     // tags: count1, "a" (len1 + 3 pad)
        0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, // inner.x i64 = -1
    ];
    assert_eq!(bytes, expected);
    assert_eq!(from_bytes::<Demo>(&bytes).unwrap(), d);
}

#[test]
fn from_bytes_exact_rejects_trailing_bytes() {
    let bytes = to_bytes(&7u32).unwrap();
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(from_bytes_exact::<u32>(&bytes).is_ok());
    assert!(matches!(
        from_bytes_exact::<u32>(&extra),
        Err(truenas_xdr::XdrError::TrailingBytes)
    ));
}

#[test]
fn decode_out_of_range_is_an_error() {
    // 256 encoded as a u32, decoded into a u8, overflows.
    let bytes = to_bytes(&256u32).unwrap();
    assert!(matches!(from_bytes::<u8>(&bytes), Err(truenas_xdr::XdrError::Range)));
}

#[test]
fn decode_truncated_input_is_eof() {
    assert!(matches!(from_bytes::<u32>(&[0, 0]), Err(truenas_xdr::XdrError::Eof { .. })));
}
