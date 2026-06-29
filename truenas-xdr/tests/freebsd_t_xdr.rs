//! Port of FreeBSD's XDR conformance test — `contrib/netbsd-tests/lib/libc/rpc/t_xdr.c`
//! plus its `h_testbits.x` IDL (NetBSD-derived; built in FreeBSD as the `xdr_test` ATF
//! test). This is an **independent, canonical Sun-RPC XDR** vector — not generated from
//! this project's Zig/Python pipeline — so it cross-validates the codec against the
//! reference implementation. The C test decodes `xdrdata[]`, then re-encodes and
//! `memcmp`s against it; we assert both directions byte-for-byte.
//!
//! The interesting case is `medenum ME_NEG = -1234`: XDR enums are signed 32-bit, so a
//! negative discriminant must encode as `0xfffffb2e` (two's complement) — which exercises
//! the `XdrEnum` derive's handling of negative `#[repr(i32)]` discriminants.

use truenas_xdr::{from_bytes, to_bytes, XdrEnum};

// Variant names mirror the `h_testbits.x` IDL (SE_*/ME_*/BE_*), hence the shared prefixes.

// --- the enums from h_testbits.x (verbatim discriminants) --------------------

#[derive(XdrEnum, Clone, Copy, PartialEq, Debug)]
#[repr(i32)]
enum SmallEnum {
    SeOne = 1,
    SeTwo = 2,
}

#[derive(XdrEnum, Clone, Copy, PartialEq, Debug)]
#[repr(i32)]
#[allow(clippy::enum_variant_names)]
enum MedEnum {
    MeNeg = -1234,
    MeOne = 1,
    MeTwo = 2,
    MeMany = 1234,
}

#[derive(XdrEnum, Clone, Copy, PartialEq, Debug)]
#[repr(i32)]
#[allow(clippy::enum_variant_names)]
enum BigEnum {
    BeOne = 1,
    BeTwo = 2,
    BeMany = 1234,
    BeLots = 1234567,
}

/// The exact `xdrdata[]` buffer from `t_xdr.c`: `double 1.0`, then SE_ONE, ME_NEG, BE_LOTS.
const T_XDR_GOLDEN: [u8; 20] = [
    0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // double 1.0
    0x00, 0x00, 0x00, 0x01, // smallenum SE_ONE
    0xff, 0xff, 0xfb, 0x2e, // medenum ME_NEG (= -1234)
    0x00, 0x12, 0xd6, 0x87, // bigenum BE_LOTS (= 1234567)
];

#[test]
fn freebsd_t_xdr_vector_round_trips() {
    // The four values t_xdr.c encodes, in order (a tuple = its fields concatenated).
    let value = (1.0f64, SmallEnum::SeOne, MedEnum::MeNeg, BigEnum::BeLots);

    // ENCODE — must equal the FreeBSD buffer byte-for-byte (the C test's memcmp).
    assert_eq!(to_bytes(&value).unwrap(), T_XDR_GOLDEN);

    // DECODE — recovers the values (the C test's XDR_DECODE pass).
    let decoded: (f64, SmallEnum, MedEnum, BigEnum) = from_bytes(&T_XDR_GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn signed_enum_discriminants_match_freebsd() {
    // A negative enum is two's-complement signed i32, and a large one is plain.
    assert_eq!(to_bytes(&MedEnum::MeNeg).unwrap(), [0xff, 0xff, 0xfb, 0x2e]);
    assert_eq!(from_bytes::<MedEnum>(&[0xff, 0xff, 0xfb, 0x2e]).unwrap(), MedEnum::MeNeg);
    assert_eq!(to_bytes(&BigEnum::BeLots).unwrap(), [0x00, 0x12, 0xd6, 0x87]);
    assert_eq!(from_bytes::<MedEnum>(&[0x00, 0x00, 0x04, 0xd2]).unwrap(), MedEnum::MeMany); // 1234
}
