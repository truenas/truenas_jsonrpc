//! Tests for the `XdrEnum` / `XdrUnion` derives, including the FreeBSD `sctrl` union
//! golden (the `grab = 4` discriminant gap that proves a declaration-index encoding would
//! be wrong). The byte sequences are the FreeBSD `sys/xdr`-emitted values.

use serde::{Deserialize, Serialize};
use truenas_xdr::{from_bytes, serialized_size, to_bytes, XdrEnum, XdrUnion};

#[derive(XdrEnum, Clone, Copy, PartialEq, Debug)]
#[repr(i32)]
enum Dir {
    None = 0,
    Call = 1,
    Reply = 2,
    Both = 3,
}

#[derive(XdrEnum, Clone, Copy, PartialEq, Debug)]
#[repr(i32)]
enum Gapped {
    A = 0,
    B = 4, // a gap: the declaration index would be 1, but the wire value must be 4
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct GrabArg {
    number: i32,
    dir: Dir,
    stamp: String,
}

#[derive(XdrUnion, Clone, PartialEq, Debug)]
#[repr(i32)]
enum CtrlArg {
    Reset = 0,
    Record(i32) = 1,
    Pause = 2,
    Grab(GrabArg) = 4,
}

#[test]
fn xdr_enum_encodes_declared_discriminant() {
    assert_eq!(to_bytes(&Dir::Both).unwrap(), [0, 0, 0, 3]);
    assert_eq!(from_bytes::<Dir>(&[0, 0, 0, 3]).unwrap(), Dir::Both);
    // The gap: B encodes as 4, not the declaration index 1.
    assert_eq!(to_bytes(&Gapped::B).unwrap(), [0, 0, 0, 4]);
    assert_eq!(from_bytes::<Gapped>(&[0, 0, 0, 4]).unwrap(), Gapped::B);
}

#[test]
fn xdr_enum_rejects_unknown_discriminant() {
    // 1 is not a valid Gapped discriminant (only 0 and 4).
    assert!(from_bytes::<Gapped>(&[0, 0, 0, 1]).is_err());
}

#[test]
fn sctrl_union_matches_freebsd_golden() {
    let grab = CtrlArg::Grab(GrabArg {
        number: 5,
        dir: Dir::Both,
        stamp: "hi".to_string(),
    });
    #[rustfmt::skip]
    let golden = [
        0,0,0,4,           // CtrlArg discriminant: grab = 4
        0,0,0,5,           // GrabArg.number = 5
        0,0,0,3,           // GrabArg.dir = both = 3
        0,0,0,2, b'h', b'i', 0,0, // GrabArg.stamp = "hi" (len 2 + 2 pad)
    ];
    let bytes = to_bytes(&grab).unwrap();
    assert_eq!(bytes, golden, "20-byte sctrl grab union");
    assert_eq!(bytes.len(), 20);
    assert_eq!(serialized_size(&grab).unwrap(), 20);
    assert_eq!(from_bytes::<CtrlArg>(&golden).unwrap(), grab);
}

#[test]
fn union_void_arm_is_tag_only() {
    assert_eq!(to_bytes(&CtrlArg::Reset).unwrap(), [0, 0, 0, 0]);
    assert_eq!(
        from_bytes::<CtrlArg>(&[0, 0, 0, 0]).unwrap(),
        CtrlArg::Reset
    );
    // A data arm with a single payload word.
    assert_eq!(
        to_bytes(&CtrlArg::Record(7)).unwrap(),
        [0, 0, 0, 1, 0, 0, 0, 7]
    );
    assert_eq!(
        from_bytes::<CtrlArg>(&[0, 0, 0, 1, 0, 0, 0, 7]).unwrap(),
        CtrlArg::Record(7)
    );
    assert_eq!(to_bytes(&CtrlArg::Pause).unwrap(), [0, 0, 0, 2]);
}

#[test]
fn union_rejects_unknown_discriminant() {
    assert!(from_bytes::<CtrlArg>(&[0, 0, 0, 9]).is_err());
}
