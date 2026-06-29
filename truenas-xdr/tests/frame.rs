//! TXDR frame tests, including byte-exact validation against the `xdr_add` golden vector
//! from `truenas_jsonrpc/zig/conformance/golden.json` (proving the frame + codec match the
//! cross-language wire). The full 7-case sweep lives in `conformance.rs`.

use serde::{Deserialize, Serialize};
use truenas_xdr::frame::{
    self, build_reply_err, build_reply_ok, build_request, is_xdr, parse_error_payload, parse_reply,
    parse_request, Request,
};
use truenas_xdr::to_bytes;

const TEST_ID: [u8; 16] = [
    0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00,
];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AddArgs {
    a: i32,
    b: i32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AddResult {
    sum: i64,
    label: String,
}

#[test]
fn add_request_matches_golden() {
    // xdr.add is proc-id 1001; args a=2, b=3.
    let golden =
        unhex("5458445200000001000003e900000001123e4567e89b12d3a4564266141740000000000200000003");
    let params = to_bytes(&AddArgs { a: 2, b: 3 }).unwrap();
    let frame = build_request(1001, Some(TEST_ID), &params).unwrap();
    assert_eq!(frame, golden, "xdr_add request frame");

    // ...and parsing recovers the envelope + params.
    let req = parse_request(&frame).unwrap();
    assert_eq!(req.proc_id, 1001);
    assert_eq!(req.rid, Some(TEST_ID));
    assert_eq!(req.version, frame::VERSION);
    assert_eq!(truenas_xdr::from_bytes::<AddArgs>(req.params).unwrap(), AddArgs { a: 2, b: 3 });
}

#[test]
fn add_reply_matches_golden() {
    let golden = unhex(
        "545844520000000100000001123e4567e89b12d3a456426614174000000000000000000000000005000000026f6b0000",
    );
    let result = to_bytes(&AddResult { sum: 5, label: "ok".to_string() }).unwrap();
    let frame = build_reply_ok(Some(TEST_ID), &result).unwrap();
    assert_eq!(frame, golden, "xdr_add reply frame");

    let reply = parse_reply(&frame).unwrap();
    assert_eq!(reply.status, frame::STATUS_OK);
    assert_eq!(reply.rid, Some(TEST_ID));
    assert_eq!(
        truenas_xdr::from_bytes::<AddResult>(reply.body).unwrap(),
        AddResult { sum: 5, label: "ok".to_string() }
    );
}

#[test]
fn error_frame_matches_golden() {
    // xdr_unknown_proc: status=1, code=-32601, detail = the JSON error object.
    let golden = unhex(
        "545844520000000100000001123e4567e89b12d3a45642661417400000000001ffff80a70000002c7b22636f6465223a2d33323630312c226d657373616765223a224d6574686f64206e6f7420666f756e64227d",
    );
    let detail = br#"{"code":-32601,"message":"Method not found"}"#;
    let frame = build_reply_err(Some(TEST_ID), -32601, detail).unwrap();
    assert_eq!(frame, golden, "xdr error reply frame");

    let reply = parse_reply(&frame).unwrap();
    assert_eq!(reply.status, frame::STATUS_ERR);
    let (code, got_detail) = parse_error_payload(reply.body).unwrap();
    assert_eq!(code, -32601);
    assert_eq!(got_detail, detail);
}

#[test]
fn notification_has_no_id() {
    let frame = build_request(9, None, b"zz..").unwrap();
    assert!(is_xdr(&frame));
    let req = parse_request(&frame).unwrap();
    assert_eq!(req, Request { version: 1, proc_id: 9, rid: None, params: b"zz.." });
}

#[test]
fn is_xdr_discriminates_json() {
    assert!(is_xdr(&build_request(1, None, &[]).unwrap()));
    assert!(!is_xdr(br#"{"jsonrpc":"2.0"}"#)); // a JSON envelope starts with '{'
    assert!(!is_xdr(b"TX")); // too short
}

#[test]
fn parse_rejects_bad_magic_and_version() {
    // A full, valid frame with a corrupted magic byte → magic-mismatch (not a truncation).
    let mut bad_magic = build_request(1, None, &[]).unwrap();
    bad_magic[0] ^= 0xff;
    assert!(parse_request(&bad_magic).is_err());
    // Correct magic, wrong version (2 instead of 1).
    let mut bad_ver = build_request(1, None, &[]).unwrap();
    bad_ver[7] = 2; // the version word is bytes 4..8
    assert!(parse_request(&bad_ver).is_err());
    // Magic only, no room for the envelope → truncated.
    assert!(parse_request(&[0x54, 0x58, 0x44, 0x52]).is_err());
}
