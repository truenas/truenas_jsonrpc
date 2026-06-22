//! Conformance against the cross-language golden `xdr_cases`
//! (`truenas_jsonrpc/zig/conformance/golden.json`), generated normatively by the Python
//! `truenas_pyjsonrpc.xdr` codec. The `add` and `unknown_proc` (error) cases are validated
//! in `frame.rs`; here are the `echo`/`echo_empty` cases, which exercise list + optional +
//! bool + string together. (The three `xdr_filter_*` cases exercise the dispatch layer's
//! filterable encoding — base + `XdrQueryOptions` + filters-JSON-string + `Vec<entry>` — and
//! are validated with the XDR dispatch integration, where those types are defined.)

use serde::{Deserialize, Serialize};
use truenas_xdr::frame::{build_reply_ok, build_request, parse_reply, parse_request};
use truenas_xdr::{from_bytes, to_bytes};

const TEST_ID: [u8; 16] = [
    0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00,
];
const ECHO_PROC: u32 = 1002;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// `xdr.echo`'s params/result type: a list, an optional string, and a bool.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
struct Echo {
    nums: Vec<i32>,
    note: Option<String>,
    flag: bool,
}

/// Drive one echo case: build the request frame (assert == golden), parse it, decode the
/// params, then echo them back as a reply (assert == golden), and decode the reply body.
fn check_echo(value: Echo, request_hex: &str, reply_hex: &str) {
    let params = to_bytes(&value).unwrap();
    let request = build_request(ECHO_PROC, Some(TEST_ID), &params).unwrap();
    assert_eq!(request, unhex(request_hex), "echo request frame");

    let req = parse_request(&request).unwrap();
    assert_eq!(req.proc_id, ECHO_PROC);
    assert_eq!(from_bytes::<Echo>(req.params).unwrap(), value);

    // echo: the handler returns its argument, so the reply body is the same encoded bytes.
    let reply = build_reply_ok(req.rid, req.params).unwrap();
    assert_eq!(reply, unhex(reply_hex), "echo reply frame");
    let parsed = parse_reply(&reply).unwrap();
    assert_eq!(from_bytes::<Echo>(parsed.body).unwrap(), value);
}

#[test]
fn xdr_echo() {
    check_echo(
        Echo { nums: vec![1, 2, 3], note: Some("hi".to_string()), flag: true },
        "5458445200000001000003ea00000001123e4567e89b12d3a4564266141740000000000300000001000000020000000300000001000000026869000000000001",
        "545844520000000100000001123e4567e89b12d3a456426614174000000000000000000300000001000000020000000300000001000000026869000000000001",
    );
}

#[test]
fn xdr_echo_empty() {
    check_echo(
        Echo { nums: vec![], note: None, flag: false },
        "5458445200000001000003ea00000001123e4567e89b12d3a456426614174000000000000000000000000000",
        "545844520000000100000001123e4567e89b12d3a45642661417400000000000000000000000000000000000",
    );
}
