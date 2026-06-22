//! Byte-exact conformance for **filterable methods over the XDR binary wire**, against the
//! `xdr_filter_*` golden vectors (`truenas_jsonrpc/zig/conformance/golden.json`). The golden
//! request bytes are fed straight through `dispatch`; the reply must match the golden
//! byte-for-byte — proving the request decode (base + XdrQueryOptions + query-filters JSON
//! string), the filter engine, and the result encoding (count → hyper, rows → count+entries)
//! are all wire-compatible with the Python/Zig implementations.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use truenas_jsonrpc::{
    tnfilter, CompiledFilters, CompiledOptions, Dispatched, FilterableJsonRpcMethod, JsonRpcError,
    JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The filterable method's base accepts (empty — the query rides in query-filters/options).
#[derive(Serialize, Deserialize)]
struct QueryArgs {}

/// The `entry` type streamed through the filter (id hyper, name string, ratio double,
/// active bool, note optional string).
#[derive(Serialize, Deserialize)]
struct FEntry {
    id: i64,
    name: String,
    ratio: f64,
    active: bool,
    note: Option<String>,
}

/// The fixed source the golden was generated from (recovered by decoding the unfiltered
/// `order_desc` golden), in id order.
fn dataset() -> Vec<FEntry> {
    vec![
        FEntry { id: 1, name: "alpha".into(), ratio: 0.5, active: true, note: Some("x".into()) },
        FEntry { id: 2, name: "beta".into(), ratio: 2.5, active: false, note: None },
        FEntry { id: 3, name: "alpha".into(), ratio: 1.5, active: true, note: None },
        FEntry { id: 4, name: "gamma".into(), ratio: 3.5, active: false, note: Some("y".into()) },
        FEntry { id: 5, name: "Alpha".into(), ratio: 0.25, active: true, note: Some("z".into()) },
    ]
}

/// `xdr.query` is filterable at proc-id 1003; it streams the dataset through `tnfilter`.
fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("conf", "1")
        .filterable(FilterableJsonRpcMethod::<QueryArgs, FEntry, _>::new(
            MethodDef::new("xdr.query").xdr(1003),
            |_a: QueryArgs, _cx: &RequestCtx<()>, f: &CompiledFilters, o: &CompiledOptions| {
                Ok::<_, JsonRpcError>(tnfilter(dataset(), f, o)?)
            },
        ))
        .unwrap()
        .build()
}

#[tokio::test]
async fn xdr_filter_goldens() {
    // (name, request hex, reply hex) from golden.json `xdr_cases`.
    let cases = [
        (
            "xdr_filter_eq",
            "5458445200000001000003eb00000001123e4567e89b12d3a456426614174000000000000000000000000000000000000000000000000000000000165b5b226e616d65222c223d222c22616c706861225d5d0000",
            "545844520000000100000001123e4567e89b12d3a4564266141740000000000000000002000000000000000100000005616c7068610000003fe000000000000000000001000000010000000178000000000000000000000300000005616c7068610000003ff80000000000000000000100000000",
        ),
        (
            "xdr_filter_count",
            "5458445200000001000003eb00000001123e4567e89b12d3a456426614174000000000010000000000000000000000000000000000000000000000165b5b226e616d65222c223d222c22616c706861225d5d0000",
            "545844520000000100000001123e4567e89b12d3a456426614174000000000000000000000000002",
        ),
        (
            "xdr_filter_order_desc",
            "5458445200000001000003eb00000001123e4567e89b12d3a456426614174000000000000000000100000001000000062d726174696f000000000000000000000000000000000000000000025b5d0000",
            "545844520000000100000001123e4567e89b12d3a456426614174000000000000000000500000000000000040000000567616d6d61000000400c000000000000000000000000000100000001790000000000000000000002000000046265746140040000000000000000000000000000000000000000000300000005616c7068610000003ff80000000000000000000100000000000000000000000100000005616c7068610000003fe000000000000000000001000000010000000178000000000000000000000500000005416c7068610000003fd00000000000000000000100000001000000017a000000",
        ),
    ];

    let p = proto();
    for (name, request, reply) in cases {
        let s = p.new_session(Some(()), Arc::new(NullOutbound));
        let got = match p.dispatch(&unhex(request), &s).await {
            Dispatched::Reply(b) => b,
            Dispatched::Nothing => panic!("{name}: expected a reply"),
        };
        assert_eq!(got, unhex(reply), "{name}: filterable XDR reply mismatch");
    }
}
