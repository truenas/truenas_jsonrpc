//! Byte-exact conformance for **filterable methods over the XDR binary wire**, against the
//! `xdr_filter_*` committed golden vectors. The golden request bytes are fed straight through
//! `dispatch`; the reply must match the golden byte-for-byte — proving the request decode
//! (base + XdrQueryOptions + query-filters JSON string), the filter engine, and the result
//! encoding (count → hyper, rows → count+entries) all produce the canonical XDR wire bytes.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use truenas_rpc::{
    tnfilter, AuditOutcome, CompiledFilters, CompiledOptions, Dispatched, FilterableRpcMethod,
    JsonRpcError, JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx, RequestInfo, Session,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
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
        FEntry {
            id: 1,
            name: "alpha".into(),
            ratio: 0.5,
            active: true,
            note: Some("x".into()),
        },
        FEntry {
            id: 2,
            name: "beta".into(),
            ratio: 2.5,
            active: false,
            note: None,
        },
        FEntry {
            id: 3,
            name: "alpha".into(),
            ratio: 1.5,
            active: true,
            note: None,
        },
        FEntry {
            id: 4,
            name: "gamma".into(),
            ratio: 3.5,
            active: false,
            note: Some("y".into()),
        },
        FEntry {
            id: 5,
            name: "Alpha".into(),
            ratio: 0.25,
            active: true,
            note: Some("z".into()),
        },
    ]
}

/// `xdr.query` is filterable at proc-id 1003; it streams the dataset through `tnfilter`.
fn proto() -> JsonRpcProtocol<()> {
    JsonRpcProtocol::<()>::builder("conf", "1")
        .filterable(FilterableRpcMethod::<QueryArgs, FEntry, _>::new(
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
            Dispatched::Transfer(_) | Dispatched::Passthrough(_) | Dispatched::Sessions { .. } => {
                unreachable!("transfer/passthrough directive unexpected in this test")
            }
        };
        assert_eq!(got, unhex(reply), "{name}: filterable XDR reply mismatch");
    }
}

#[tokio::test]
async fn audited_filterable_xdr_call_emits_audit_record() {
    // An audited filterable XDR call: the base params and the (reduced) query-filters/options are
    // reflected to JSON for the audit sink — for both the rows and count shapes — even though they
    // ride the binary wire. (The result is not reflected for audit; the record carries the outcome.)
    let records: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let rec = records.clone();
    let p = JsonRpcProtocol::<()>::builder("conf", "1")
        .filterable(FilterableRpcMethod::<QueryArgs, FEntry, _>::new(
            MethodDef::new("xdr.query")
                .xdr(1003)
                .audit_message("queried"),
            |_a: QueryArgs, _cx: &RequestCtx<()>, f: &CompiledFilters, o: &CompiledOptions| {
                Ok::<_, JsonRpcError>(tnfilter(dataset(), f, o)?)
            },
        ))
        .unwrap()
        .audit_sink(
            move |req: &RequestInfo,
                  _outcome: AuditOutcome<'_>,
                  _s: &Session<()>,
                  _m: Option<&str>| {
                rec.lock().unwrap().push(json!({ "params": req.params }));
            },
        )
        .build();
    // `xdr_filter_eq` → the matching rows; `xdr_filter_count` → the integer count. Auditing each
    // exercises params reflection for both the `Rows` and `Count` shapes (the wire bytes themselves are
    // covered byte-for-byte by `xdr_filter_goldens`).
    let rows_req = unhex("5458445200000001000003eb00000001123e4567e89b12d3a456426614174000000000000000000000000000000000000000000000000000000000165b5b226e616d65222c223d222c22616c706861225d5d0000");
    let count_req = unhex("5458445200000001000003eb00000001123e4567e89b12d3a456426614174000000000010000000000000000000000000000000000000000000000165b5b226e616d65222c223d222c22616c706861225d5d0000");
    for req in [rows_req, count_req] {
        let s = p.new_session(Some(()), Arc::new(NullOutbound));
        let _ = p.dispatch(&req, &s).await;
    }
    let recs = records.lock().unwrap();
    // Rows shape: the reflected query-filters.
    assert_eq!(
        recs[0]["params"]["query-filters"],
        json!([["name", "=", "alpha"]])
    );
    // Count shape: the reflected query-options.
    assert_eq!(recs[1]["params"]["query-options"]["count"], true);
}
