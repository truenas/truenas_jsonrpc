//! Rust filter-engine benchmark — an `Entry` dataset, `x.query` wires, and a
//! WARMUP/TRIALS/ITERS protocol (min-of-trials). It measures the Rust filter engine
//! (predicates over a `serde_json::Value` *view* of each row).
//!
//! The dataset is leaked to `&'static`, so the handler yields `&Entry` with **no per-row
//! clone** — isolating the filter's cost (the per-row `to_value` view + dynamic compare)
//! rather than a benchmark artifact. Run optimized (debug numbers are meaningless):
//!     cargo run --release --example filter_bench

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use truenas_jsonrpc::{
    tnfilter, CompiledFilters, CompiledOptions, FilterableJsonRpcMethod, JsonRpcError,
    JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx,
};

#[derive(Deserialize, Serialize)]
struct QueryArgs {}

#[derive(Serialize)]
struct Entry {
    id: i64,
    name: &'static str,
    ratio: f64,
    active: bool,
    note: Option<&'static str>,
}

const NAMES: [&str; 4] = ["alpha", "beta", "gamma", "delta"];
const N: usize = 100_000;
const WARMUP: usize = 10;
const TRIALS: usize = 5;
const ITERS: usize = 100;
const UID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn fq(params: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":"{UID}","method":"x.query","params":{params}}}"#).into_bytes()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // The row dataset, leaked so the handler can yield `&Entry`.
    let data: Vec<Entry> = (0..N)
        .map(|i| Entry {
            id: i as i64,
            name: NAMES[i % 4],
            ratio: (i % 1000) as f64 * 0.5,
            active: i % 2 == 0,
            note: if i % 3 == 0 { None } else { Some("note") },
        })
        .collect();
    let data: &'static [Entry] = Box::leak(data.into_boxed_slice());

    let proto = JsonRpcProtocol::<()>::builder("bench", "1.0.0")
        .filterable(FilterableJsonRpcMethod::<QueryArgs, &'static Entry, _>::new(
            MethodDef::new("x.query"),
            move |_a: QueryArgs, _cx: &RequestCtx<()>, f: &CompiledFilters, o: &CompiledOptions| {
                Ok::<_, JsonRpcError>(tnfilter(data.iter(), f, o)?)
            },
        ))
        .unwrap()
        .build();
    let session = proto.new_session(Some(()), Arc::new(NullOutbound));

    let cases: &[(&str, &str, bool)] = &[
        ("count_all", r#"{"query-filters":[],"query-options":{"count":true}}"#, true),
        ("count_eq", r#"{"query-filters":[["name","=","alpha"]],"query-options":{"count":true}}"#, true),
        ("filter_page", r#"{"query-filters":[["name","=","alpha"]],"query-options":{"limit":100}}"#, false),
        ("order_page", r#"{"query-filters":[],"query-options":{"order_by":["-id"],"limit":100}}"#, false),
    ];

    println!("# rust filter bench  N={N}  iters={ITERS}  trials={TRIALS}  (min-of-trials)");
    println!("{:<14}{:>12}{:>12}{:>9}", "case", "us/op", "Mrows/s", "reply");
    let mut guard = 0u64;
    for (name, params, full_scan) in cases {
        let w = fq(params);
        for _ in 0..WARMUP {
            let _ = proto.dispatch(&w, &session).await;
        }
        let mut reply_len = 0usize;
        let mut best = u128::MAX;
        for _ in 0..TRIALS {
            let start = Instant::now();
            let mut sink = 0u64;
            for _ in 0..ITERS {
                let bytes = proto.dispatch(&w, &session).await.into_bytes().unwrap();
                sink = sink.wrapping_add(bytes.len() as u64);
                reply_len = bytes.len();
            }
            let elapsed = start.elapsed().as_nanos();
            guard = guard.wrapping_add(sink);
            best = best.min(elapsed);
        }
        let ns_op = best as f64 / ITERS as f64;
        let us_op = ns_op / 1000.0;
        if *full_scan {
            let mrows = N as f64 / ns_op * 1000.0;
            println!("{name:<14}{us_op:>12.2}{mrows:>12.1}{reply_len:>9}");
        } else {
            println!("{name:<14}{us_op:>12.2}{:>12}{reply_len:>9}", "-");
        }
    }
    std::hint::black_box(guard);
}
