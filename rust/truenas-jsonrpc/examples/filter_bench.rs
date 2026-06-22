//! End-to-end A/B benchmark (Rust): dispatch a filterable JSON-RPC method over a 100K-row
//! array, to compare against `python3 rust/bench/python_filter.py`.
//!
//! Each row is one full `dispatch` (wire bytes in -> reply bytes out): envelope parse +
//! param decode + query compile + the handler feeding the 100K rows through `tnfilter` +
//! result encode. The handler holds the dataset and feeds the (move-through) engine via
//! `data.iter().cloned()` — so it clones each row the engine *pulls* (all rows on a full
//! scan; only the few pulled before a `get`/`limit` short-circuit otherwise). A real
//! streaming handler (DB cursor / libzfs iterator) would avoid even that.
//!
//! Run release:  `cargo run --release --example filter_bench`

use std::fs;
use std::sync::Arc;
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;
use truenas_jsonrpc::{
    compile_filters, tnfilter, tnmatch, CompiledFilters, CompiledOptions, Dispatched,
    FilterableJsonRpcMethod, JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx,
};

#[derive(Deserialize)]
struct Empty {}

const DATA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../bench/filter_data.json");

fn wire(params: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","method":"report.query","id":"f81d4fae-7dec-11d0-a765-00a0c91e6bf6","params":{params}}}"#
    )
    .into_bytes()
}

fn result_size(d: Dispatched) -> i64 {
    let bytes = d.into_bytes().expect("reply");
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    match &v["result"] {
        Value::Array(a) => a.len() as i64,
        Value::Number(n) => n.as_i64().unwrap_or(-1), // count
        Value::Object(_) => 1,                        // get -> a single record
        _ => -1,
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let raw = fs::read_to_string(DATA_PATH)
        .expect("read filter_data.json — run `python3 rust/bench/gen_filter_data.py` first");
    let data: Arc<Vec<Value>> = Arc::new(serde_json::from_str(&raw).expect("parse filter_data.json"));
    println!("rows: {}\n", data.len());

    let d = data.clone();
    let proto = JsonRpcProtocol::<()>::builder("bench", "1.0")
        .filterable(FilterableJsonRpcMethod::<Empty, Value, _>::new(
            MethodDef::new("report.query"),
            move |_a: Empty, _cx: &RequestCtx<()>, f: &CompiledFilters, o: &CompiledOptions| {
                Ok(tnfilter(d.iter().cloned(), f, o)?)
            },
        ))
        .unwrap()
        .build();
    let session = proto.new_session(Some(()), Arc::new(NullOutbound));

    let scenarios: &[(&str, &str, u64)] = &[
        ("count active=true (scan, no encode)",
         r#"{"query-filters":[["active","=",true]],"query-options":{"count":true}}"#, 200),
        ("get active=true (short-circuit)",
         r#"{"query-filters":[["active","=",true]],"query-options":{"get":true}}"#, 500),
        ("eq id=50000 (full scan, 1 row)",
         r#"{"query-filters":[["id","=",50000]]}"#, 200),
        ("filter active=true (50K rows, encode-heavy)",
         r#"{"query-filters":[["active","=",true]]}"#, 20),
        ("order_by -score limit 10 (sort 100K)",
         r#"{"query-filters":[],"query-options":{"order_by":["-score"],"limit":10}}"#, 30),
    ];

    println!("{:<46} {:>10} {:>11} {:>9}", "scenario", "ms/query", "queries/s", "result");
    println!("{}", "-".repeat(80));
    for (label, params, iters) in scenarios {
        let w = wire(params);
        for _ in 0..3 {
            let _ = proto.dispatch(&w, &session).await;
        }
        let sz = result_size(proto.dispatch(&w, &session).await);
        let t0 = Instant::now();
        for _ in 0..*iters {
            let _ = proto.dispatch(&w, &session).await;
        }
        let dt = t0.elapsed().as_secs_f64();
        println!("{label:<46} {:>10.3} {:>11.0} {sz:>9}", dt / *iters as f64 * 1e3, *iters as f64 / dt);
    }

    // --- decomposition: isolate the engine from the move-through feed -------------------
    // Engine-only, borrowed: the fair apples-to-apples vs Python's C `tnfilter` count — no
    // dispatch, no per-row clone, no encode; just the compiled predicate over &data.
    let cf = compile_filters(&[serde_json::json!(["active", "=", true])]).unwrap();
    let iters = 200u64;
    let t0 = Instant::now();
    let mut acc = 0i64;
    for _ in 0..iters {
        let mut n = 0i64;
        for row in data.iter() {
            if tnmatch(row, &cf).unwrap() {
                n += 1;
            }
        }
        acc += n;
    }
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "\nengine-only borrowed scan (tnmatch over &data, no clone/encode): {:>8.3} ms/scan  ({} matches)",
        dt / iters as f64 * 1e3,
        acc / iters as i64
    );

    // The per-row clone the move-through feed adds on a full scan (`data.iter().cloned()`).
    let t0 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(data.iter().cloned().count());
    }
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "clone-feed overhead (data.iter().cloned() of all {} rows):  {:>8.3} ms/scan",
        data.len(),
        dt / iters as f64 * 1e3
    );
}
