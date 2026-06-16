//! Micro-benchmark: `JsonRpcProtocol::dispatch` throughput (Rust), to A/B against
//! `python3 rust/bench/python_dispatch.py`.
//!
//! Three numbers:
//!   1. **dispatch overhead** — a no-op handler, 1 thread, async (awaited inline, no
//!      `spawn_blocking`). The pure parse→decode→encode cost; the apples-to-apples match
//!      for Python's single-threaded synchronous `dispatch`.
//!   2. **realistic handler, 1 thread** — a sync handler doing real per-request CPU work
//!      (a stand-in for a checksum / light crypto / building a larger response), driven
//!      sequentially on the `spawn_blocking` path.
//!   3. **realistic handler, N threads** — the same, driven concurrently. Shows the
//!      multi-core speedup (Rust has no GIL, so blocking handlers scale across cores).
//!
//! Run release:  `cargo run --release --example bench [noop_iters]`

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use truenas_jsonrpc::{
    AsyncJsonRpcMethod, JsonRpcMethod, JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx,
};

#[derive(Deserialize)]
struct Args {
    n: i64,
}
#[derive(Serialize)]
struct Res {
    n: i64,
}

const WIRE: &[u8] = br#"{"jsonrpc":"2.0","method":"bench","id":"f81d4fae-7dec-11d0-a765-00a0c91e6bf6","params":{"n":41}}"#;

/// Stand-in for real per-request CPU work (e.g. a checksum, light crypto, or building a
/// sizeable response). `#[inline(never)]` and feeding the result into the response keep
/// the optimizer from eliding it.
#[inline(never)]
fn realistic_work(seed: i64) -> i64 {
    let mut x = (seed as u64) ^ 0x9e37_79b9_7f4a_7c15;
    for _ in 0..8_000 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        x ^= x >> 29;
    }
    (x & 0x7fff_ffff) as i64
}

fn report(label: &str, iters: u64, dt: Duration) -> f64 {
    let ops = iters as f64 / dt.as_secs_f64();
    println!("{label:<48}: {ops:>12.0} ops/sec   {:7.2} us/op", dt.as_secs_f64() * 1e6 / iters as f64);
    ops
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let noop_iters: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5_000_000);
    let par = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    println!("cores available: {par}\n");

    // 1) Pure dispatch overhead — no-op handler, 1 thread, inline (no spawn_blocking).
    {
        let proto = JsonRpcProtocol::<()>::builder("bench", "1.0")
            .async_method(AsyncJsonRpcMethod::new(MethodDef::new("bench"), |a: Args, _c: RequestCtx<()>| async move {
                Ok(Res { n: a.n + 1 })
            }))
            .unwrap()
            .build();
        let session = proto.new_session(Some(()), Arc::new(NullOutbound));
        for _ in 0..50_000 {
            let _ = proto.dispatch(WIRE, &session).await;
        }
        let t0 = Instant::now();
        for _ in 0..noop_iters {
            let _ = proto.dispatch(WIRE, &session).await;
        }
        report("dispatch overhead, no-op handler (1 thread)", noop_iters, t0.elapsed());
    }

    // A realistic sync handler (real CPU work) on the spawn_blocking path.
    let proto = Arc::new(
        JsonRpcProtocol::<()>::builder("bench", "1.0")
            .method(JsonRpcMethod::new(MethodDef::new("bench"), |a: Args, _c: &RequestCtx<()>| {
                Ok(Res { n: realistic_work(a.n) })
            }))
            .unwrap()
            .build(),
    );
    let session = proto.new_session(Some(()), Arc::new(NullOutbound));
    for _ in 0..2_000 {
        let _ = proto.dispatch(WIRE, &session).await;
    }

    let iters: u64 = 200_000;

    // 2) Realistic handler, single-threaded (sequential).
    let one = {
        let t0 = Instant::now();
        for _ in 0..iters {
            let _ = proto.dispatch(WIRE, &session).await;
        }
        report("realistic handler (1 thread, sequential)", iters, t0.elapsed())
    };

    // 3) Realistic handler, concurrent across cores.
    let many = {
        let workers = par;
        let per = iters / workers as u64;
        let t0 = Instant::now();
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let p = proto.clone();
            let s = session.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..per {
                    let _ = p.dispatch(WIRE, &s).await;
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        report(&format!("realistic handler ({workers} threads, concurrent)"), per * workers as u64, t0.elapsed())
    };

    println!("\nmulti-core speedup on the realistic handler: {:.1}x", many / one);
}
