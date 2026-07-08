//! Micro-benchmark: `JsonRpcProtocol::dispatch` throughput.
//!
//! Numbers (each one a perf-gate cell — see PERF.md):
//!   1a. **JSON dispatch overhead** — a no-op handler, 1 thread, async (awaited inline, no
//!      `spawn_blocking`). The pure JSON parse→decode→encode cost.
//!   1b. **XDR dispatch overhead** — the same no-op handler over the TXDR binary wire. The pure
//!      XDR decode→encode cost; isolates the codec path from the handler.
//!   2. **realistic handler, 1 thread** — a sync handler doing real per-request CPU work
//!      (a stand-in for a checksum / light crypto / building a larger response), driven
//!      sequentially on the `spawn_blocking` path.
//!   3. **realistic handler, N threads** — the same, driven concurrently. Shows the
//!      multi-core speedup (blocking handlers scale across cores).
//!
//! Run release:  `cargo run --release --example bench [noop_iters]`

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use truenas_rpc::{
    AsyncRpcMethod, JsonRpcProtocol, MethodDef, NullOutbound, RequestCtx, RpcMethod,
};

#[derive(Deserialize, Serialize)]
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
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        x ^= x >> 29;
    }
    (x & 0x7fff_ffff) as i64
}

fn report(label: &str, iters: u64, dt: Duration) -> f64 {
    let ops = iters as f64 / dt.as_secs_f64();
    println!(
        "{label:<48}: {ops:>12.0} ops/sec   {:7.2} us/op",
        dt.as_secs_f64() * 1e6 / iters as f64
    );
    ops
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let noop_iters: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000);
    let par = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    println!("cores available: {par}\n");

    // 1) Pure dispatch overhead — no-op handler, 1 thread, inline (no spawn_blocking).
    {
        let proto = JsonRpcProtocol::<()>::builder("bench", "1.0")
            .async_method(AsyncRpcMethod::new(
                MethodDef::new("bench"),
                |a: Args, _c: RequestCtx<()>| async move { Ok(Res { n: a.n + 1 }) },
            ))
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
        report(
            "dispatch overhead, no-op handler, JSON wire (1 thread)",
            noop_iters,
            t0.elapsed(),
        );
    }

    // 1b) Pure dispatch overhead over the TXDR binary wire — same no-op handler, async, 1 thread.
    {
        use truenas_xdr::frame::build_request;
        use truenas_xdr::to_bytes;
        const XID: [u8; 16] = [
            0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e,
            0x6b, 0xf6,
        ];
        let proto = JsonRpcProtocol::<()>::builder("bench", "1.0")
            .async_method(AsyncRpcMethod::new(
                MethodDef::new("bench").xdr(1001),
                |a: Args, _c: RequestCtx<()>| async move { Ok(Res { n: a.n + 1 }) },
            ))
            .unwrap()
            .build();
        let session = proto.new_session(Some(()), Arc::new(NullOutbound));
        let xdr_wire = build_request(1001, Some(XID), &to_bytes(&Args { n: 41 }).unwrap()).unwrap();
        for _ in 0..50_000 {
            let _ = proto.dispatch(&xdr_wire, &session).await;
        }
        let t0 = Instant::now();
        for _ in 0..noop_iters {
            let _ = proto.dispatch(&xdr_wire, &session).await;
        }
        report(
            "dispatch overhead, no-op handler, XDR wire (1 thread)",
            noop_iters,
            t0.elapsed(),
        );
    }

    // 1c) **Most sensitive cell.** Concurrent async dispatch throughput — no-op handler, inline (no
    //     `spawn_blocking`), N tasks, JSON + XDR. The async/inline path has no thread hop to mask a
    //     per-request regression (a boxed future, an extra alloc, lost inlining), so a "fuckup" shows
    //     here first — gate hardest on these two numbers.
    {
        use truenas_xdr::frame::build_request;
        use truenas_xdr::to_bytes;
        const XID: [u8; 16] = [
            0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e,
            0x6b, 0xf6,
        ];
        let proto = Arc::new(
            JsonRpcProtocol::<()>::builder("bench", "1.0")
                .async_method(AsyncRpcMethod::new(
                    MethodDef::new("bench").xdr(1001),
                    |a: Args, _c: RequestCtx<()>| async move { Ok(Res { n: a.n + 1 }) },
                ))
                .unwrap()
                .build(),
        );
        let session = proto.new_session(Some(()), Arc::new(NullOutbound));
        let workers = par;
        let per = noop_iters / workers as u64;
        let wires: [(&str, Vec<u8>); 2] = [
            ("JSON", WIRE.to_vec()),
            (
                "XDR",
                build_request(1001, Some(XID), &to_bytes(&Args { n: 41 }).unwrap()).unwrap(),
            ),
        ];
        for (wlabel, wire) in wires {
            for _ in 0..20_000 {
                let _ = proto.dispatch(&wire, &session).await;
            }
            let t0 = Instant::now();
            let mut handles = Vec::with_capacity(workers);
            for _ in 0..workers {
                let (p, s, w) = (proto.clone(), session.clone(), wire.clone());
                handles.push(tokio::spawn(async move {
                    for _ in 0..per {
                        let _ = p.dispatch(&w, &s).await;
                    }
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
            report(
                &format!("async dispatch, no-op, {wlabel} wire ({workers} tasks, concurrent)"),
                per * workers as u64,
                t0.elapsed(),
            );
        }
    }

    // A realistic sync handler (real CPU work) on the spawn_blocking path.
    let proto = Arc::new(
        JsonRpcProtocol::<()>::builder("bench", "1.0")
            .method(RpcMethod::new(
                MethodDef::new("bench"),
                |a: Args, _c: &RequestCtx<()>| {
                    Ok(Res {
                        n: realistic_work(a.n),
                    })
                },
            ))
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
        report(
            "realistic handler (1 thread, sequential)",
            iters,
            t0.elapsed(),
        )
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
        report(
            &format!("realistic handler ({workers} threads, concurrent)"),
            per * workers as u64,
            t0.elapsed(),
        )
    };

    println!(
        "\nmulti-core speedup on the realistic handler: {:.1}x",
        many / one
    );
}
