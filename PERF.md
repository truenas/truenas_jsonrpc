# Performance gate

The dispatch hot path is the load-bearing cost of the server. Changes to it — especially the
`ProtocolEngine` seam refactor — must not regress throughput. A prior naive pluggable-codec attempt
caused a ~3–4× drop; the fix (the enum-based `Codec` seam) was validated **free** by A/B benchmarking.
This note is the standing gate: **A/B every hot-path change against a baseline and root-cause any
movement beyond run-to-run noise.**

The numbers below are **relative** — they are valid only as before/after pairs measured on the *same
machine, back to back*. Don't compare across machines; re-measure the baseline locally before an A/B.

## Two guards

**1. Committable dispatch microbench (zero-dep, `std::time`)** — isolates the per-request hot path
(`JsonRpcProtocol::dispatch(bytes) -> Dispatched`), JSON + XDR. The most sensitive cell (low variance);
catches per-request alloc / `dyn` regressions directly.

```sh
cargo run --release -p truenas-jsonrpc --example bench [noop_iters]   # default 5_000_000
# best-of-3 is plenty:
for r in 1 2 3; do taskset -c 0-7 ./target/release/examples/bench 2000000; done
```

**2. Local e2e throughput harness (gitignored, `bench/`)** — full path: framing + syscalls + writev +
the connection loop + dispatch, over an AF_UNIX socket. Catches framing/writer/connection-loop
regressions (what Phase 2+ touches). `bench/` is local tooling, not committed; the driver is a single
no-deps file built with `rustc`.

```sh
cargo build --release -p truenas-jsonrpc-server --example bench_server   # the server (untracked, local)
rustc -O --edition 2021 bench/unix_ab/driver.rs -o bench/unix_ab/driver  # the load driver (gitignored)
# start server on a socket, then: ./bench/unix_ab/driver <sock> 50000 8   (50k req × 8 conns)
# BENCH_MODE=async on the server for the inline/async path.
```

## Baseline (dev box; commit `4cbd05f`; best-of-3, `taskset -c 0-7`)

Re-measure locally before trusting these — they anchor the *shape*, not absolute hardware numbers.

**The async/inline cells are the primary gate.** The async path has no `spawn_blocking` thread hop to
mask a per-request regression (a boxed future, an extra alloc, lost inlining), so a "fuckup" shows
there first — the sync cells' thread hop swamps small regressions. Gate hardest on the async numbers.

| Microbench cell (`async` = inline, no `spawn_blocking`) | ops/sec | µs/op | run-to-run |
|---|---:|---:|---|
| **async** JSON dispatch overhead (no-op, 1 thread) | ~209 000 | 4.78 | ±1% ← tightest |
| **async** XDR  dispatch overhead (no-op, 1 thread) | ~920 000 | 1.09 | ±1% ← tightest |
| **async** JSON dispatch, no-op (8 tasks, concurrent) | ~1 100 000 | 0.90 | ±10% |
| **async** XDR  dispatch, no-op (8 tasks, concurrent) | ~2 200 000 | 0.46 | ±15% |
| sync realistic handler (1 thread, sequential)        | ~15 400 | 65 | ±3% |
| sync realistic handler (8 threads, concurrent)       | ~73 000 | 14 | ±9% |

| E2e (8 conns × 50k, req/reply) | req/sec | run-to-run |
|---|---:|---|
| **async** (inline, `delay_us=0`)     | ~63 000 | ±6% ← primary |
| sync (spawn_blocking, `delay_us=0`)  | ~64 000 | ±4% |

The two single-thread **async** dispatch-overhead cells (±1%) are the most sensitive — watch them first.
The concurrent async cells add an under-load check (noisier). The sync / realistic cells are handler-
and syscall-dominated and least sensitive.

## Landed change — the `Service` op-table extraction (Stage 1)

Lifting the op-table off `JsonRpcProtocol` into a shared `Service<S>` — so the JSON-RPC and ONC RPC
wires are both *views* over one op-table — puts the registry, run core, and session registry behind one
`Arc<Service>` the protocol holds. The only per-request delta is a single `Arc<Service>` pointer-load at
the top of the dispatch prelude, reused across the ~5 field reads it guards. **A/B (back-to-back,
best-of-3, single-thread async): XDR ~919–920k vs a ~907–913k baseline; JSON unchanged within noise** —
the indirection is free (the pointer is hot, and those reads were already chasing `self`).

**`Service::prepare_xdr` is `#[inline(always)]`, and that is load-bearing — not cosmetic.** It returns
the ~100-byte per-request pipeline by value and has two callers (`Service::run_proc` and
`JsonRpcProtocol::dispatch_xdr`). With a plain `#[inline]`, LLVM *declined* to inline it across the
`Service` boundary, leaving a real call plus a return-slot `memcpy` on the XDR hot path — a measured
~2% on the single-thread async XDR cell, confirmed back-to-back. Forcing the inline folds the prelude
into each caller, so the generated hot path is identical to before the seam existed. **Do not relax it
without re-running the XDR cell.**

## The gate

- **A/B every hot-path change**: capture the baseline, apply the change, re-measure, compare on the same
  machine. A cell that moves **beyond its run-to-run noise** is a regression to **root-cause
  (perf/flamegraph), not a tax to accept** — the swings are real and findable.
- **Per-request regression checklist** — the refactor must add **zero** of, per request:
  - new heap allocations (`Box`/`Vec`/`String`);
  - new `dyn`/vtable calls on the hot path (the engine boundary is per-**connection**, not per-request);
  - `Box<dyn Future>` or a `tokio::spawn` per request;
  - `Bytes` → `Vec` copies (lost zero-copy);
  - `serde_json::Value` materialization / round-trips;
  - re-encodes (encode once);
  - locks on the hot path.
- The baseline is already tuned (audit snapshot only when audited; `run` vs `run_value` to avoid an extra
  box; vectored writes). The bar is **stay at it**.
