# Dispatch benchmark — Python vs Zig

A like-for-like microbenchmark of the **synchronous dispatch core**: `wire bytes in → reply bytes out`,
single-threaded, with trivial handlers so it measures *framework overhead* (JSON parse, id/structural
validation, method lookup, param decode, handler call, result encode, response serialize) rather than
application work.

The two harnesses are deliberate mirrors:

| | Zig | Python |
|---|---|---|
| file | [`bench.zig`](bench.zig) (consumes `@import("truenas_jsonrpc")`) | [`bench.py`](bench.py) (imports `truenas_pyjsonrpc`) |
| methods | `add`, `pool.create` (trivial) | same |
| param/result types | plain `struct`s | `msgspec.Struct`s of identical shape |
| input | `[]const u8` wire | the same wire, pre-`.encode("utf-8")`'d to `bytes` |
| session | one long-lived `newSession`, reused | one long-lived `new_session()`, reused |
| op measured | `proto.dispatch(reply_alloc, wire, &sess)`, reply freed | `proto.dispatch(wire, sess)`, reply dropped |

Both run the same corpus and the same protocol (`WARMUP` untimed dispatches, then `TRIALS` timed runs of
`ITERS` dispatches), and report the **minimum ns/op across trials** — steady-state, least scheduler/GC/
allocator noise.

## Corpus

| case | exercises |
|---|---|
| `add` | parse + decode 2 ints + run + encode 1 int + serialize (the common path) |
| `create` | decode 1 string, encode a 2-field object |
| `method_not_found` | request error path with no param decode |
| `invalid_params` | decode-failure path (array params → by-name-only rejection) |
| `notification` | decode + run, **no** response serialization |
| `parse_error` | earliest exit (malformed JSON) |

## Running

Run them **sequentially**, not concurrently (concurrent runs contend for CPU and inflate both):

```sh
# Zig — ReleaseFast is mandatory; Debug numbers are meaningless
zig build bench -Doptimize=ReleaseFast

# Python
python3 bench/bench.py
```

## What this is and isn't

- **Is:** an honest, full-stack, single-threaded dispatch-cost comparison of the two libraries *as
  written* — Python's JSON work runs in msgspec's C extension; Zig's runs in pure-Zig `std.json`.
- **Isn't:** a throughput/concurrency benchmark (that belongs to the future transport layer), nor a
  test of large/nested payloads. The handlers are trivial on purpose.
- **Known Zig headroom not exercised here:** `dispatch` allocates a fresh arena per call; a server could
  reuse one arena across requests (`reset(.retain_capacity)`), and `std.json` decode-into-struct has
  further room. These are deliberately left as-written so the number reflects today's code.

## Results

Sequential run on an **Intel Atom C3758 @ 2.20 GHz** (8 cores; a TrueNAS appliance-class CPU — absolute
numbers are conservative, the *ratio* is the point). Python 3.13.5 / msgspec 0.20.0; Zig 0.16.0
ReleaseFast. Min-of-7-trials `ns/op`:

| case | Python ns/op | Zig ns/op | Zig speedup | Python ops/s | Zig ops/s |
|---|---:|---:|:---:|---:|---:|
| `add` | 33,581 | 3,745 | **9.0×** | 29,779 | 267,046 |
| `create` | 33,363 | 3,655 | **9.1×** | 29,973 | 273,579 |
| `method_not_found` | 18,135 | 3,336 | **5.4×** | 55,143 | 299,749 |
| `invalid_params` | 25,460 | 4,312 | **5.9×** | 39,278 | 231,900 |
| `notification` | 12,226 | 2,811 | **4.4×** | 81,791 | 355,719 |
| `parse_error` | 8,200 | 1,222 | **6.7×** | 121,956 | 818,628 |

**Read:** the Zig dispatch core is ~5–9× faster on the common request path, single-threaded. The wider
gaps on `add`/`create` include Python's `uuid.UUID()` id validation, msgspec encode, and (for
`invalid_params`/`parse_error`) building the error `data` detail string — work the Zig side does more
cheaply or omits. Reply sizes differ on the error cases because Python attaches a `data` detail that the
Zig engine does not (the conformance suite strips it before comparing).

**Optimization history.** The success path originally serialized the handler result to a `std.json.Value`
tree (stringify → parse-back) which the envelope then *re-stringified* — `add`/`create` measured ~5.2/5.6
µs. Carrying the already-serialized result bytes in `Ran.ok_bytes` and splicing them straight into the
envelope (`successBytesRaw`) removed both the parse-back and the re-stringify: `add` 5.24 → 3.74 µs
(−29%), `create` 5.61 → 3.66 µs (−35%), and `notification` 3.43 → 2.81 µs (−18%, since `run` still
serializes the result even when it's discarded). A/B conformance stayed green throughout (responses are
byte-equivalent to Python). Remaining headroom: the wire is still parsed into a full `Value` tree, the
per-dispatch arena is created/destroyed each call, and notifications serialize a result they discard.

> Re-run after any dispatch change; numbers are machine-specific.
