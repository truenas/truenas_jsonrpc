#!/usr/bin/env python3
"""Filtering A/B microbenchmark for the Python reference — the mirror of `bench/filter_bench.zig`: the same
dataset (generated identically), the same `x.query` wires, one long-lived session, bytes-in -> reply-bytes-out.
So the two programs' numbers are directly comparable: Python's `tnfilter` (the truenas_pyfilter C engine,
evaluating predicates over dicts via CPython) vs the Zig engine (typed structs via a comptime field accessor).

    python3 zig/bench/filter_bench.py

Methodology matches the Zig harness: WARMUP untimed dispatches, then TRIALS timed runs of ITERS dispatches,
reporting the minimum across trials. Fewer ITERS than Zig because each dispatch is far slower; us/op + Mrows/s
normalize, so the comparison is fair. See the Zig file for what each case isolates.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "python"))

import msgspec  # noqa: E402
from truenas_pyjsonrpc import JSONRPCProtocol, FilterableJSONRPCMethod  # noqa: E402
from truenas_pyfilter import tnfilter  # noqa: E402  (the C filter engine — the thing under test)


class QueryArgs(msgspec.Struct):
    pass


class Entry(msgspec.Struct):  # element type (codegen/openrpc only; the handler returns dicts)
    id: int
    name: str
    ratio: float
    active: bool
    note: str | None = None


N = 100_000
NAMES = ["alpha", "beta", "gamma", "delta"]


def build_data(n):
    # Byte-for-byte the same logical rows as filter_bench.zig's dataset.
    return [{"id": i, "name": NAMES[i % 4], "ratio": (i % 1000) * 0.5,
             "active": i % 2 == 0, "note": None if i % 3 == 0 else "note"} for i in range(n)]


_DATA = build_data(N)


def query(request, session_state, request_state, filters, options):
    # Push-down through the C engine over the full dataset (the realistic filterable handler).
    return tnfilter(_DATA, filters=filters, options=options)


PROTO = JSONRPCProtocol(
    [FilterableJSONRPCMethod("x.query", accepts=QueryArgs, entry=Entry, handler=query)],
    name="bench", version="1.0.0",
)

UID = "123e4567-e89b-12d3-a456-426614174000"


def fq(params):
    return '{"jsonrpc":"2.0","id":"%s","method":"x.query","params":%s}' % (UID, params)


# (name, params, full_scan) — full_scan cases scan all N with no output, so Mrows/s is the eval throughput.
CASES = [
    ("count_all", '{"query-filters":[],"query-options":{"count":true}}', True),
    ("count_eq", '{"query-filters":[["name","=","alpha"]],"query-options":{"count":true}}', True),
    ("filter_page", '{"query-filters":[["name","=","alpha"]],"query-options":{"limit":100}}', False),
    ("order_page", '{"query-filters":[],"query-options":{"order_by":["-id"],"limit":100}}', False),
]

WARMUP = 5
TRIALS = 5
ITERS = 30  # each dispatch scans/encodes far more than the trivial bench; keep wall-time sane (us/op normalizes).


def main():
    sess = PROTO.new_session()
    dispatch = PROTO.dispatch
    cases = [(name, fq(params).encode("utf-8"), full) for name, params, full in CASES]

    print(f"# python filter bench  truenas_pyfilter (C)  N={N}  iters={ITERS}  trials={TRIALS}  (min-of-trials)")
    print(f"{'case':<14}{'us/op':>12}{'Mrows/s':>12}{'reply':>9}")

    guard = 0
    for name, wire, full in cases:
        last = None
        for _ in range(WARMUP):
            last = dispatch(wire, sess)
        reply_len = 0 if last is None else len(last)

        best = float("inf")
        for _ in range(TRIALS):
            start = time.perf_counter_ns()
            for _ in range(ITERS):
                guard ^= 1 if dispatch(wire, sess) is None else 0
            elapsed = time.perf_counter_ns() - start
            if elapsed < best:
                best = elapsed
        ns_op = best / ITERS
        us_op = ns_op / 1000.0
        if full:
            mrows = N / ns_op * 1000.0  # rows/ns -> Mrows/s
            print(f"{name:<14}{us_op:>12.2f}{mrows:>12.1f}{reply_len:>9}")
        else:
            print(f"{name:<14}{us_op:>12.2f}{'-':>12}{reply_len:>9}")
    if guard < 0:
        print(guard)


if __name__ == "__main__":
    main()
