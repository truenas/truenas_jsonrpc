#!/usr/bin/env python3
"""Synchronous-dispatch microbenchmark for the Python reference (`truenas_pyjsonrpc`) — the mirror of
`bench/bench.zig`: the same wire corpus, equivalent trivial handlers, one long-lived session, and the
same bytes-in -> reply-bytes-out operation, so the two programs' ns/op are directly comparable.

    python3 zig/bench/bench.py

Methodology matches the Zig harness: per case, WARMUP untimed dispatches, then TRIALS timed runs of
ITERS dispatches, reporting the *minimum* ns/op across trials (steady state, least noise). Fewer ITERS
than the Zig side because each Python dispatch is far slower; ns/op is normalized so this is fair.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "python"))

import msgspec  # noqa: E402
from truenas_pyjsonrpc import JSONRPCProtocol, JSONRPCMethod  # noqa: E402


# Method types — identical shapes to the Zig bench's structs.
class PoolCreateArgs(msgspec.Struct):
    name: str


class PoolCreateResult(msgspec.Struct):
    id: int
    name: str


class AddArgs(msgspec.Struct):
    a: int
    b: int


class AddResult(msgspec.Struct):
    sum: int


def pool_create(request, session_state, request_state):
    return PoolCreateResult(id=7, name=request.name)


def add(request, session_state, request_state):
    return AddResult(sum=request.a + request.b)


PROTO = JSONRPCProtocol(
    [
        JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add),
        JSONRPCMethod("pool.create", accepts=PoolCreateArgs, returns=PoolCreateResult, handler=pool_create),
    ],
    name="bench",
    version="1.0.0",
)

UID = "123e4567-e89b-12d3-a456-426614174000"
CASES = [
    ("add", '{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":2,"b":3}}' % UID),
    ("create", '{"jsonrpc":"2.0","id":"%s","method":"pool.create","params":{"name":"tank"}}' % UID),
    ("method_not_found", '{"jsonrpc":"2.0","id":"%s","method":"nope"}' % UID),
    ("invalid_params", '{"jsonrpc":"2.0","id":"%s","method":"add","params":[2,3]}' % UID),
    ("notification", '{"jsonrpc":"2.0","method":"add","params":{"a":2,"b":3}}'),
    ("parse_error", "{not json"),
]

WARMUP = 50_000
TRIALS = 7
ITERS = 100_000  # Python dispatch is ~10-50x slower per op; fewer iters keeps wall-time sane (ns/op normalizes).


def main():
    sess = PROTO.new_session()
    dispatch = PROTO.dispatch
    # Feed pre-encoded bytes (mirrors Zig's []const u8 input — no per-iteration str.encode()).
    cases = [(name, wire.encode("utf-8")) for name, wire in CASES]

    print(f"# python dispatch bench  msgspec={msgspec.__version__}  iters={ITERS}  trials={TRIALS}  (min-of-trials ns/op)")
    print(f"{'case':<18}{'ns/op':>12}{'ops/s':>16}{'reply':>9}")

    guard = 0
    for name, wire in cases:
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
        ops = 1e9 / ns_op
        print(f"{name:<18}{ns_op:>12.1f}{ops:>16.0f}{reply_len:>9}")
    # keep `guard` observable
    if guard < 0:
        print(guard)


if __name__ == "__main__":
    main()
