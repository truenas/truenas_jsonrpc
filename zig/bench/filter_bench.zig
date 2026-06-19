//! Filtering A/B microbenchmark for the Zig engine — a *consumer* of the public library, mirroring
//! `bench/filter_bench.py` exactly: the same dataset (generated identically), the same `x.query` wires, one
//! long-lived session, bytes-in → reply-bytes-out. The two programs therefore measure the same thing, so the
//! numbers are directly comparable: the Zig filter engine (predicates evaluated on typed structs via a
//! comptime field accessor) vs Python's `tnfilter` (the truenas_pyfilter C engine over dicts).
//!
//! Build & run optimized (Debug numbers are meaningless):
//!     zig build filter-bench -Doptimize=ReleaseFast
//!
//! Cases isolate different parts of the path:
//!   count_all / count_eq  — a FULL SCAN with no output (count mode returns a bare int), so `Mrows/s` is the
//!                           pure predicate-evaluation throughput over N rows.
//!   filter_page           — filter + `limit`: the streaming sink STOPS EARLY once the page is full, so this
//!                           is a per-query latency (it scans only until 100 matches, not all N).
//!   order_page            — `order_by` + `limit`: buffers the matched set, stable-sorts it, returns a window
//!                           (the buffered, non-streaming path).
const std = @import("std");
const builtin = @import("builtin");
const trpc = @import("truenas_jsonrpc");

const Ctx = trpc.RequestCtx(void);
const QueryArgs = struct {};
const Entry = struct { id: i64, name: []const u8, ratio: f64, active: bool, note: ?[]const u8 };

const NAMES = [_][]const u8{ "alpha", "beta", "gamma", "delta" };

const Api = struct {
    data: []const Entry,
    // The streaming push-down handler: emit each record; the sink tests-then-serializes only matches, and
    // `wantMore()` lets a `limit`ed query stop scanning early.
    fn query(self: *Api, _: QueryArgs, _: *Ctx, sink: *trpc.FilterSink(Entry)) !void {
        for (self.data) |e| {
            if (!sink.wantMore()) break;
            try sink.emit(e);
        }
    }
};

const N: u64 = 100_000;

const Case = struct { name: []const u8, wire: []const u8, full_scan: bool };
const uid = "123e4567-e89b-12d3-a456-426614174000";
fn fq(comptime params: []const u8) []const u8 {
    return "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"x.query\",\"params\":" ++ params ++ "}";
}
const CASES = [_]Case{
    // Pure iteration: match-all + count → scan N, no predicate branch beyond the empty AND, no output.
    .{ .name = "count_all", .wire = fq("{\"query-filters\":[],\"query-options\":{\"count\":true}}"), .full_scan = true },
    // Predicate evaluation: one `=` over N rows (matches 25%), count → no output. The headline filter number.
    .{ .name = "count_eq", .wire = fq("{\"query-filters\":[[\"name\",\"=\",\"alpha\"]],\"query-options\":{\"count\":true}}"), .full_scan = true },
    // Realistic page: filter + limit 100 → the streaming sink stops early (≈400 rows scanned, not N).
    .{ .name = "filter_page", .wire = fq("{\"query-filters\":[[\"name\",\"=\",\"alpha\"]],\"query-options\":{\"limit\":100}}"), .full_scan = false },
    // Sort + page: order_by -id, limit 100 → buffer all matches, stable-sort, window.
    .{ .name = "order_page", .wire = fq("{\"query-filters\":[],\"query-options\":{\"order_by\":[\"-id\"],\"limit\":100}}"), .full_scan = false },
};

const WARMUP: u64 = 10;
const TRIALS: u32 = 5;
const ITERS: u64 = 100;

inline fn nanoNow() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Free the reply (the caller owns it) and return its length, so the dispatch can't be optimized away.
inline fn consume(d: trpc.Dispatched, reply_alloc: std.mem.Allocator) u64 {
    switch (d) {
        .reply => |bytes| {
            const n = bytes.len;
            reply_alloc.free(bytes);
            return n;
        },
        .none => return 0,
        .subscribe => |s| {
            const n = s.reply.len;
            reply_alloc.free(s.reply);
            reply_alloc.free(s.sub_id);
            return n;
        },
    }
}

pub fn main() !void {
    const gpa = std.heap.smp_allocator;

    // Build the dataset once (not timed) — byte-for-byte the same logical rows as filter_bench.py's.
    const data = try gpa.alloc(Entry, N);
    defer gpa.free(data);
    for (data, 0..) |*e, i| {
        e.* = .{
            .id = @intCast(i),
            .name = NAMES[i % 4],
            .ratio = @as(f64, @floatFromInt(i % 1000)) * 0.5,
            .active = (i % 2 == 0),
            .note = if (i % 3 == 0) null else "note",
        };
    }

    var api = Api{ .data = data };
    var b = trpc.Protocol(void).builder(gpa, "bench", "1.0.0");
    try b.filterableMethod("x.query", &api, Api.query, Entry, .{});
    var proto = b.build();
    defer proto.deinit();
    var sess = proto.newSession(null);

    std.debug.print("# zig filter bench  mode={s}  N={d}  iters={d}  trials={d}  (min-of-trials)\n", .{ @tagName(builtin.mode), N, ITERS, TRIALS });
    if (builtin.mode == .Debug)
        std.debug.print("!! WARNING: Debug build — rebuild with -Doptimize=ReleaseFast for meaningful numbers\n", .{});
    std.debug.print("{s:<14}{s:>12}{s:>12}{s:>9}\n", .{ "case", "us/op", "Mrows/s", "reply" });

    var guard: u64 = 0;
    for (CASES) |case| {
        var w: u64 = 0;
        var reply_len: u64 = 0;
        while (w < WARMUP) : (w += 1) reply_len = consume(proto.dispatch(gpa, case.wire, &sess), gpa);

        var best: u64 = std.math.maxInt(u64);
        var t: u32 = 0;
        while (t < TRIALS) : (t += 1) {
            const start = nanoNow();
            var i: u64 = 0;
            var sink: u64 = 0;
            while (i < ITERS) : (i += 1) sink +%= consume(proto.dispatch(gpa, case.wire, &sess), gpa);
            const elapsed = nanoNow() - start;
            guard +%= sink;
            if (elapsed < best) best = elapsed;
        }
        const ns_op = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(ITERS));
        const us_op = ns_op / 1000.0;
        if (case.full_scan) {
            const mrows = @as(f64, @floatFromInt(N)) / ns_op * 1000.0; // rows/ns → Mrows/s
            std.debug.print("{s:<14}{d:>12.2}{d:>12.1}{d:>9}\n", .{ case.name, us_op, mrows, reply_len });
        } else {
            std.debug.print("{s:<14}{d:>12.2}{s:>12}{d:>9}\n", .{ case.name, us_op, "-", reply_len });
        }
    }
    std.mem.doNotOptimizeAway(guard);
}
