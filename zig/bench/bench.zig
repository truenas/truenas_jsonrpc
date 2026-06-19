//! Synchronous-dispatch microbenchmark for the Zig engine — a *consumer* of the public library
//! (`@import("truenas_jsonrpc")`), mirroring `bench/bench.py` exactly: the same wire corpus, equivalent
//! trivial handlers, one long-lived session, and the same bytes-in → reply-bytes-out operation. The two
//! programs therefore measure the same thing, so their ns/op are directly comparable.
//!
//! Build & run optimized (Debug numbers are meaningless):
//!     zig build bench -Doptimize=ReleaseFast
//!
//! Methodology: per case, `WARMUP` untimed dispatches, then `TRIALS` timed runs of `ITERS` dispatches;
//! we report the *minimum* ns/op across trials (steady state, least scheduler/allocator noise). The
//! reply bytes are freed each iteration (the caller owns them — a real cost), and their length is summed
//! into a guard the optimizer cannot elide.
const std = @import("std");
const builtin = @import("builtin");
const trpc = @import("truenas_jsonrpc");

const Ctx = trpc.RequestCtx(void);

// Method types — identical shapes to the Python bench's msgspec.Structs.
const PoolCreateArgs = struct { name: []const u8 };
const PoolCreateResult = struct { id: u32, name: []const u8 };
const AddArgs = struct { a: i64, b: i64 };
const AddResult = struct { sum: i64 };

const Api = struct {
    fn create(_: *Api, args: PoolCreateArgs, _: *Ctx) !PoolCreateResult {
        return .{ .id = 7, .name = args.name };
    }
    fn add(_: *Api, args: AddArgs, _: *Ctx) !AddResult {
        return .{ .sum = args.a + args.b };
    }
};

const Case = struct { name: []const u8, wire: []const u8 };

const uid = "123e4567-e89b-12d3-a456-426614174000";

// Hand-assembled XDR request frames for the SAME add/create methods over the binary wire. The bench is a
// consumer and the internal frame builder isn't exported, so the fixed frames are spelled out as hex. They
// have NO Python mirror — they isolate the binary-wire speedup WITHIN the Zig engine (XDR vs JSON dispatch
// of the identical method: no text parse, no Value tree, ~no allocation). Frame layout:
//   magic 'TXDR'(54584452) · version(1) · proc_id · id{flag(1) + 16 bytes} · XDR<params>
const xdr_uid_hex = "123e4567e89b12d3a456426614174000";
fn hexBytes(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
// add over XDR (proc 1001): AddArgs{a:i64=2, b:i64=3} → two 8-byte hypers.
const add_xdr = hexBytes("54584452" ++ "00000001" ++ "000003e9" ++ "00000001" ++ xdr_uid_hex ++ "0000000000000002" ++ "0000000000000003");
// create over XDR (proc 1002): PoolCreateArgs{name:"tank"} → string<> (u32 len 4 + 'tank', already aligned).
const create_xdr = hexBytes("54584452" ++ "00000001" ++ "000003ea" ++ "00000001" ++ xdr_uid_hex ++ "00000004" ++ "74616e6b");

const CASES = [_]Case{
    // The bread-and-butter request: parse + decode 2 ints + run + encode 1 int + serialize.
    .{ .name = "add", .wire = "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"add\",\"params\":{\"a\":2,\"b\":3}}" },
    // Decode 1 string, encode a 2-field object.
    .{ .name = "create", .wire = "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"pool.create\",\"params\":{\"name\":\"tank\"}}" },
    // Error path with no decode (lookup miss) — cheapest request that still serializes a reply.
    .{ .name = "method_not_found", .wire = "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"nope\"}" },
    // Decode-failure path: by-name only, so array params → invalid_params.
    .{ .name = "invalid_params", .wire = "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"add\",\"params\":[2,3]}" },
    // Decode + run, but NO response encode/serialize (isolates the reply-building cost).
    .{ .name = "notification", .wire = "{\"jsonrpc\":\"2.0\",\"method\":\"add\",\"params\":{\"a\":2,\"b\":3}}" },
    // Earliest exit: malformed JSON → invalid_json.
    .{ .name = "parse_error", .wire = "{not json" },
    // The SAME add/create methods over the XDR binary wire — compare directly against `add`/`create` above.
    .{ .name = "add_xdr", .wire = &add_xdr },
    .{ .name = "create_xdr", .wire = &create_xdr },
};

const WARMUP: u64 = 50_000;
const TRIALS: u32 = 7;
const ITERS: u64 = 1_000_000;

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
        // The bench corpus is all client_server request methods; a subscribe directive never occurs here,
        // but the arm keeps the switch exhaustive (and frees the ack + sub_id if one ever did).
        .subscribe => |s| {
            const n = s.reply.len;
            reply_alloc.free(s.reply);
            reply_alloc.free(s.sub_id);
            return n;
        },
        // The bench corpus dispatches no transfer methods; the arm keeps the switch exhaustive.
        .transfer => |t| {
            reply_alloc.free(t.ready);
            return t.ready.len;
        },
    }
}

pub fn main() !void {
    const gpa = std.heap.smp_allocator;

    var api = Api{};
    var b = trpc.Protocol(void).builder(gpa, "bench", "1.0.0");
    // Dual-wire: each method answers JSON and (via .xdr/.xdr_id, proc >= 1001) the binary wire.
    try b.method("add", &api, Api.add, .{ .xdr = true, .xdr_id = 1001 });
    try b.method("pool.create", &api, Api.create, .{ .xdr = true, .xdr_id = 1002 });
    var proto = b.build();
    defer proto.deinit();

    // One long-lived session, reused across every dispatch (the realistic server scenario).
    var sess = proto.newSession(null);

    std.debug.print("# zig dispatch bench  mode={s}  iters={d}  trials={d}  (min-of-trials ns/op)\n", .{ @tagName(builtin.mode), ITERS, TRIALS });
    if (builtin.mode == .Debug)
        std.debug.print("!! WARNING: Debug build — rebuild with -Doptimize=ReleaseFast for meaningful numbers\n", .{});
    std.debug.print("{s:<18}{s:>12}{s:>16}{s:>9}\n", .{ "case", "ns/op", "ops/s", "reply" });

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
        const ops = 1e9 / ns_op;
        std.debug.print("{s:<18}{d:>12.1}{d:>16.0}{d:>9}\n", .{ case.name, ns_op, ops, reply_len });
    }
    std.mem.doNotOptimizeAway(guard);
}
