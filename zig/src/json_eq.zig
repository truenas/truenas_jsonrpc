//! Structural JSON equality — test-support only; the dispatch runtime never uses it. Exposed publicly
//! as `trpc.testing.jsonEql` for consumers writing conformance / A-B tests, and used by the library's
//! own unit tests plus the consumer conformance suite under `zig/conformance/`.
//!
//! Order-insensitive comparison of two `std.json.Value` trees, so semantically-equal JSON with different
//! object-key order (msgspec declaration order vs our encode order) still matches; impl-specific subtrees
//! (e.g. `error.data`) can be normalized before comparing. Integer/float forms compare equal when value-equal.
const std = @import("std");
const Value = std.json.Value;

pub fn eql(a: Value, b: Value) bool {
    return switch (a) {
        .null => b == .null,
        .bool => |x| b == .bool and x == b.bool,
        .integer => |x| switch (b) {
            .integer => |y| x == y,
            .float => |y| @as(f64, @floatFromInt(x)) == y,
            else => false,
        },
        .float => |x| switch (b) {
            .float => |y| x == y,
            .integer => |y| x == @as(f64, @floatFromInt(y)),
            else => false,
        },
        .number_string => |x| b == .number_string and std.mem.eql(u8, x, b.number_string),
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        .array => |x| eqlArray(x, b),
        .object => |x| eqlObject(x, b),
    };
}

fn eqlArray(x: std.json.Array, b: Value) bool {
    if (b != .array) return false;
    if (x.items.len != b.array.items.len) return false;
    for (x.items, b.array.items) |ia, ib| {
        if (!eql(ia, ib)) return false;
    }
    return true;
}

fn eqlObject(x: std.json.ObjectMap, b: Value) bool {
    if (b != .object) return false;
    if (x.count() != b.object.count()) return false;
    var it = x.iterator();
    while (it.next()) |entry| {
        const bv = b.object.get(entry.key_ptr.*) orelse return false;
        if (!eql(entry.value_ptr.*, bv)) return false;
    }
    return true;
}

const testing = std.testing;

fn parse(arena: std.mem.Allocator, s: []const u8) Value {
    return std.json.parseFromSliceLeaky(Value, arena, s, .{}) catch unreachable;
}

test "scalars, equal" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    try testing.expect(eql(parse(al, "true"), parse(al, "true")));
    try testing.expect(eql(parse(al, "7"), parse(al, "7")));
    try testing.expect(eql(parse(al, "\"hi\""), parse(al, "\"hi\"")));
    try testing.expect(eql(parse(al, "null"), parse(al, "null")));
}

test "scalars, unequal and mismatched tags" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    try testing.expect(!eql(parse(al, "7"), parse(al, "8")));
    try testing.expect(!eql(parse(al, "true"), parse(al, "false")));
    try testing.expect(!eql(parse(al, "\"a\""), parse(al, "1")));
}

test "objects compared order-insensitively" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    const x = parse(al, "{\"jsonrpc\":\"2.0\",\"id\":\"u\",\"result\":{\"id\":7,\"name\":\"tank\"}}");
    const y = parse(al, "{\"result\":{\"name\":\"tank\",\"id\":7},\"id\":\"u\",\"jsonrpc\":\"2.0\"}");
    try testing.expect(eql(x, y));
    const z = parse(al, "{\"jsonrpc\":\"2.0\",\"id\":\"u\",\"result\":{\"id\":8,\"name\":\"tank\"}}");
    try testing.expect(!eql(x, z));
}

test "arrays are order-sensitive; differing length unequal" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    try testing.expect(eql(parse(al, "[1,2,3]"), parse(al, "[1,2,3]")));
    try testing.expect(!eql(parse(al, "[1,2,3]"), parse(al, "[3,2,1]")));
    try testing.expect(!eql(parse(al, "[1,2]"), parse(al, "[1,2,3]")));
}

test "missing/extra object keys are unequal" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    try testing.expect(!eql(parse(al, "{\"a\":1}"), parse(al, "{\"a\":1,\"b\":2}")));
    try testing.expect(!eql(parse(al, "{\"a\":1,\"b\":2}"), parse(al, "{\"a\":1,\"c\":2}")));
}
