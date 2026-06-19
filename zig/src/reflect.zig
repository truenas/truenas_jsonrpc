//! Comptime secret-field discovery + audit redaction. Given a type `T` and a `std.json.Value` that is
//! the JSON encoding of a `T`, `redactValue` returns it with every `Secret(_)` field replaced by
//! `"********"` (a `null` secret stays `null`), recursing structs / optionals / slices / arrays.
//! Mirrors Python `redaction.compile_plan` + `redact`: a plan compiled from the type, applied to the
//! encoded value. The input Value is freshly parsed from bytes the caller owns, so masking is in place.
//!
//! M1 scope: struct fields, optionals, slices/arrays, and `Secret(_)`. Maps (`std.json` object-typed
//! fields), tagged unions, and `rename`d wire names are deferred (none appear in the M1 method set).
const std = @import("std");

/// The mask substituted for a secret value in the audit view (byte-matches Python `redaction.REDACTED`).
pub const REDACTED = "********";

fn isSecret(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and @hasDecl(T, "__redact");
}

/// True if `T` carries a secret anywhere reachable — lets non-secret types skip the walk entirely
/// (the common, hot case: most methods have no secrets, so redaction compiles to a no-op).
pub fn hasSecrets(comptime T: type) bool {
    if (isSecret(T)) return true;
    return switch (@typeInfo(T)) {
        .@"struct" => |s| blk: {
            inline for (s.fields) |f| {
                if (hasSecrets(f.type)) break :blk true;
            }
            break :blk false;
        },
        .optional => |o| hasSecrets(o.child),
        .array => |a| hasSecrets(a.child),
        .pointer => |p| p.size == .slice and p.child != u8 and hasSecrets(p.child),
        else => false,
    };
}

/// Return `v` (the JSON encoding of a `T`) with secrets masked. Identity when `T` has no secrets.
pub fn redactValue(comptime T: type, v: std.json.Value) std.json.Value {
    if (comptime !hasSecrets(T)) return v;
    return redactNode(T, v);
}

fn redactNode(comptime T: type, v: std.json.Value) std.json.Value {
    if (comptime isSecret(T)) {
        return if (v == .null) v else .{ .string = REDACTED };
    }
    switch (@typeInfo(T)) {
        .@"struct" => |s| {
            if (v != .object) return v;
            inline for (s.fields) |f| {
                if (comptime hasSecrets(f.type)) {
                    if (v.object.getPtr(f.name)) |slot| slot.* = redactNode(f.type, slot.*);
                }
            }
            return v;
        },
        .optional => |o| return if (v == .null) v else redactNode(o.child, v),
        .array => |a| {
            if (v == .array) for (v.array.items) |*it| {
                it.* = redactNode(a.child, it.*);
            };
            return v;
        },
        .pointer => |p| {
            if (p.size == .slice and v == .array) for (v.array.items) |*it| {
                it.* = redactNode(p.child, it.*);
            };
            return v;
        },
        else => return v,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;
const Secret = @import("meta.zig").Secret;
const json_eq = @import("json_eq.zig");

fn parse(arena: std.mem.Allocator, s: []const u8) std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, arena, s, .{}) catch unreachable;
}

fn expectRedacts(comptime T: type, arena: std.mem.Allocator, input: []const u8, expected: []const u8) !void {
    const got = redactValue(T, parse(arena, input));
    try testing.expect(json_eq.eql(got, parse(arena, expected)));
}

test "hasSecrets: only types reachable from a Secret report true" {
    try testing.expect(!hasSecrets(struct { a: i64, b: []const u8 }));
    try testing.expect(hasSecrets(struct { a: i64, pw: Secret([]const u8) }));
    try testing.expect(hasSecrets(struct { inner: struct { pw: Secret(i64) } }));
    try testing.expect(hasSecrets(struct { maybe: ?Secret([]const u8) }));
    try testing.expect(!hasSecrets(struct { names: []const []const u8 }));
}

test "redactValue masks a top-level Secret, leaves siblings" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const T = struct { user: []const u8, password: Secret([]const u8) };
    try expectRedacts(T, a.allocator(), "{\"user\":\"bob\",\"password\":\"hunter2\"}", "{\"user\":\"bob\",\"password\":\"********\"}");
}

test "redactValue recurses nested structs, optionals, and slices" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    // nested struct
    const Nested = struct { creds: struct { user: []const u8, pw: Secret([]const u8) } };
    try expectRedacts(Nested, arena, "{\"creds\":{\"user\":\"x\",\"pw\":\"s\"}}", "{\"creds\":{\"user\":\"x\",\"pw\":\"********\"}}");

    // optional present → masked; null → stays null
    const Opt = struct { token: ?Secret([]const u8) };
    try expectRedacts(Opt, arena, "{\"token\":\"abc\"}", "{\"token\":\"********\"}");
    try expectRedacts(Opt, arena, "{\"token\":null}", "{\"token\":null}");

    // slice of structs → each element masked
    const List = struct { items: []const struct { id: i64, key: Secret([]const u8) } };
    try expectRedacts(List, arena, "{\"items\":[{\"id\":1,\"key\":\"a\"},{\"id\":2,\"key\":\"b\"}]}", "{\"items\":[{\"id\":1,\"key\":\"********\"},{\"id\":2,\"key\":\"********\"}]}");
}

test "redactValue is identity for a secret-free type" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const T = struct { a: i64, b: []const u8 };
    try expectRedacts(T, a.allocator(), "{\"a\":1,\"b\":\"x\"}", "{\"a\":1,\"b\":\"x\"}");
}
