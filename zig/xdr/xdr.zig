//! Canonical XDR (RFC 4506) codec — comptime reflective encode/decode over any supported Zig type, byte-for-
//! byte identical to FreeBSD `sys/xdr` (and pynfs `xdrlib3`). Generic + dependency-free: the truenas_jsonrpc
//! library imports it for the binary wire, and it is independently tested here against the C reference's
//! canonical bytes (see the golden vectors below — incl. the 20-byte `sctrl` union case the FreeBSD source
//! emits verbatim).
//!
//! Wire encoding (all big-endian; verified vs `xdr.c`/`xdr_array.c`/`xdr_reference.c`):
//!   int ≤32 bits / enum / bool → one 4-byte word (shorts/chars widen to 4; bool 0/1; enum as i32)
//!   int 33..64 bits (hyper)    → 8 bytes, big-endian (high 32-bit word first)
//!   f32 / f64                  → @bitCast to u32/u64, big-endian (f64 high word first)
//!   []const u8                 → u32 length + bytes + 0-pad to 4 (opaque/string<>; carries any bytes)
//!   []T  (T != u8)             → u32 count + each element
//!   [N]u8 / [N]T (fixed)       → bytes+pad / N elements, NO count
//!   ?T (optional)              → u32 0 (absent) | 1 (present) + value   (= xdr_pointer's bool discriminant)
//!   struct                     → fields concatenated in declaration order, NO inter-field padding
//!   union(enum)                → i32 tag (@intFromEnum) + the active arm (a `void` arm emits nothing)
//!   void                       → nothing
//! A type may override the codec by declaring `pub fn xdrEncode(self, *std.Io.Writer) !void` +
//! `pub fn xdrDecode(std.mem.Allocator, *std.Io.Reader) !Self` (used for wire-transparent wrappers like
//! `Secret(T)`), mirroring the JSON `jsonStringify`/`jsonParse` hooks.
const std = @import("std");

const W = std.Io.Writer;
const R = std.Io.Reader;

fn pad4(n: usize) usize {
    return (4 - n % 4) % 4;
}

/// Encode `value` to `w` as canonical XDR.
pub fn encode(w: *W, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .void => {},
        .int => |info| {
            if (info.bits <= 32) {
                if (info.signedness == .signed) try w.writeInt(i32, @intCast(value), .big) else try w.writeInt(u32, @intCast(value), .big);
            } else {
                if (info.signedness == .signed) try w.writeInt(i64, @intCast(value), .big) else try w.writeInt(u64, @intCast(value), .big);
            }
        },
        .bool => try w.writeInt(u32, @intFromBool(value), .big),
        .float => |fl| if (fl.bits == 32) try w.writeInt(u32, @bitCast(value), .big) else try w.writeInt(u64, @bitCast(value), .big),
        .@"enum" => try w.writeInt(i32, @intCast(@intFromEnum(value)), .big),
        .optional => |o| {
            if (value) |v| {
                try w.writeInt(u32, 1, .big);
                try encode(w, v);
            } else {
                try w.writeInt(u32, 0, .big);
            }
            _ = o;
        },
        .@"struct" => |s| {
            if (@hasDecl(T, "xdrEncode")) return value.xdrEncode(w);
            inline for (s.fields) |f| try encode(w, @field(value, f.name));
        },
        .@"union" => |u| {
            if (u.tag_type == null) @compileError("XDR union must be tagged: " ++ @typeName(T));
            try w.writeInt(i32, @intCast(@intFromEnum(std.meta.activeTag(value))), .big);
            switch (value) {
                inline else => |payload| try encode(w, payload),
            }
        },
        .pointer => |p| {
            if (p.size != .slice) @compileError("XDR: only slices supported, got " ++ @typeName(T));
            try w.writeInt(u32, @intCast(value.len), .big);
            if (p.child == u8) {
                try w.writeAll(value);
                try w.splatByteAll(0, pad4(value.len));
            } else {
                for (value) |elem| try encode(w, elem);
            }
        },
        .array => |a| {
            if (a.child == u8) {
                try w.writeAll(&value);
                try w.splatByteAll(0, pad4(a.len));
            } else {
                for (value) |elem| try encode(w, elem);
            }
        },
        else => @compileError("XDR: unsupported type " ++ @typeName(T)),
    }
}

fn readU32(r: *R) !u32 {
    return std.mem.readInt(u32, try r.takeArray(4), .big);
}
fn readU64(r: *R) !u64 {
    return std.mem.readInt(u64, try r.takeArray(8), .big);
}
fn skipPad(r: *R, n: usize) !void {
    const p = pad4(n);
    if (p > 0) _ = try r.take(p);
}

/// Decode a value of type `T` from `r`. `gpa` allocates variable-length `[]T` (a `[]const u8` aliases the
/// reader's buffer — zero-copy — so the buffer must outlive the result). Precondition: the bytes are a
/// canonical XDR encoding of `T` (a well-formed frame); malformed enum/union tags are not yet range-checked.
pub fn decode(comptime T: type, gpa: std.mem.Allocator, r: *R) !T {
    switch (@typeInfo(T)) {
        .void => return {},
        .int => |info| {
            if (info.bits <= 32) {
                const raw = try readU32(r);
                return if (info.signedness == .signed)
                    (std.math.cast(T, @as(i32, @bitCast(raw))) orelse error.XdrRange)
                else
                    (std.math.cast(T, raw) orelse error.XdrRange);
            } else {
                const raw = try readU64(r);
                return if (info.signedness == .signed)
                    (std.math.cast(T, @as(i64, @bitCast(raw))) orelse error.XdrRange)
                else
                    (std.math.cast(T, raw) orelse error.XdrRange);
            }
        },
        .bool => return (try readU32(r)) != 0,
        .float => |fl| return if (fl.bits == 32) @as(f32, @bitCast(try readU32(r))) else @as(f64, @bitCast(try readU64(r))),
        .@"enum" => return @enumFromInt(@as(i32, @bitCast(try readU32(r)))),
        .optional => |o| {
            return if ((try readU32(r)) != 0) try decode(o.child, gpa, r) else null;
        },
        .@"struct" => |s| {
            if (@hasDecl(T, "xdrDecode")) return T.xdrDecode(gpa, r);
            var v: T = undefined;
            inline for (s.fields) |f| @field(v, f.name) = try decode(f.type, gpa, r);
            return v;
        },
        .@"union" => |u| {
            const Tag = u.tag_type.?;
            const tag: Tag = @enumFromInt(@as(i32, @bitCast(try readU32(r))));
            switch (tag) {
                inline else => |t| {
                    const name = @tagName(t);
                    return @unionInit(T, name, try decode(@FieldType(T, name), gpa, r));
                },
            }
        },
        .pointer => |p| {
            if (p.size != .slice) @compileError("XDR: only slices supported, got " ++ @typeName(T));
            const count = try readU32(r);
            if (p.child == u8) {
                const bytes = try r.take(count);
                try skipPad(r, count);
                return bytes;
            } else {
                const out = try gpa.alloc(p.child, count);
                for (out) |*slot| slot.* = try decode(p.child, gpa, r);
                return out;
            }
        },
        .array => |a| {
            var out: T = undefined;
            if (a.child == u8) {
                @memcpy(&out, try r.take(a.len));
                try skipPad(r, a.len);
            } else {
                for (&out) |*slot| slot.* = try decode(a.child, gpa, r);
            }
            return out;
        },
        else => @compileError("XDR: unsupported type " ++ @typeName(T)),
    }
}

/// Encode `value` to a fresh arena-owned byte slice (the dispatch-path convenience).
pub fn encodeAlloc(gpa: std.mem.Allocator, value: anytype) ![]u8 {
    var aw: W.Allocating = .init(gpa);
    try encode(&aw.writer, value);
    return aw.writer.buffered();
}

/// Comptime predicate: is `T` XDR-encodable by this codec? Lets a generic registration (`Method.define`)
/// generate real XDR thunks only for compatible types and stub the rest — so a JSON-only method carrying a
/// non-XDR type (e.g. a dynamic `std.json.Value`) still compiles. Mirrors the `encode`/`decode` switch.
pub fn compatible(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .void, .bool, .int, .float, .@"enum" => true,
        .optional => |o| compatible(o.child),
        .@"struct" => |s| blk: {
            if (@hasDecl(T, "xdrEncode")) break :blk true;
            for (s.fields) |f| {
                if (!compatible(f.type)) break :blk false;
            }
            break :blk true;
        },
        .@"union" => |u| blk: {
            if (u.tag_type == null) break :blk false;
            for (u.fields) |f| {
                if (!compatible(f.type)) break :blk false;
            }
            break :blk true;
        },
        .pointer => |p| p.size == .slice and compatible(p.child),
        .array => |a| compatible(a.child),
        else => false,
    };
}

// ── Tests: golden vectors vs FreeBSD `sys/xdr` canonical bytes ─────────────────────
const testing = std.testing;

/// Encode into a stack buffer and assert the exact bytes.
fn expectBytes(value: anytype, expected: []const u8) !void {
    var buf: [256]u8 = undefined;
    var w = W.fixed(&buf);
    try encode(&w, value);
    try testing.expectEqualSlices(u8, expected, w.buffered());
}

const Dir = enum(i32) { none = 0, call = 1, reply = 2, both = 3 };
const GrabArg = struct { number: i32, dir: Dir, stamp: []const u8 };
const CtrlOp = enum(i32) { reset = 0, record = 1, pause = 2, grab = 4 }; // grab=4, mirrors sctrl.x
const CtrlArg = union(CtrlOp) { reset: void, record: i32, pause: void, grab: GrabArg };

test "scalars: int/bool/enum/hyper/float widths + big-endian" {
    try expectBytes(@as(i32, 5), &.{ 0, 0, 0, 5 });
    try expectBytes(@as(u32, 0x04030201), &.{ 4, 3, 2, 1 });
    try expectBytes(@as(i32, -1), &.{ 0xff, 0xff, 0xff, 0xff });
    try expectBytes(@as(i16, -1), &.{ 0xff, 0xff, 0xff, 0xff }); // short widens to 4, sign-extended
    try expectBytes(true, &.{ 0, 0, 0, 1 });
    try expectBytes(false, &.{ 0, 0, 0, 0 });
    try expectBytes(Dir.both, &.{ 0, 0, 0, 3 });
    try expectBytes(@as(u64, 1), &.{ 0, 0, 0, 0, 0, 0, 0, 1 }); // hyper: 8 bytes, high word first
    try expectBytes(@as(f64, 1.5), &.{ 0x3f, 0xf8, 0, 0, 0, 0, 0, 0 }); // IEEE-754 1.5 big-endian
}

test "opaque/string: u32 len + bytes + 0-pad to 4; empty = just the count word" {
    try expectBytes(@as([]const u8, "hi"), &.{ 0, 0, 0, 2, 'h', 'i', 0, 0 });
    try expectBytes(@as([]const u8, "abcd"), &.{ 0, 0, 0, 4, 'a', 'b', 'c', 'd' }); // no pad on multiple-of-4
    try expectBytes(@as([]const u8, ""), &.{ 0, 0, 0, 0 });
}

test "optional: u32 0/1 + value" {
    try expectBytes(@as(?i32, null), &.{ 0, 0, 0, 0 });
    try expectBytes(@as(?i32, 5), &.{ 0, 0, 0, 1, 0, 0, 0, 5 });
}

test "array: variable = count + elements; fixed = elements, no count" {
    try expectBytes(@as([]const i32, &.{ 1, 2 }), &.{ 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2 });
    try expectBytes([_]i32{ 7, 8 }, &.{ 0, 0, 0, 7, 0, 0, 0, 8 }); // fixed [2]i32: no count
    try expectBytes([_]u8{ 'h', 'i' }, &.{ 'h', 'i', 0, 0 }); // fixed [2]u8: bytes + pad, no len
}

test "struct: fields concatenated, no inter-field padding" {
    const S = struct { a: i32, b: []const u8, c: bool };
    try expectBytes(S{ .a = 5, .b = "hi", .c = true }, &.{
        0, 0, 0, 5, // a
        0, 0, 0, 2, 'h', 'i', 0, 0, // b
        0, 0, 0, 1, // c
    });
}

test "union: i32 discriminant + arm — reproduces the FreeBSD sctrl 20-byte golden" {
    // From the FreeBSD sys/xdr reference: CTRLarg{grab} GRABarg{number=5, dir=both(3), stamp="hi"} =
    // 00000004 00000005 00000003 00000002 6869 0000  (20 bytes).
    try expectBytes(CtrlArg{ .grab = .{ .number = 5, .dir = .both, .stamp = "hi" } }, &.{
        0, 0, 0, 4, // discriminant CTRL_GRAB
        0, 0, 0, 5, // number
        0, 0, 0, 3, // dir = both
        0, 0, 0, 2, 'h', 'i', 0, 0, // stamp
    });
    try expectBytes(CtrlArg{ .reset = {} }, &.{ 0, 0, 0, 0 }); // void arm: just the discriminant
}

test "round-trip: decode(encode(x)) == x" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const S = struct { a: i32, b: []const u8, c: ?u64, d: []const i32, e: Dir };
    const original = S{ .a = -7, .b = "round trip", .c = 42, .d = &.{ 10, 20, 30 }, .e = .reply };

    const bytes = try encodeAlloc(arena, original);
    var r = R.fixed(bytes);
    const back = try decode(S, arena, &r);

    try testing.expectEqual(original.a, back.a);
    try testing.expectEqualStrings(original.b, back.b);
    try testing.expectEqual(original.c, back.c);
    try testing.expectEqualSlices(i32, original.d, back.d);
    try testing.expectEqual(original.e, back.e);

    // union round-trip
    const cv = CtrlArg{ .grab = .{ .number = 99, .dir = .call, .stamp = "x" } };
    const cb = try encodeAlloc(arena, cv);
    var cr = R.fixed(cb);
    const cback = try decode(CtrlArg, arena, &cr);
    try testing.expect(cback == .grab);
    try testing.expectEqual(@as(i32, 99), cback.grab.number);
    try testing.expectEqualStrings("x", cback.grab.stamp);
}
