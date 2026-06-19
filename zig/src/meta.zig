//! `Secret(T)` — a wire-transparent wrapper that marks a field secret for audit redaction. On the wire
//! it encodes/decodes exactly as `T` (the real value flows), via custom `std.json` hooks; the audit view
//! masks it to `"********"` (see reflect.zig + the protocol audit path). The comptime redaction walk
//! finds it through the `__redact` decl. Mirrors Python `Annotated[T, SECRET]`.
const std = @import("std");

/// Wrap a field type to mark it secret: `password: trpc.Secret([]const u8)`. Transparent on the wire;
/// discovered for redaction via `@hasDecl(FieldType, "__redact")`.
pub fn Secret(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Marker read by the comptime redaction walk (reflect.zig).
        pub const __redact = true;

        /// The real value — flows on the wire; masked only in the audit view.
        value: T,

        /// Encode transparently as `T` (std passes the `*Stringify` as `jw`).
        pub fn jsonStringify(self: Self, jw: anytype) !void {
            try jw.write(self.value);
        }

        /// Decode transparently from a `std.json.Value` as `T` (our decode path is value-sourced).
        pub fn jsonParseFromValue(
            allocator: std.mem.Allocator,
            source: std.json.Value,
            options: std.json.ParseOptions,
        ) !Self {
            return .{ .value = try std.json.parseFromValueLeaky(T, allocator, source, options) };
        }
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;

test "Secret is wire-transparent: encodes the real value, no wrapper object" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    const Creds = struct { user: []const u8, password: Secret([]const u8) };
    const c = Creds{ .user = "bob", .password = .{ .value = "hunter2" } };

    const bytes = try std.json.Stringify.valueAlloc(arena, c, .{});
    // The real secret is on the wire; there is NO `"value"` wrapper key.
    try testing.expect(std.mem.indexOf(u8, bytes, "\"hunter2\"") != null);
    try testing.expect(std.mem.indexOf(u8, bytes, "value") == null);
}

test "Secret round-trips through parseFromValue back to the inner value" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    const Creds = struct { user: []const u8, password: Secret([]const u8) };
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"user\":\"bob\",\"password\":\"hunter2\"}", .{});
    const back = try std.json.parseFromValueLeaky(Creds, arena, v, .{});
    try testing.expectEqualStrings("bob", back.user);
    try testing.expectEqualStrings("hunter2", back.password.value);
}

test "Secret of an int is transparent too" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    const Holder = struct { pin: Secret(i64) };
    const bytes = try std.json.Stringify.valueAlloc(arena, Holder{ .pin = .{ .value = 4242 } }, .{});
    try testing.expect(std.mem.indexOf(u8, bytes, "4242") != null);
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
    const back = try std.json.parseFromValueLeaky(Holder, arena, v, .{});
    try testing.expectEqual(@as(i64, 4242), back.pin.value);
}
