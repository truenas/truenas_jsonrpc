//! Permissive JSON-RPC envelope handling — dispatch stages 1–3 (parse → id resolution → structural
//! checks) plus the success/error response builders. Mirrors Python `protocol.py` (`_dispatch_one`
//! parse stages, `_is_uuid`, `_error_envelope`). Stage 1–3 errors are NEVER suppressed, even for a
//! message with no id.
const std = @import("std");
const errors = @import("errors.zig");

/// `str(uuid.UUID(v)) == v.lower()`: canonical 8-4-4-4-12 hex with hyphens at fixed positions,
/// case-insensitive. Accepts uppercase (echoed verbatim); rejects URN/braced/integer forms.
pub fn isUuid(v: []const u8) bool {
    if (v.len != 36) return false;
    for (v, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (c != '-') return false;
        } else if (!std.ascii.isHex(c)) {
            return false;
        }
    }
    return true;
}

/// Validated envelope fields (stages 1–3 passed). `params` defaults to an empty object when absent
/// (Python's `_EMPTY`), so a no-arg method decodes against `{}`.
pub const Fields = struct {
    rid: ?[]const u8,
    has_id: bool,
    method: []const u8,
    params: std.json.Value,
};

/// An early (stage 1–3) error to emit verbatim. `rid` is the id to echo (null when unresolved).
pub const Fail = struct {
    code: errors.ErrorCode,
    rid: ?[]const u8,
    message: []const u8,
};

pub const Outcome = union(enum) {
    fields: Fields,
    fail: Fail,
};

inline fn failure(code: errors.ErrorCode, rid: ?[]const u8, message: []const u8) Outcome {
    return .{ .fail = .{ .code = code, .rid = rid, .message = message } };
}

/// Dispatch stages 1–3: JSON parse, id (UUID-only) resolution, structural checks
/// (`jsonrpc == "2.0"`, non-empty string `method`).
pub fn parse(arena: std.mem.Allocator, wire: []const u8) Outcome {
    // Stage 1 — parse. Malformed → INVALID_JSON; valid non-object (incl. top-level array) → INVALID_REQUEST.
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, wire, .{}) catch
        return failure(.invalid_json, null, errors.msg.parse_error);
    const obj = switch (root) {
        .object => |o| o,
        else => return failure(.invalid_request, null, errors.msg.invalid_request),
    };

    // Stage 2 — id. A present id must be a canonical UUID string; otherwise INVALID_REQUEST with
    // id echoed as null. An absent id (key not present) is a notification.
    var rid: ?[]const u8 = null;
    var has_id = false;
    if (obj.get("id")) |idv| {
        if (idv != .string or !isUuid(idv.string))
            return failure(.invalid_request, null, errors.msg.invalid_request);
        rid = idv.string;
        has_id = true;
    }

    // Stage 3 — structural. Errors here echo the resolved id and are never suppressed for notifications.
    const jv = obj.get("jsonrpc") orelse return failure(.invalid_request, rid, errors.msg.invalid_request);
    if (jv != .string or !std.mem.eql(u8, jv.string, "2.0"))
        return failure(.invalid_request, rid, errors.msg.invalid_request);

    const mv = obj.get("method") orelse return failure(.invalid_request, rid, errors.msg.invalid_request);
    if (mv != .string or mv.string.len == 0)
        return failure(.invalid_request, rid, errors.msg.invalid_request);

    const params = obj.get("params") orelse std.json.Value{ .object = .empty };
    return .{ .fields = .{ .rid = rid, .has_id = has_id, .method = mv.string, .params = params } };
}

fn idValue(rid: ?[]const u8) std.json.Value {
    return if (rid) |r| .{ .string = r } else .null;
}

/// `{"jsonrpc":"2.0","result":<result_json>,"id":<rid|null>}` — splices the already-serialized result
/// bytes in directly (no intermediate `Value` tree, no re-stringify; one allocation). Field order is
/// irrelevant — A/B compares structurally. `rid` is a validated UUID (no JSON escaping needed).
pub fn successBytesRaw(arena: std.mem.Allocator, rid: ?[]const u8, result_json: []const u8) ![]u8 {
    if (rid) |r|
        return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"result\":{s},\"id\":\"{s}\"}}", .{ result_json, r });
    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"result\":{s},\"id\":null}}", .{result_json});
}

/// `{"jsonrpc":"2.0","error":{"code":<int>,"message":<msg>[,"data":<data>]},"id":<rid|null>}`.
/// `data` is omitted when null (Python parity).
pub fn errorBytes(
    arena: std.mem.Allocator,
    rid: ?[]const u8,
    code: errors.ErrorCode,
    message: []const u8,
    data: ?std.json.Value,
) ![]u8 {
    var err_obj: std.json.ObjectMap = .empty;
    try err_obj.put(arena, "code", .{ .integer = @intFromEnum(code) });
    try err_obj.put(arena, "message", .{ .string = message });
    if (data) |d| try err_obj.put(arena, "data", d);
    var obj: std.json.ObjectMap = .empty;
    try obj.put(arena, "jsonrpc", .{ .string = "2.0" });
    try obj.put(arena, "error", .{ .object = err_obj });
    try obj.put(arena, "id", idValue(rid));
    return std.json.Stringify.valueAlloc(arena, std.json.Value{ .object = obj }, .{});
}

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;
const json_eq = @import("json_eq.zig");

test "isUuid: canonical accepted (incl. uppercase), variants rejected" {
    try testing.expect(isUuid("123e4567-e89b-12d3-a456-426614174000"));
    try testing.expect(isUuid("123E4567-E89B-12D3-A456-426614174000")); // uppercase ok
    try testing.expect(!isUuid("urn:uuid:123e4567-e89b-12d3-a456-426614174000"));
    try testing.expect(!isUuid("{123e4567-e89b-12d3-a456-426614174000}"));
    try testing.expect(!isUuid("123e4567e89b12d3a456426614174000")); // no hyphens
    try testing.expect(!isUuid("123e4567-e89b-12d3-a456-42661417400")); // too short
    try testing.expect(!isUuid("123e4567-e89b-12d3-a456-42661417400g")); // non-hex
    try testing.expect(!isUuid("abc"));
}

fn parseWire(arena: std.mem.Allocator, wire: []const u8) Outcome {
    return parse(arena, wire);
}

test "parse: happy request resolves fields" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    const out = parseWire(al, "{\"jsonrpc\":\"2.0\",\"id\":\"123e4567-e89b-12d3-a456-426614174000\",\"method\":\"pool.create\",\"params\":{\"name\":\"tank\"}}");
    try testing.expect(out == .fields);
    try testing.expect(out.fields.has_id);
    try testing.expectEqualStrings("pool.create", out.fields.method);
    try testing.expectEqualStrings("123e4567-e89b-12d3-a456-426614174000", out.fields.rid.?);
}

test "parse: notification (no id) → fields with has_id=false; absent params → {}" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    const out = parseWire(al, "{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}");
    try testing.expect(out == .fields);
    try testing.expect(!out.fields.has_id);
    try testing.expect(out.fields.rid == null);
    try testing.expect(out.fields.params == .object);
    try testing.expectEqual(@as(usize, 0), out.fields.params.object.count());
}

test "parse: stage-1/2/3 error branches" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();

    // malformed JSON → INVALID_JSON
    try testing.expectEqual(errors.ErrorCode.invalid_json, parseWire(al, "{not json").fail.code);
    // top-level array → INVALID_REQUEST
    try testing.expectEqual(errors.ErrorCode.invalid_request, parseWire(al, "[1,2,3]").fail.code);
    // id present but not a UUID → INVALID_REQUEST, id echoed null
    {
        const o = parseWire(al, "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"m\"}");
        try testing.expectEqual(errors.ErrorCode.invalid_request, o.fail.code);
        try testing.expect(o.fail.rid == null);
    }
    // id null → INVALID_REQUEST
    try testing.expectEqual(errors.ErrorCode.invalid_request, parseWire(al, "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"m\"}").fail.code);
    // bad version → INVALID_REQUEST, id echoed
    {
        const o = parseWire(al, "{\"jsonrpc\":\"1.0\",\"id\":\"123e4567-e89b-12d3-a456-426614174000\",\"method\":\"m\"}");
        try testing.expectEqual(errors.ErrorCode.invalid_request, o.fail.code);
        try testing.expectEqualStrings("123e4567-e89b-12d3-a456-426614174000", o.fail.rid.?);
    }
    // missing method → INVALID_REQUEST (even without id)
    try testing.expectEqual(errors.ErrorCode.invalid_request, parseWire(al, "{\"jsonrpc\":\"2.0\"}").fail.code);
    // empty method → INVALID_REQUEST
    try testing.expectEqual(errors.ErrorCode.invalid_request, parseWire(al, "{\"jsonrpc\":\"2.0\",\"method\":\"\"}").fail.code);
}

test "response builders round-trip to the expected JSON shape" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();

    const ok = try successBytesRaw(al, "u", "7");
    const ok_v = try std.json.parseFromSliceLeaky(std.json.Value, al, ok, .{});
    const ok_exp = try std.json.parseFromSliceLeaky(std.json.Value, al, "{\"jsonrpc\":\"2.0\",\"result\":7,\"id\":\"u\"}", .{});
    try testing.expect(json_eq.eql(ok_v, ok_exp));

    // error without data; id null
    const er = try errorBytes(al, null, .invalid_request, errors.msg.invalid_request, null);
    const er_v = try std.json.parseFromSliceLeaky(std.json.Value, al, er, .{});
    const er_exp = try std.json.parseFromSliceLeaky(std.json.Value, al, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"},\"id\":null}", .{});
    try testing.expect(json_eq.eql(er_v, er_exp));
}
