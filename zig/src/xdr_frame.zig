//! The XDR binary-wire frame — modeled on the JSON-RPC envelope, so the two representations stay coupled.
//! A frame is `magic(raw u32) + XDR<Envelope> + payload`: the magic is the raw pre-decode discriminator
//! (a JSON envelope always starts with `{` = 0x7B, so a non-`{` magic is unambiguous), and the rest is the
//! envelope + payload run through the SAME generic codec used for params/results.
//!
//! The envelopes are the XDR analog of Python's `JSONRPCEnvelope` — the same logical fields, encoded
//! XDR-optimally. The only deliberate divergences from a byte-clone: `proc_id:u32` replaces the JSON
//! `method` string (the binary op-table), and the id is 16 raw bytes vs the JSON UUID string. The id is
//! canonicalized to/from the 36-char UUID string at the wire edge, so the in-flight/audit/cancel machinery
//! keeps its string keying.
//!
//!   Request:  magic · XDR<RequestEnvelope{version, proc_id, id:?[16]u8}> · params:XDR<Accepts>
//!   Reply:    magic · XDR<ReplyEnvelope{version, id:?[16]u8, status}>    · status 0 → result:XDR
//!                                                                          status 1 → XDR<{code,detail}>
const std = @import("std");
const errors = @import("errors.zig");
const xdr = @import("xdr");

pub const MAGIC: u32 = 0x54584452; // "TXDR"
pub const VERSION: u32 = 1;
/// Proc-ids 0..=this are RESERVED for protocol control messages (the `$/` namespace over the binary
/// wire — session setup / cancel / serverInfo, mirroring the JSON control ops; not yet implemented).
/// Application methods must use `xdr_id` > this. Mirrors api-specs/gen.py + Python `XDR_RESERVED_PROC_MAX`.
pub const reserved_proc_max: u32 = 1000;

/// The XDR request envelope — parallels `JSONRPCEnvelope` (`method` → `proc_id`; id as 16 raw bytes).
pub const RequestEnvelope = struct { version: u32, proc_id: u32, id: ?[16]u8 };
/// The XDR reply envelope — parallels `{jsonrpc, result|error, id}` (the result/error follows; `status`
/// discriminates, the XDR analog of JSON's result-vs-error key).
pub const ReplyEnvelope = struct { version: u32, id: ?[16]u8, status: u32 }; // status: 0 ok, 1 err
/// The error payload: the int code (fast path) + the full JSON `{code,message,data}` as a `string<>`.
pub const XdrErrorPayload = struct { code: i32, detail: []const u8 };

/// True iff `wire` is an XDR frame (starts with the magic). Cheap prefix check on a whole message.
pub fn isXdr(wire: []const u8) bool {
    return wire.len >= 4 and std.mem.readInt(u32, wire[0..4], .big) == MAGIC;
}

pub const Request = struct {
    version: u32,
    proc_id: u32,
    /// The id as the raw 16 wire bytes (null for a notification). Echoed straight back into the reply with
    /// zero allocation; the dispatcher canonicalizes it to a UUID string lazily — only when an id'd request
    /// engages the string-keyed shared machinery (authz info / in-flight tracker / audit).
    rid_bytes: ?[16]u8,
    /// The XDR-encoded params (the remainder of the frame) — fed to the method's `xdr_decode_fn`.
    params: []const u8,
};

pub const ParseError = error{ NotXdr, Truncated, BadId, OutOfMemory };

/// Parse an XDR request frame: the raw magic, then the codec-decoded envelope, then params = the remainder.
pub fn parseRequest(arena: std.mem.Allocator, wire: []const u8) ParseError!Request {
    var r = std.Io.Reader.fixed(wire);
    const m = std.mem.readInt(u32, r.takeArray(4) catch return error.Truncated, .big);
    if (m != MAGIC) return error.NotXdr;
    const env = xdr.decode(RequestEnvelope, arena, &r) catch return error.Truncated;
    // No id canonicalization here: keep the raw 16 bytes (the reply echoes them verbatim, and any id'd
    // request that needs the UUID string gets it lazily in the dispatcher).
    return .{ .version = env.version, .proc_id = env.proc_id, .rid_bytes = env.id, .params = wire[r.seek..] };
}

/// A success reply frame: magic + envelope (status 0) + the already-XDR-encoded `result_bytes`. The id is
/// the raw wire bytes, echoed back as-is (no string round-trip).
pub fn replyBytes(arena: std.mem.Allocator, rid: ?[16]u8, result_bytes: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeInt(u32, MAGIC, .big);
    try xdr.encode(w, ReplyEnvelope{ .version = VERSION, .id = rid, .status = 0 });
    try w.writeAll(result_bytes);
    return aw.writer.buffered();
}

/// An error reply frame: magic + envelope (status 1) + the `{code, detail}` payload.
pub fn errorFrame(arena: std.mem.Allocator, rid: ?[16]u8, err: errors.JsonRpcError) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeInt(u32, MAGIC, .big);
    try xdr.encode(w, ReplyEnvelope{ .version = VERSION, .id = rid, .status = 1 });
    try xdr.encode(w, XdrErrorPayload{ .code = @intFromEnum(err.code), .detail = try errorJson(arena, err) });
    return aw.writer.buffered();
}

/// The error detail packed into the frame: the JSON `{code,message[,data]}` object (matches the JSON wire's
/// `error` member), so a client gets the int code immediately AND the full structured info.
fn errorJson(arena: std.mem.Allocator, err: errors.JsonRpcError) ![]u8 {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(arena, "code", .{ .integer = @intFromEnum(err.code) });
    try obj.put(arena, "message", .{ .string = err.message });
    if (err.data) |d| try obj.put(arena, "data", d);
    return std.json.Stringify.valueAlloc(arena, std.json.Value{ .object = obj }, .{});
}

/// 16 raw bytes → the canonical hyphenated UUID string (arena-owned). The dispatcher calls this lazily for
/// an XDR request that crosses into the JSON string-keyed machinery (authz / in-flight tracker / audit).
pub fn bytesToUuid(arena: std.mem.Allocator, b: [16]u8) ![]u8 {
    return std.fmt.allocPrint(
        arena,
        "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
        .{ b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15] },
    );
}

/// Canonical hyphenated UUID string → 16 raw bytes (null if malformed).
fn uuidToBytes(s: []const u8) ?[16]u8 {
    if (s.len != 36) return null;
    var hex: [32]u8 = undefined;
    var j: usize = 0;
    for (s, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (c != '-') return null;
            continue;
        }
        hex[j] = c;
        j += 1;
    }
    var out: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, &hex) catch return null;
    return out;
}

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;
const test_uid = "123e4567-e89b-12d3-a456-426614174000";
const test_idb: [16]u8 = .{ 0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00 };

test "uuid round-trips bytes <-> string" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const s = try bytesToUuid(a.allocator(), test_idb);
    try testing.expectEqualStrings(test_uid, s);
    try testing.expectEqual(test_idb, uuidToBytes(s).?);
}

test "request frame is the envelope + params; parse recovers them" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // Build via the codec: magic + RequestEnvelope{1, 7, id} + params "ABCD".
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeInt(u32, MAGIC, .big);
    try xdr.encode(w, RequestEnvelope{ .version = 1, .proc_id = 7, .id = test_idb });
    try w.writeAll("ABCD");
    const wire = aw.writer.buffered();

    try testing.expect(isXdr(wire));
    const req = try parseRequest(arena, wire);
    try testing.expectEqual(@as(u32, 1), req.version);
    try testing.expectEqual(@as(u32, 7), req.proc_id);
    try testing.expectEqual(test_idb, req.rid_bytes.?); // raw bytes, not a canonicalized string
    try testing.expectEqualSlices(u8, "ABCD", req.params);

    // A notification (no id): proc_id only, params follow the lone 0 discriminant.
    var aw2: std.Io.Writer.Allocating = .init(arena);
    try aw2.writer.writeInt(u32, MAGIC, .big);
    try xdr.encode(&aw2.writer, RequestEnvelope{ .version = 1, .proc_id = 9, .id = null });
    try aw2.writer.writeAll("zz");
    const note = try parseRequest(arena, aw2.writer.buffered());
    try testing.expect(note.rid_bytes == null);
    try testing.expectEqual(@as(u32, 9), note.proc_id);
    try testing.expectEqualSlices(u8, "zz", note.params);
}

test "reply + error frames carry the id and status (offsets unchanged)" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    const ok = try replyBytes(arena, test_idb, "RES!");
    try testing.expect(isXdr(ok));
    // magic(4) version(4) id[disc(4)+16] status(4) "RES!"(4) = 36 bytes; status word at [28..32].
    try testing.expectEqual(@as(usize, 36), ok.len);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, ok[28..32], .big));

    const er = try errorFrame(arena, test_idb, .{ .code = .invalid_params, .message = "Invalid params" });
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, er[28..32], .big)); // status err
    try testing.expectEqual(@as(i32, -32602), std.mem.readInt(i32, er[32..36], .big)); // code
}
