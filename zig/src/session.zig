//! `Session(S)` — per-connection state (mirrors Python `SessionState`); never serialized.
//! `RequestCtx(S)` — the handler context (mirrors Python `RequestState`): audit detail, cancellation,
//! and the `fail(...)` mechanism that carries a chosen `JsonRpcError` payload beside `error.JsonRpc`.
const std = @import("std");
const errors = @import("errors.zig");
const types = @import("types.zig");

/// `S` is the application's per-session server-internal state (identity/connection handle), the typed
/// analogue of Python's opaque `server_state_internal`.
pub fn Session(comptime S: type) type {
    return struct {
        session_uuid: []const u8,
        protocol_name: []const u8,
        lifecycle: types.SessionLifecycle = .none,
        /// Server-only: authenticated identity / connection handle (read by handlers + authorizer).
        server_state_internal: ?S = null,
        /// Client-facing data surfaced in session-setup replies.
        server_state_external: ?std.json.Value = null,
    };
}

/// The handler's `ctx`. Holds the per-dispatch arena (for handler result allocation), the request id,
/// a back-pointer to the session, and the out-of-band error payload.
pub fn RequestCtx(comptime S: type) type {
    return struct {
        const Self = @This();

        arena: std.mem.Allocator,
        id: ?[]const u8,
        sess: *Session(S),
        /// Count of `$/progress` notifications emitted (M2 back-channel).
        count: u32 = 0,
        cancelled_flag: bool = false,
        /// Runtime audit detail (last call wins); not redacted — keep secrets out.
        audit_message: ?[]const u8 = null,
        /// Set by `fail`; read back by the run thunk via `takeError`.
        pending_error: ?errors.JsonRpcError = null,

        pub fn session(self: *Self) *Session(S) {
            return self.sess;
        }

        pub fn setAudit(self: *Self, msg: []const u8) void {
            self.audit_message = msg;
        }

        pub fn cancelled(self: *const Self) bool {
            return self.cancelled_flag;
        }

        /// Choose a JSON-RPC error: `return ctx.fail(.request_failed, "…", null);`. Stashes the
        /// payload and returns the sentinel (Zig error values carry no payload).
        pub fn fail(self: *Self, code: errors.ErrorCode, message: []const u8, data: ?std.json.Value) error{JsonRpc} {
            self.pending_error = .{ .code = code, .message = message, .data = data };
            return error.JsonRpc;
        }

        pub fn raiseIfCancelled(self: *Self) error{JsonRpc}!void {
            if (self.cancelled_flag) return self.fail(.request_cancelled, "Request cancelled", null);
        }

        /// Map a returned error → a `JsonRpcError`: the `JsonRpc` sentinel yields the stashed payload;
        /// ANY other error becomes `internal_error` (Python's "any exception → INTERNAL_ERROR").
        pub fn takeError(self: *Self, e: anyerror) errors.JsonRpcError {
            if (e == error.JsonRpc) {
                if (self.pending_error) |pe| return pe;
            }
            return .{ .code = .internal_error, .message = "Internal error" };
        }
        // updateProgress(...) — M2, once the Outbound sink lands.
    };
}

const testing = std.testing;

const TestState = struct { uid: u32 };

test "fail stashes the chosen error; takeError returns it; setAudit + session() work" {
    var sess: Session(TestState) = .{ .session_uuid = "s", .protocol_name = "p" };
    sess.server_state_internal = .{ .uid = 42 };
    var ctx: RequestCtx(TestState) = .{ .arena = testing.allocator, .id = "u", .sess = &sess };

    ctx.setAudit("created");
    try testing.expectEqualStrings("created", ctx.audit_message.?);
    try testing.expectEqual(@as(u32, 42), ctx.session().server_state_internal.?.uid);

    const e = ctx.fail(.request_failed, "nope", null);
    try testing.expectEqual(error.JsonRpc, e);
    const jr = ctx.takeError(error.JsonRpc);
    try testing.expectEqual(@as(i32, -32803), @intFromEnum(jr.code));
    try testing.expectEqualStrings("nope", jr.message);
}

test "takeError maps a non-sentinel error to internal_error" {
    var sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p" };
    sess.lifecycle = .established;
    var ctx: RequestCtx(void) = .{ .arena = testing.allocator, .id = null, .sess = &sess };
    ctx.count += 1;
    const jr = ctx.takeError(error.SomethingElse);
    try testing.expectEqual(@as(i32, -32603), @intFromEnum(jr.code));
}

test "cancellation predicate + raiseIfCancelled" {
    var sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p" };
    sess.lifecycle = .established;
    var ctx: RequestCtx(void) = .{ .arena = testing.allocator, .id = "u", .sess = &sess };
    try testing.expect(!ctx.cancelled());
    try ctx.raiseIfCancelled(); // not cancelled → no error
    ctx.cancelled_flag = true;
    try testing.expect(ctx.cancelled());
    try testing.expectError(error.JsonRpc, ctx.raiseIfCancelled());
}

test "session defaults to lifecycle .none" {
    const sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p" };
    try testing.expectEqual(types.SessionLifecycle.none, sess.lifecycle);
}
