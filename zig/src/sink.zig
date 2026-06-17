//! The audit sink seam. `AuditSink(S)` is a closure the protocol invokes once per audited method call
//! (success / handler-error / authorization denial), handing it an already-redacted `AuditRecord(S)`.
//! Mirrors Python `register_audit_handler` + the `AuditRecord` it assembles. The record's `params` and
//! `response` Values live in the dispatch's per-call arena — a sink that retains them must copy (as
//! Python's `poll_audit` copies off the IO path); the conformance suite's capturing sink does exactly
//! that. M2 will add a back-channel/outbound sink alongside this one.
const std = @import("std");
const session_mod = @import("session.zig");

/// The redacted audit view (mirrors the kwargs Python's audit handler receives: a request view +
/// response envelope + the assembled message). `params` and the success `result` inside `response`
/// are secret-masked; errors pass through unredacted.
pub fn AuditRecord(comptime S: type) type {
    return struct {
        /// The method name. (`null` is reserved for the future control-op audits — sessionSetup/cancel.)
        method: ?[]const u8,
        id: ?[]const u8,
        params: std.json.Value,
        roles: []const []const u8,
        response: std.json.Value,
        message: ?[]const u8,
        session: *session_mod.Session(S),
    };
}

/// A closure over an app object — wired via `Builder.auditSink(instance, fn(*Inst, AuditRecord(S)) void)`.
pub fn AuditSink(comptime S: type) type {
    return struct {
        ctx: *anyopaque,
        call: *const fn (ctx: *anyopaque, record: AuditRecord(S)) void,
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;

test "AuditSink closure receives the record" {
    const Probe = struct {
        seen: u32 = 0,
        last_method: ?[]const u8 = null,
        last_message: ?[]const u8 = null,
        fn call(ctx: *anyopaque, record: AuditRecord(void)) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.seen += 1;
            self.last_method = record.method;
            self.last_message = record.message;
        }
    };
    var probe = Probe{};
    const sink = AuditSink(void){ .ctx = @ptrCast(&probe), .call = &Probe.call };

    var sess: session_mod.Session(void) = .{ .session_uuid = "s", .protocol_name = "p" };
    sink.call(sink.ctx, .{
        .method = "login",
        .id = "u",
        .params = .null,
        .roles = &.{},
        .response = .null,
        .message = "user login",
        .session = &sess,
    });

    try testing.expectEqual(@as(u32, 1), probe.seen);
    try testing.expectEqualStrings("login", probe.last_method.?);
    try testing.expectEqualStrings("user login", probe.last_message.?);
}
