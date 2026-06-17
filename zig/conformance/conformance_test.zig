//! A/B differential conformance — the gating proof, run as a **consumer** of the published library.
//! It imports only `truenas_jsonrpc` (the public API, incl. `trpc.testing.jsonEql`), replays each
//! golden case (generated from the Python reference by `generate.py`) through the Zig reference
//! protocol, and asserts the response — plus, for audited methods, the redacted audit records, and,
//! for stateful `steps` sequences, each step on one carried-forward session — structurally equal the
//! Python oracle's.
const std = @import("std");
const trpc = @import("truenas_jsonrpc");
const reference = @import("reference.zig");

const golden_json = @embedFile("golden.json");

/// One golden audit record (the redacted view the Python audit handler received).
const AuditEntry = struct {
    method: ?[]const u8 = null,
    id: ?[]const u8 = null,
    params: std.json.Value = .null,
    roles: []const []const u8 = &.{},
    response: std.json.Value = .null,
    message: ?[]const u8 = null,
};
/// One step of a stateful sequence (dispatched on the same session as its siblings).
const Step = struct {
    wire: []const u8,
    response: ?std.json.Value = null,
};
const Case = struct {
    name: []const u8,
    protocol: []const u8,
    wire: []const u8 = "",
    response: ?std.json.Value = null,
    audits: []AuditEntry = &.{},
    steps: []Step = &.{},
};
const Golden = struct { cases: []Case };

fn optStrEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

fn rolesEql(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

fn dispatchToValue(proto: *trpc.Protocol(void), arena: std.mem.Allocator, sess: *trpc.Session(void), wire: []const u8) ?std.json.Value {
    return switch (proto.dispatch(arena, wire, sess)) {
        .none => null,
        .reply => |bytes| std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch null,
    };
}

fn responseMatches(got: ?std.json.Value, want: ?std.json.Value) bool {
    return if (want) |exp| (got != null and trpc.testing.jsonEql(got.?, exp)) else (got == null);
}

/// Compare the Python oracle's audit records to the ones the Zig engine captured for this case.
fn auditsMatch(arena: std.mem.Allocator, want: []const AuditEntry, have: []const reference.AuditEntry) bool {
    if (want.len != have.len) return false;
    for (want, have) |w, h| {
        if (!optStrEql(w.method, h.method)) return false;
        if (!optStrEql(w.id, h.id)) return false;
        if (!optStrEql(w.message, h.message)) return false;
        if (!rolesEql(w.roles, h.roles)) return false;
        const hp = std.json.parseFromSliceLeaky(std.json.Value, arena, h.params_json, .{}) catch return false;
        if (!trpc.testing.jsonEql(w.params, hp)) return false;
        const hr = std.json.parseFromSliceLeaky(std.json.Value, arena, h.response_json, .{}) catch return false;
        if (!trpc.testing.jsonEql(w.response, hr)) return false;
    }
    return true;
}

test "A/B differential against the Python oracle" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const golden = try std.json.parseFromSliceLeaky(Golden, arena, golden_json, .{ .ignore_unknown_fields = true });
    try std.testing.expect(golden.cases.len >= 10); // anti-vacuity: a silently-empty corpus fails

    var api = reference.Api{};
    var open_proto = try reference.buildOpen(std.testing.allocator, &api);
    defer open_proto.deinit();
    var authz_proto = try reference.buildAuthz(std.testing.allocator, &api);
    defer authz_proto.deinit();
    var cap = reference.Capture{ .arena = arena };
    var audit_proto = try reference.buildAudit(std.testing.allocator, &api, &cap);
    defer audit_proto.deinit();
    var gated_proto = try reference.buildGated(std.testing.allocator, &api);
    defer gated_proto.deinit();

    var saw_audit = false; // anti-vacuity: at least one case actually emits an audit record
    var saw_steps = false; // anti-vacuity: at least one stateful multi-step sequence runs
    var failures: usize = 0;
    for (golden.cases) |case| {
        const is_audit = std.mem.eql(u8, case.protocol, "audit");
        const proto = if (is_audit)
            &audit_proto
        else if (std.mem.eql(u8, case.protocol, "authz"))
            &authz_proto
        else if (std.mem.eql(u8, case.protocol, "gated"))
            &gated_proto
        else
            &open_proto;

        // Stateful sequence: replay every step on ONE session (lifecycle carries forward).
        if (case.steps.len > 0) {
            saw_steps = true;
            var sess = proto.newSession(null);
            for (case.steps, 0..) |step, i| {
                const got = dispatchToValue(proto, arena, &sess, step.wire);
                if (!responseMatches(got, step.response)) {
                    failures += 1;
                    std.debug.print("A/B step mismatch [{s} step {d}]\n  wire: {s}\n", .{ case.name, i, step.wire });
                }
            }
            continue;
        }

        if (is_audit) cap.records.clearRetainingCapacity();
        var sess = proto.newSession(null);
        const got = dispatchToValue(proto, arena, &sess, case.wire);
        const resp_ok = responseMatches(got, case.response);

        const have_audits: []const reference.AuditEntry = if (is_audit) cap.records.items else &.{};
        const audits_ok = auditsMatch(arena, case.audits, have_audits);
        if (case.audits.len > 0) saw_audit = true;

        if (!resp_ok or !audits_ok) {
            failures += 1;
            std.debug.print("A/B mismatch [{s}] resp_ok={} audits_ok={} (want {d} audits, have {d})\n  wire: {s}\n", .{ case.name, resp_ok, audits_ok, case.audits.len, have_audits.len, case.wire });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
    try std.testing.expect(saw_audit);
    try std.testing.expect(saw_steps);
}
