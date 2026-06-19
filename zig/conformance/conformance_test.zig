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
    audits: []AuditEntry = &.{},
};
/// One server→client publish in a delivery case: a topic method + the payload to `sendNotification`.
const Publish = struct { method: []const u8, payload: std.json.Value = .null };
/// A delivery case: subscribe, publish each `publish`, then assert the drained outbound `notifications`.
const Delivery = struct {
    subscribe: []const u8,
    publish: []Publish = &.{},
    notifications: []std.json.Value = &.{},
};
const Case = struct {
    name: []const u8,
    protocol: []const u8,
    wire: []const u8 = "",
    response: ?std.json.Value = null,
    audits: []AuditEntry = &.{},
    steps: []Step = &.{},
    delivery: ?Delivery = null,
};
/// One byte-exact XDR case: a request frame + the reply frame the Zig dispatch must reproduce (both hex).
const XdrCase = struct { name: []const u8, request: []const u8, reply: []const u8 };
/// One transfer case: a request wire + the `$/transferReady` envelope (`ready`) the directive carries and
/// the `complete()` final response (`final`) — both compared structurally to the Zig dispatch's output.
const TransferCase = struct { name: []const u8, wire: []const u8, ready: std.json.Value, final: std.json.Value };
const Golden = struct { cases: []Case, xdr_cases: []XdrCase = &.{}, transfer_cases: []TransferCase = &.{} };

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
        // A subscribe directive: the golden compares the ack reply (sub_id + topic routing are a
        // transport concern, exercised in the M2b delivery suite, not in this response comparison).
        .subscribe => |s| std.json.parseFromSliceLeaky(std.json.Value, arena, s.reply, .{}) catch null,
        // A transfer directive: the `$/transferReady` envelope is the "response" here (the handshake +
        // complete() are exercised by the dedicated transfer A/B below).
        .transfer => |t| std.json.parseFromSliceLeaky(std.json.Value, arena, t.ready, .{}) catch null,
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
    // The SPEC-GENERATED `audit` protocol (built from rpc_gen.register). Every audit case is also run
    // through this and must match the golden identically — proving generated == hand-written.
    var gen_handlers = reference.GenHandlers{};
    var gen_cap = reference.Capture{ .arena = arena };
    var gen_proto = try reference.buildGenerated(std.testing.allocator, &gen_handlers, &gen_cap);
    defer gen_proto.deinit();
    // `gated_audit` — session-setup with secret creds + an audit sink, so the control-op audit records
    // ($/sessionSetup / Continue / Close) are emitted; compared per-step for the setup→continue→close flow.
    var gauth_cap = reference.Capture{ .arena = arena };
    var gated_audit_proto = try reference.buildGatedAudit(std.testing.allocator, &api, &gauth_cap);
    defer gated_audit_proto.deinit();
    // `pubsub` — a SERVER_CLIENT topic; subscribe mints a sub_id via the consumer-owned FixedIdGen
    // (reset per case so it counts from ...001, matching the Python oracle's pinned-uuid4 reset).
    var idg = reference.FixedIdGen{};
    var pubsub_proto = try reference.buildPubSub(std.testing.allocator, &idg);
    defer pubsub_proto.deinit();
    // `filter` — a filterable query method whose handler streams a fixed dataset through the FilterSink;
    // the golden is the normative Python+C `tnfilter` output over the identical data.
    var filter_proto = try reference.buildFilter(std.testing.allocator, &api);
    defer filter_proto.deinit();
    // A single-threaded Io backend drives the transport's (Io-aware) delivery in the delivery cases —
    // all ops are non-blocking here, so single-threaded suffices (the blocking poll is unit-tested apart).
    var iot: std.Io.Threaded = .init_single_threaded;
    const io = iot.io();

    var saw_audit = false; // anti-vacuity: at least one case actually emits an audit record
    var saw_steps = false; // anti-vacuity: at least one stateful multi-step sequence runs
    var saw_generated = false; // anti-vacuity: the spec-generated path is actually exercised
    var saw_delivery = false; // anti-vacuity: at least one pub/sub delivery (subscribe→publish→drain) runs
    var saw_filter = false; // anti-vacuity: at least one filterable (x.query) case runs
    var failures: usize = 0;
    for (golden.cases) |case| {
        if (std.mem.eql(u8, case.protocol, "filter")) saw_filter = true;
        const is_audit = std.mem.eql(u8, case.protocol, "audit");
        const is_gauth = std.mem.eql(u8, case.protocol, "gated_audit");
        const proto = if (is_audit)
            &audit_proto
        else if (is_gauth)
            &gated_audit_proto
        else if (std.mem.eql(u8, case.protocol, "authz"))
            &authz_proto
        else if (std.mem.eql(u8, case.protocol, "gated"))
            &gated_proto
        else if (std.mem.eql(u8, case.protocol, "pubsub"))
            &pubsub_proto
        else if (std.mem.eql(u8, case.protocol, "filter"))
            &filter_proto
        else
            &open_proto;
        // The capturing sink for this protocol (null when the protocol has no audit sink → no records).
        const cap_for: ?*reference.Capture = if (is_audit) &cap else if (is_gauth) &gauth_cap else null;
        // Reset the deterministic id source per pubsub case so each case's sub_ids count from ...001.
        if (std.mem.eql(u8, case.protocol, "pubsub")) idg.reset();

        // Delivery: subscribe → server publishes → drain the transport's outbound; compare the wire stream
        // to the Python oracle's. Exercises the Io-aware Transport as a consumer (subscribe directive →
        // applySubscribe → sendNotification → pollNotification), the M2b counterpart of the M2a ack A/B.
        if (case.delivery) |d| {
            saw_delivery = true;
            var tr = trpc.Transport(void).init(std.testing.allocator, &pubsub_proto);
            defer tr.deinit();
            var dsess = pubsub_proto.newSession(null);
            switch (pubsub_proto.dispatch(arena, d.subscribe, &dsess)) {
                .subscribe => |dir| tr.applySubscribe(io, dir, &dsess) catch {
                    failures += 1;
                    std.debug.print("A/B delivery [{s}]: applySubscribe failed\n", .{case.name});
                    continue;
                },
                else => {
                    failures += 1;
                    std.debug.print("A/B delivery [{s}]: subscribe yielded no directive\n", .{case.name});
                    continue;
                },
            }
            for (d.publish) |pm| {
                // The conformance owns the topic's `Notifies` type (AlertEvent); parse the golden payload
                // into it and publish — the transport re-validates + encodes the notification wire.
                const payload = std.json.parseFromValueLeaky(reference.AlertEvent, arena, pm.payload, .{ .ignore_unknown_fields = true }) catch {
                    failures += 1;
                    continue;
                };
                tr.sendNotification(io, pm.method, payload) catch |e| {
                    failures += 1;
                    std.debug.print("A/B delivery [{s}]: sendNotification failed: {s}\n", .{ case.name, @errorName(e) });
                };
            }
            for (d.notifications) |want| {
                const p = tr.pollNotification(io, false) orelse {
                    failures += 1;
                    std.debug.print("A/B delivery [{s}]: missing a notification\n", .{case.name});
                    break;
                };
                const v = std.json.parseFromSliceLeaky(std.json.Value, arena, p.data, .{}) catch .null;
                if (!trpc.testing.jsonEql(v, want)) {
                    failures += 1;
                    std.debug.print("A/B delivery [{s}]: notification mismatch\n  wire: {s}\n", .{ case.name, p.data });
                }
                std.testing.allocator.free(p.data); // freed only after the comparison + any diagnostic
            }
            if (tr.pollNotification(io, false)) |extra| { // nothing should remain beyond the golden stream
                std.testing.allocator.free(extra.data);
                failures += 1;
                std.debug.print("A/B delivery [{s}]: extra notification beyond golden\n", .{case.name});
            }
            continue;
        }

        // Stateful sequence: replay every step on ONE session (lifecycle + audits carry/capture per step).
        if (case.steps.len > 0) {
            saw_steps = true;
            var sess = proto.newSession(null);
            for (case.steps, 0..) |step, i| {
                if (cap_for) |c| c.records.clearRetainingCapacity();
                const got = dispatchToValue(proto, arena, &sess, step.wire);
                const have: []const reference.AuditEntry = if (cap_for) |c| c.records.items else &.{};
                if (step.audits.len > 0) saw_audit = true;
                if (!responseMatches(got, step.response) or !auditsMatch(arena, step.audits, have)) {
                    failures += 1;
                    std.debug.print("A/B step mismatch [{s} step {d}] (want {d} audits, have {d})\n  wire: {s}\n", .{ case.name, i, step.audits.len, have.len, step.wire });
                }
            }
            continue;
        }

        if (cap_for) |c| c.records.clearRetainingCapacity();
        var sess = proto.newSession(null);
        const got = dispatchToValue(proto, arena, &sess, case.wire);
        const resp_ok = responseMatches(got, case.response);

        const have_audits: []const reference.AuditEntry = if (cap_for) |c| c.records.items else &.{};
        const audits_ok = auditsMatch(arena, case.audits, have_audits);
        if (case.audits.len > 0) saw_audit = true;

        if (!resp_ok or !audits_ok) {
            failures += 1;
            std.debug.print("A/B mismatch [{s}] resp_ok={} audits_ok={} (want {d} audits, have {d})\n  wire: {s}\n", .{ case.name, resp_ok, audits_ok, case.audits.len, have_audits.len, case.wire });
        }

        // Re-run audit AND filter cases through the spec-generated protocol; it must match the golden
        // identically — proving the codegen-emitted `b.method` / `b.filterableMethod` == hand-written.
        if (is_audit or std.mem.eql(u8, case.protocol, "filter")) {
            saw_generated = true;
            gen_cap.records.clearRetainingCapacity();
            var gsess = gen_proto.newSession(null);
            const ggot = dispatchToValue(&gen_proto, arena, &gsess, case.wire);
            const gresp_ok = responseMatches(ggot, case.response);
            const gaudits_ok = auditsMatch(arena, case.audits, gen_cap.records.items);
            if (!gresp_ok or !gaudits_ok) {
                failures += 1;
                std.debug.print("A/B GENERATED mismatch [{s}] resp_ok={} audits_ok={}\n  wire: {s}\n", .{ case.name, gresp_ok, gaudits_ok, case.wire });
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
    try std.testing.expect(saw_audit);
    try std.testing.expect(saw_steps);
    try std.testing.expect(saw_generated);
    try std.testing.expect(saw_delivery);
    try std.testing.expect(saw_filter);

    // Directive teeth: the loop above compares only the ack *value* (`dispatchToValue` collapses the
    // directive). Assert here that a subscribe actually yields a `.subscribe` DIRECTIVE carrying the
    // minted sub_id + topic — the signal the (Io-aware) transport needs to register the subscription.
    idg.reset();
    var psess = pubsub_proto.newSession(null);
    switch (pubsub_proto.dispatch(arena, "{\"jsonrpc\":\"2.0\",\"id\":\"123e4567-e89b-12d3-a456-426614174000\",\"method\":\"alerts.subscribe\",\"params\":{\"channel\":\"pool\"}}", &psess)) {
        .subscribe => |s| {
            try std.testing.expectEqualStrings("00000000-0000-4000-8000-000000000001", s.sub_id);
            try std.testing.expectEqualStrings("alerts.subscribe", s.topic);
        },
        else => try std.testing.expect(false),
    }
}

const rpc_gen = @import("rpc_gen.zig");

test "generated rpc_gen.Demo round-trips (optional, default, array, enum, nested $ref, secret)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Decode via the engine's path (Value source → parseFromValue, which Secret's hook supports).
    const full = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"name\":\"n\",\"count\":3,\"ratio\":2.5,\"tags\":[\"a\",\"b\"],\"color\":\"green\",\"inner\":{\"x\":9},\"api_key\":\"sekret\"}", .{});
    const v = try std.json.parseFromValueLeaky(rpc_gen.Demo, arena, full, .{ .ignore_unknown_fields = true });
    try std.testing.expectEqualStrings("n", v.name);
    try std.testing.expectEqual(@as(i64, 3), v.count);
    try std.testing.expectEqual(@as(f64, 2.5), v.ratio);
    try std.testing.expect(v.note == null); // optional, absent
    try std.testing.expect(v.tags != null and v.tags.?.len == 2);
    try std.testing.expect(v.color == .green); // inline enum from a JSON string
    try std.testing.expectEqual(@as(i64, 9), v.inner.x); // nested $ref
    try std.testing.expectEqualStrings("sekret", v.api_key.value); // Secret unwrapped

    // Omitted count/ratio fall back to the schema defaults; note stays null.
    const min = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"name\":\"m\",\"color\":\"red\",\"inner\":{\"x\":1},\"api_key\":\"k\"}", .{});
    const d = try std.json.parseFromValueLeaky(rpc_gen.Demo, arena, min, .{});
    try std.testing.expectEqual(@as(i64, 0), d.count);
    try std.testing.expectEqual(@as(f64, 1.5), d.ratio);
    try std.testing.expect(d.color == .red);

    // Secret is wire-transparent on encode (real value, not "********").
    const bytes = try std.json.Stringify.valueAlloc(arena, v, .{});
    try std.testing.expect(std.mem.indexOf(u8, bytes, "sekret") != null);
}

test "$/describe serves the generated OpenRPC document" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var proto = try reference.buildDescribe(std.testing.allocator);
    defer proto.deinit();
    var sess = proto.newSession(null);
    switch (proto.dispatch(arena, "{\"jsonrpc\":\"2.0\",\"id\":\"123e4567-e89b-12d3-a456-426614174000\",\"method\":\"$/describe\"}", &sess)) {
        .reply => |bytes| {
            const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
            const result = v.object.get("result") orelse return error.NoResult;
            // The result equals the embedded codegen doc (round-trip) and is a well-formed OpenRPC 1.3.2 doc.
            const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, reference.openrpc_json, .{});
            try std.testing.expect(trpc.testing.jsonEql(result, doc));
            try std.testing.expectEqualStrings("1.3.2", result.object.get("openrpc").?.string);
            try std.testing.expect(result.object.get("methods").? == .array);
            try std.testing.expect(result.object.get("components").?.object.get("schemas") != null);
            try std.testing.expect(result.object.get("components").?.object.get("errors") != null);

            // Focused filterable-shape proof (these methods are scoped out of the openrpc_gen.py A/B, so
            // assert their contract here): x.query is `x-query:true`, result is an array of `Entry`, and its
            // query-options lists EXACTLY the four kept options (get + select dropped).
            var xq: ?std.json.Value = null;
            for (result.object.get("methods").?.array.items) |mv| {
                if (std.mem.eql(u8, mv.object.get("name").?.string, "x.query")) xq = mv;
            }
            try std.testing.expect(xq != null);
            try std.testing.expect(xq.?.object.get("x-query").?.bool);
            const res_schema = xq.?.object.get("result").?.object.get("schema").?.object;
            try std.testing.expectEqualStrings("array", res_schema.get("type").?.string);
            try std.testing.expectEqualStrings("#/components/schemas/Entry", res_schema.get("items").?.object.get("$ref").?.string);
            var qopts: ?std.json.Value = null;
            for (xq.?.object.get("params").?.array.items) |pv| {
                if (std.mem.eql(u8, pv.object.get("name").?.string, "query-options")) qopts = pv.object.get("schema");
            }
            const qprops = qopts.?.object.get("properties").?.object;
            try std.testing.expectEqual(@as(usize, 4), qprops.count());
            inline for (.{ "count", "order_by", "offset", "limit" }) |k|
                try std.testing.expect(qprops.get(k) != null);
        },
        else => try std.testing.expect(false),
    }
}

test "XDR A/B: Zig binary-wire dispatch reproduces the Python byte-exact frames" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const golden = try std.json.parseFromSliceLeaky(Golden, arena, golden_json, .{ .ignore_unknown_fields = true });
    try std.testing.expect(golden.xdr_cases.len >= 3); // anti-vacuity

    var api = reference.Api{};
    var proto = try reference.buildXdr(std.testing.allocator, &api);
    defer proto.deinit();

    var failures: usize = 0;
    for (golden.xdr_cases) |c| {
        const req = try arena.alloc(u8, c.request.len / 2);
        _ = try std.fmt.hexToBytes(req, c.request);
        const exp = try arena.alloc(u8, c.reply.len / 2);
        _ = try std.fmt.hexToBytes(exp, c.reply);

        var sess = proto.newSession(null);
        switch (proto.dispatch(arena, req, &sess)) {
            .reply => |got| if (!std.mem.eql(u8, got, exp)) {
                failures += 1;
                std.debug.print("XDR A/B [{s}]: reply bytes differ (want {d}, got {d})\n", .{ c.name, exp.len, got.len });
            },
            else => {
                failures += 1;
                std.debug.print("XDR A/B [{s}]: no reply\n", .{c.name});
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}

test "XDR codegen: the spec-emitted `.xdr`/`.xdr_id` opt-in yields a working binary-wire method (generated ping, proc 1001)" {
    // Closes the codegen loop: `ping` carries `"xdr": true, "xdr_id": 1001` in sample.json, so gen.py emits
    // `b.method("ping", …, .{ .xdr = true, .xdr_id = 1001 })`. Dispatch the generated method over the binary
    // wire and byte-compare the reply — proving the emitted opts produce a real XDR method, not just compile.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var gen_handlers = reference.GenHandlers{};
    var gen_cap = reference.Capture{ .arena = arena };
    var proto = try reference.buildGenerated(std.testing.allocator, &gen_handlers, &gen_cap);
    defer proto.deinit();

    // Request: magic + RequestEnvelope{version=1, proc_id=1001, id present} + params (PingArgs is empty → 0 bytes).
    const req_hex = "54584452" ++ "00000001" ++ "000003e9" ++ "00000001" ++ "123e4567e89b12d3a456426614174000";
    // Reply: magic + ReplyEnvelope{version=1, id, status=0} + PingResult{pong=true} (bool → u32 1).
    const rep_hex = "54584452" ++ "00000001" ++ "00000001" ++ "123e4567e89b12d3a456426614174000" ++ "00000000" ++ "00000001";

    const req = try arena.alloc(u8, req_hex.len / 2);
    _ = try std.fmt.hexToBytes(req, req_hex);
    const exp = try arena.alloc(u8, rep_hex.len / 2);
    _ = try std.fmt.hexToBytes(exp, rep_hex);

    var sess = proto.newSession(null);
    switch (proto.dispatch(arena, req, &sess)) {
        .reply => |got| try std.testing.expectEqualSlices(u8, exp, got),
        else => try std.testing.expect(false),
    }
}

test "transfer A/B: dispatch reproduces the Python $/transferReady envelope + complete() final response" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const golden = try std.json.parseFromSliceLeaky(Golden, arena, golden_json, .{ .ignore_unknown_fields = true });
    try std.testing.expect(golden.transfer_cases.len >= 2); // anti-vacuity

    var api = reference.Api{};
    var proto = try reference.buildTransfer(std.testing.allocator, &api);
    defer proto.deinit();

    var failures: usize = 0;
    for (golden.transfer_cases) |c| {
        var sess = proto.newSession(null);
        const d = proto.dispatch(arena, c.wire, &sess);
        if (d != .transfer) {
            failures += 1;
            std.debug.print("transfer A/B [{s}]: not a transfer directive\n", .{c.name});
            continue;
        }
        // The $/transferReady envelope the directive carries.
        const ready = std.json.parseFromSliceLeaky(std.json.Value, arena, d.transfer.ready, .{}) catch {
            failures += 1;
            continue;
        };
        if (!trpc.testing.jsonEql(ready, c.ready)) {
            failures += 1;
            std.debug.print("transfer A/B [{s}]: $/transferReady mismatch\n", .{c.name});
        }
        // complete() over a mock FileTransfer (no real fd) → the final response.
        const ft: trpc.FileTransfer = .{ .fd = -1, .direction = d.transfer.direction, .af_unix = d.transfer.af_unix, .result_json = "{}" };
        const final = d.transfer.complete(arena, &ft) orelse {
            failures += 1;
            continue;
        };
        const final_v = std.json.parseFromSliceLeaky(std.json.Value, arena, final, .{}) catch {
            failures += 1;
            continue;
        };
        if (!trpc.testing.jsonEql(final_v, c.final)) {
            failures += 1;
            std.debug.print("transfer A/B [{s}]: complete() final mismatch\n", .{c.name});
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}
