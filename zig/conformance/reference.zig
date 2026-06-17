//! The Zig reference protocols for A/B conformance, written as a **consumer** of the public library
//! (`@import("truenas_jsonrpc")`) — exactly how a downstream user builds a protocol. Must mirror
//! `zig/conformance/generate.py` exactly (same names, accepts/returns shapes, handler results, hooks).
const std = @import("std");
const trpc = @import("truenas_jsonrpc");

pub const PoolCreateArgs = struct { name: []const u8 };
pub const PoolCreateResult = struct { id: u32, name: []const u8 };
pub const AddArgs = struct { a: i64, b: i64 };
pub const AddResult = struct { sum: i64 };
pub const NoArgs = struct {};
pub const ServerInfoResult = struct { name: []const u8, version: []const u8 };
pub const LoginArgs = struct { user: []const u8, password: trpc.Secret([]const u8) };
pub const LoginResult = struct { token: trpc.Secret([]const u8), ok: bool };
pub const PingArgs = struct {};
pub const PingResult = struct { pong: bool };
pub const SetupArgs = struct { user: []const u8 };
pub const ContinueArgs = struct { otp: []const u8 };
pub const SetupAck = struct { stage: []const u8 };
pub const WhoamiResult = struct { who: []const u8 };
pub const VersionResult = struct { v: []const u8 };

const Ctx = trpc.RequestCtx(void);
const Builder = trpc.Protocol(void).Builder;

pub const Api = struct {
    fn create(_: *Api, args: PoolCreateArgs, _: *Ctx) !PoolCreateResult {
        return .{ .id = 7, .name = args.name };
    }
    fn add(_: *Api, args: AddArgs, _: *Ctx) !AddResult {
        return .{ .sum = args.a + args.b };
    }
    fn boom(_: *Api, _: NoArgs, _: *Ctx) !NoArgs {
        return error.Boom;
    }
    fn failing(_: *Api, _: NoArgs, ctx: *Ctx) !NoArgs {
        return ctx.fail(.request_failed, "expected failure", null);
    }
    fn secretOp(_: *Api, args: AddArgs, _: *Ctx) !AddResult {
        return .{ .sum = args.a + args.b };
    }
    fn authorize(_: *Api, request: trpc.RequestInfo, _: *trpc.Session(void)) trpc.AuthorizationResponse {
        if (std.mem.eql(u8, request.method, "secret_op")) return .{ .authorized = false, .message = "nope" };
        return .{ .authorized = true };
    }
    fn serverInfo(_: *Api, _: *trpc.Session(void)) ServerInfoResult {
        return .{ .name = "truenas", .version = "42" };
    }
    fn login(_: *Api, args: LoginArgs, ctx: *Ctx) !LoginResult {
        ctx.setAudit(std.fmt.allocPrint(ctx.arena, "as {s}", .{args.user}) catch "as ?");
        return .{ .token = .{ .value = "tok-secret" }, .ok = true };
    }
    fn ping(_: *Api, _: PingArgs, _: *Ctx) !PingResult {
        return .{ .pong = true };
    }
    fn crash(_: *Api, _: NoArgs, _: *Ctx) !PingResult {
        return error.Kaboom;
    }
    fn auditAuthorize(_: *Api, request: trpc.RequestInfo, _: *trpc.Session(void)) trpc.AuthorizationResponse {
        if (request.params == .object) if (request.params.object.get("user")) |u| {
            if (u == .string and std.mem.eql(u8, u.string, "denyme")) return .{ .authorized = false, .message = "denied" };
        };
        return .{ .authorized = true };
    }
    fn gatedSetup(_: *Api, _: SetupArgs, _: *Ctx) !trpc.SetupOutcome(SetupAck) {
        return .{ .lifecycle = .init, .result = .{ .stage = "init" } };
    }
    fn gatedContinue(_: *Api, _: ContinueArgs, _: *Ctx) !trpc.SetupOutcome(SetupAck) {
        return .{ .lifecycle = .established, .result = .{ .stage = "established" } };
    }
    fn whoami(_: *Api, _: NoArgs, _: *Ctx) !WhoamiResult {
        return .{ .who = "authed" };
    }
    fn version(_: *Api, _: NoArgs, _: *Ctx) !VersionResult {
        return .{ .v = "1.0" };
    }
};

fn registerCommon(b: *Builder, api: *Api) !void {
    try b.method("pool.create", api, Api.create, .{});
    try b.method("add", api, Api.add, .{});
    try b.method("boom", api, Api.boom, .{});
    try b.method("fail", api, Api.failing, .{});
}

/// `open` — no authorization; the spine.
pub fn buildOpen(gpa: std.mem.Allocator, api: *Api) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try registerCommon(&b, api);
    b.serverInfo(api, Api.serverInfo);
    return b.build();
}

/// `authz` — adds a `secret_op` method and an authorizer that denies it.
pub fn buildAuthz(gpa: std.mem.Allocator, api: *Api) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try registerCommon(&b, api);
    try b.method("secret_op", api, Api.secretOp, .{});
    b.authorizer(api, Api.authorize);
    return b.build();
}

/// One captured audit record, with `params`/`response` serialized to bytes (see `Capture`).
pub const AuditEntry = struct {
    method: ?[]const u8,
    id: ?[]const u8,
    params_json: []const u8,
    roles: []const []const u8,
    response_json: []const u8,
    message: ?[]const u8,
};

/// A consumer-side capturing audit sink. The record's `Value`s live in the dispatch's per-call arena
/// (freed when dispatch returns), so we copy/serialize each field into `arena` at capture time — the
/// pattern a real retaining sink (or Python's `poll_audit`) follows.
pub const Capture = struct {
    arena: std.mem.Allocator,
    records: std.ArrayList(AuditEntry) = .empty,

    fn onAudit(self: *Capture, rec: trpc.AuditRecord(void)) void {
        const a = self.arena;
        const entry: AuditEntry = .{
            .method = if (rec.method) |m| (a.dupe(u8, m) catch return) else null,
            .id = if (rec.id) |i| (a.dupe(u8, i) catch return) else null,
            .params_json = std.json.Stringify.valueAlloc(a, rec.params, .{}) catch return,
            .roles = rec.roles, // method.roles is long-lived; no copy needed
            .response_json = std.json.Stringify.valueAlloc(a, rec.response, .{}) catch return,
            .message = if (rec.message) |m| (a.dupe(u8, m) catch return) else null,
        };
        self.records.append(a, entry) catch return;
    }
};

/// `audit` — secret redaction (params + result), runtime message join, denial/error/notification
/// audit, and `audit = false` gating. Wires the capturing sink.
pub fn buildAudit(gpa: std.mem.Allocator, api: *Api, cap: *Capture) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.method("login", api, Api.login, .{ .audit = true, .audit_message = "user login" });
    try b.method("ping", api, Api.ping, .{});
    try b.method("crash", api, Api.crash, .{ .audit = true, .audit_message = "crash op" });
    b.authorizer(api, Api.auditAuthorize);
    b.auditSink(cap, Capture.onAudit);
    return b.build();
}

/// `gated` — session-setup (`setup` → `init`, `continue` → `established`) activates the ESTABLISHED
/// gate; `whoami` requires it, `version` is `pre_auth` (bypasses). No audit sink → no audit records.
pub fn buildGated(gpa: std.mem.Allocator, api: *Api) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.method("whoami", api, Api.whoami, .{});
    try b.method("version", api, Api.version, .{ .pre_auth = true });
    b.sessionSetup(api, Api.gatedSetup);
    b.sessionSetupContinue(api, Api.gatedContinue);
    return b.build();
}
