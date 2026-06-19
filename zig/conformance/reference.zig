//! The Zig reference protocols for A/B conformance, written as a **consumer** of the public library
//! (`@import("truenas_jsonrpc")`) — exactly how a downstream user builds a protocol. Must mirror
//! `zig/conformance/generate.py` exactly (same names, accepts/returns shapes, handler results, hooks).
const std = @import("std");
const trpc = @import("truenas_jsonrpc");
const rpc_gen = @import("rpc_gen.zig");
/// The codegen-produced OpenRPC document, embedded at compile time (`api-specs/gen.py` → `openrpc.json`,
/// next to this file so `@embedFile` can reach it). Re-exported for the conformance test + the $/describe payload.
pub const openrpc_json = @embedFile("openrpc.json");

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
pub const GAuthCreds = struct { user: []const u8, password: trpc.Secret([]const u8) };
pub const GAuthAck = struct { token: trpc.Secret([]const u8), stage: []const u8 };
pub const GAuthContinue = struct { otp: []const u8 };
pub const SubArgs = struct { channel: []const u8 };
pub const AlertEvent = struct { level: []const u8, text: []const u8 }; // the topic's `notifies` payload
// `filter` protocol — a filterable query method. `QueryArgs` is the (empty) base accepts; `Entry` is the
// per-record element type (flat scalars + an optional, to exercise every operator and the null guards).
pub const QueryArgs = struct {};
pub const Entry = struct { id: i64, name: []const u8, ratio: f64, active: bool, note: ?[]const u8 = null };
// `xdr` protocol — the byte-exact binary-wire methods. Types mirror generate.py's Xdr* Structs (i32, hyper,
// str=opaque, list=array, optional); both wires emit canonical XDR, the A/B compares exact bytes.
pub const XdrAddArgs = struct { a: i32, b: i32 };
pub const XdrAddResult = struct { sum: i64, label: []const u8 };
pub const XdrEcho = struct { items: []const i32, note: ?[]const u8, flag: bool };
// `transfer` protocol — raw-fd transfer methods; types mirror generate.py's T* Structs. The transfer
// handler returns a canned result (the A/B exercises the directive + complete(), not the fd I/O).
pub const TDlArgs = struct { size: i64 };
pub const TDlInterim = struct { size: i64 };
pub const TDlResult = struct { sent: i64, label: []const u8 };
pub const TUlArgs = struct { size: i64 };
pub const TUlResult = struct { received: i64, ok: bool };

/// The fixed dataset the streaming `query` handler pushes through the sink — byte-for-byte the same records
/// as generate.py's `_FDATA`, so the Python+C oracle and the Zig engine produce identical filtered output.
const filter_data = [_]Entry{
    .{ .id = 1, .name = "alpha", .ratio = 0.5, .active = true, .note = "x" },
    .{ .id = 2, .name = "beta", .ratio = 2.5, .active = false, .note = null },
    .{ .id = 3, .name = "alpha", .ratio = 1.5, .active = true, .note = null },
    .{ .id = 4, .name = "gamma", .ratio = 3.5, .active = false, .note = "y" },
    .{ .id = 5, .name = "Alpha", .ratio = 0.25, .active = true, .note = "z" },
};

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
    fn authorize(_: *Api, request: trpc.RequestInfo, _: *trpc.Session(void), _: ?*trpc.Session(void)) trpc.AuthorizationResponse {
        if (std.mem.eql(u8, request.method, "$/cancelRequest")) return .{ .authorized = false, .message = "cannot cancel" };
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
    fn auditAuthorize(_: *Api, request: trpc.RequestInfo, _: *trpc.Session(void), _: ?*trpc.Session(void)) trpc.AuthorizationResponse {
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
    fn gauthSetup(_: *Api, _: GAuthCreds, _: *Ctx) !trpc.SetupOutcome(GAuthAck) {
        return .{ .lifecycle = .init, .result = .{ .token = .{ .value = "t0p" }, .stage = "init" } };
    }
    fn gauthContinue(_: *Api, _: GAuthContinue, _: *Ctx) !trpc.SetupOutcome(GAuthAck) {
        return .{ .lifecycle = .established, .result = .{ .token = .{ .value = "t1" }, .stage = "established" } };
    }
    // A streaming filterable handler (mirrors generate.py's `fquery`, which push-downs through tnfilter):
    // emit each record; the sink tests-then-serializes only matches and stops early once a limit is hit.
    fn query(_: *Api, _: QueryArgs, _: *Ctx, sink: *trpc.FilterSink(Entry)) !void {
        for (filter_data) |e| {
            if (!sink.wantMore()) break;
            try sink.emit(e);
        }
    }
    // XDR binary-wire handlers (typed Accepts/Returns; the same handler shape as any method).
    fn xdrAdd(_: *Api, args: XdrAddArgs, _: *Ctx) !XdrAddResult {
        return .{ .sum = @as(i64, args.a) + args.b, .label = "ok" };
    }
    fn xdrEcho(_: *Api, args: XdrEcho, _: *Ctx) !XdrEcho {
        return args; // echo — re-encodes the decoded struct
    }
    // Raw-fd transfer handlers — negotiate returns the $/transferReady interim; transfer returns a canned
    // result (a real one would sendfile/recvfile on ft.fileno()). Match generate.py's t_* handlers.
    fn tDlNegotiate(_: *Api, args: TDlArgs, _: *Ctx) !TDlInterim {
        return .{ .size = args.size };
    }
    fn tDlTransfer(_: *Api, args: TDlArgs, ft: *const trpc.FileTransfer, _: *Ctx) !TDlResult {
        _ = ft;
        return .{ .sent = args.size, .label = "ok" };
    }
    fn tUlNegotiate(_: *Api, args: TUlArgs, _: *Ctx) !bool {
        _ = args;
        return true; // the upload interim is a bare bool
    }
    fn tUlTransfer(_: *Api, args: TUlArgs, ft: *const trpc.FileTransfer, _: *Ctx) !TUlResult {
        _ = ft;
        return .{ .received = args.size, .ok = true };
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

/// `gated_audit` — session-setup with a secret credential + secret result + an audit sink, so the
/// control-op audit records ($/sessionSetup / Continue / Close) are emitted and redacted. Mirrors
/// generate.py PROTO_GATED_AUDIT.
pub fn buildGatedAudit(gpa: std.mem.Allocator, api: *Api, cap: *Capture) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    b.sessionSetup(api, Api.gauthSetup);
    b.sessionSetupContinue(api, Api.gauthContinue);
    b.auditSink(cap, Capture.onAudit);
    return b.build();
}

/// A consumer-owned deterministic id source for the pub/sub A/B golden — the analog of `Capture` (a test
/// concern that lives in the conformance app, never the library, like Python's FixedIdGen). Mirrors
/// generate.py's pinned `uuid4` counter (`00000000-0000-4000-8000-{n:012d}`); `reset()` is called per
/// case so the first minted sub_id is ...000000000001 (matching the Python oracle's per-case reset).
pub const FixedIdGen = struct {
    n: u64 = 0,

    pub fn reset(self: *FixedIdGen) void {
        self.n = 0;
    }
    fn nextImpl(ctx: *anyopaque, buf: *[trpc.uuid_len]u8) []const u8 {
        const self: *FixedIdGen = @ptrCast(@alignCast(ctx));
        self.n += 1;
        return std.fmt.bufPrint(buf, "00000000-0000-4000-8000-{d:0>12}", .{self.n}) catch unreachable;
    }
    pub fn idGen(self: *FixedIdGen) trpc.IdGen {
        return .{ .ctx = @ptrCast(self), .nextFn = &nextImpl };
    }
};

/// `pubsub` — a SERVER_CLIENT subscribable topic (`alerts.subscribe`); a subscribe request mints a
/// sub_id ack via the injected FixedIdGen (a consumer concern). No session-setup (gate off) and no
/// authorizer, mirroring generate.py PROTO_PUBSUB.
pub fn buildPubSub(gpa: std.mem.Allocator, idg: *FixedIdGen) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.subscription("alerts.subscribe", SubArgs, AlertEvent, .{});
    b.idGen(idg.idGen());
    return b.build();
}

/// `filter` — a single filterable query method (`x.query`) whose handler streams `filter_data` through the
/// `FilterSink`. The golden for these cases is produced by driving the normative Python+C `tnfilter` engine
/// over the identical dataset (generate.py PROTO_FILTER), so the filtered/ordered/counted output must match.
pub fn buildFilter(gpa: std.mem.Allocator, api: *Api) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.filterableMethod("x.query", api, Api.query, Entry, .{});
    return b.build();
}

/// `xdr` — the binary-wire methods (xdr.add proc 1001, xdr.echo proc 1002; 0..=1000 are reserved for
/// protocol control messages). Proven against generate.py's byte-exact golden, where the Python
/// `xdr.py` codec is the normative reference.
pub fn buildXdr(gpa: std.mem.Allocator, api: *Api) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.method("xdr.add", api, Api.xdrAdd, .{ .xdr = true, .xdr_id = 1001 });
    try b.method("xdr.echo", api, Api.xdrEcho, .{ .xdr = true, .xdr_id = 1002 });
    // Filterable over the binary wire (proc 1003): streams the same `filter_data` through the FilterSink,
    // emitting the XDR result. Byte-exact against generate.py's `tnfilter`-driven golden.
    try b.filterableMethod("xdr.query", api, Api.query, Entry, .{ .xdr = true, .xdr_id = 1003 });
    return b.build();
}

/// `transfer` — raw-fd transfer methods (download + upload). Proven against generate.py's directive golden:
/// the Zig dispatch must reproduce the `$/transferReady` envelope + the `complete()` final response.
pub fn buildTransfer(gpa: std.mem.Allocator, api: *Api) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.transferMethod("file.download", api, Api.tDlNegotiate, Api.tDlTransfer, .download, .{ .pre_auth = true });
    try b.transferMethod("file.upload", api, Api.tUlNegotiate, Api.tUlTransfer, .upload, .{ .pre_auth = true });
    return b.build();
}

/// Hand-written handler bodies for the SPEC-GENERATED `audit` methods — note the param/return types are
/// the GENERATED `rpc_gen.*` structs, and the bodies match `Api.login`/`ping`/`crash` exactly. `pub` so
/// the generated `rpc_gen.register` can bind `H.<handler>` across the module boundary.
pub const GenHandlers = struct {
    pub fn login(_: *@This(), args: rpc_gen.LoginArgs, ctx: *Ctx) !rpc_gen.LoginResult {
        ctx.setAudit(std.fmt.allocPrint(ctx.arena, "as {s}", .{args.user}) catch "as ?");
        return .{ .token = .{ .value = "tok-secret" }, .ok = true };
    }
    pub fn ping(_: *@This(), _: rpc_gen.PingArgs, _: *Ctx) !rpc_gen.PingResult {
        return .{ .pong = true };
    }
    pub fn crash(_: *@This(), _: rpc_gen.CrashArgs, _: *Ctx) !rpc_gen.PingResult {
        return error.Kaboom;
    }
    // The SPEC-GENERATED filterable handler — streams the same `filter_data`, converted to the generated
    // `rpc_gen.Entry` (identical shape). Routing the filter A/B cases through this proves the codegen-emitted
    // `b.filterableMethod` registration behaves identically to the hand-written `buildFilter`.
    pub fn query(_: *@This(), _: rpc_gen.QueryArgs, _: *Ctx, sink: *trpc.FilterSink(rpc_gen.Entry)) !void {
        for (filter_data) |e| {
            if (!sink.wantMore()) break;
            try sink.emit(.{ .id = e.id, .name = e.name, .ratio = e.ratio, .active = e.active, .note = e.note });
        }
    }
    // Not a method (3 params but `*Session`, no error union) — wired as the authorizer hook, not collected.
    pub fn authorize(_: *@This(), request: trpc.RequestInfo, _: *trpc.Session(void), _: ?*trpc.Session(void)) trpc.AuthorizationResponse {
        if (request.params == .object) if (request.params.object.get("user")) |u| {
            if (u == .string and std.mem.eql(u8, u.string, "denyme")) return .{ .authorized = false, .message = "denied" };
        };
        return .{ .authorized = true };
    }
};

/// The `audit` protocol built from the SPEC-GENERATED `register()` instead of hand-written `b.method`
/// calls. Routing the audit golden cases through this proves generated == hand-written. The authorizer
/// and audit sink are hooks (not methods), so they stay hand-wired — same as `buildAudit`.
pub fn buildGenerated(gpa: std.mem.Allocator, handlers: *GenHandlers, cap: *Capture) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "test", "1.0.0");
    try rpc_gen.register(&b, handlers);
    b.authorizer(handlers, GenHandlers.authorize);
    b.auditSink(cap, Capture.onAudit);
    return b.build();
}

/// `describe` — serves the codegen-produced OpenRPC document via `$/describe`. `@embedFile`-ing the
/// generated `openrpc.json` proves it embeds + the library round-trips the doc (the bytes the spec-driven
/// `gen.py` emitted, which the Python A/B confirms equal `openrpc_gen.py`'s output).
pub fn buildDescribe(gpa: std.mem.Allocator) !trpc.Protocol(void) {
    var b = trpc.Protocol(void).builder(gpa, "sample", "1.0.0");
    b.describe(openrpc_json);
    return b.build();
}
