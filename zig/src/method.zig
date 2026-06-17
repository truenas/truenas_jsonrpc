//! Comptime method type-erasure. `Method(S).define(...)` monomorphizes a `decode` and a `run` thunk
//! for a handler `fn(*Service, Accepts, *RequestCtx(S)) !Returns`, then erases them behind function
//! pointers + a `*anyopaque` service instance — so a protocol's dispatch table is a single concrete
//! `StringHashMap(Method(S))`. Two-phase: `decode` (→ `invalid_params`) runs before authorization;
//! `run` (→ `internal_error` / `"Invalid result"`) runs after. Mirrors Python `JSONRPCMethod`'s
//! decode → handler → returns-validate steps.
const std = @import("std");
const errors = @import("errors.zig");
const session = @import("session.zig");
const reflect = @import("reflect.zig");

/// Per-method flags (mirror Python `JSONRPCMethod`). `roles` is metadata only — not enforced here.
pub const MethodOpts = struct {
    pre_auth: bool = false,
    audit: bool = false,
    cancellable: bool = false,
    audit_message: ?[]const u8 = null,
    roles: []const []const u8 = &.{},
};

/// Outcome of the decode phase (by-name object only; a JSON array/scalar → `invalid_params`).
pub const Decoded = union(enum) {
    ok: *anyopaque, // *Accepts, arena-allocated
    invalid_params,
};

/// Outcome of the fused run+encode phase.
pub const Ran = union(enum) {
    /// Result serialized to JSON bytes (arena-owned; static "null" for a void return). Spliced
    /// straight into the response envelope — no intermediate `Value` tree, no re-stringify.
    ok_bytes: []const u8,
    rpc_error: errors.JsonRpcError,
};

pub fn Method(comptime S: type) type {
    const Ctx = session.RequestCtx(S);
    return struct {
        const Self = @This();

        name: []const u8,
        pre_auth: bool = false,
        audit: bool = false,
        cancellable: bool = false,
        audit_message: ?[]const u8 = null,
        roles: []const []const u8 = &.{},
        instance: *anyopaque,
        decode_fn: *const fn (arena: std.mem.Allocator, params: std.json.Value) Decoded,
        run_fn: *const fn (instance: *anyopaque, decoded: *anyopaque, ctx: *Ctx) Ran,
        // Audit-view producers (only invoked for `audit`-flagged methods on the cold audit path):
        // redact the decoded params, and redact a success result from its serialized bytes.
        audit_params_fn: *const fn (arena: std.mem.Allocator, decoded: *anyopaque) std.json.Value,
        audit_result_fn: *const fn (arena: std.mem.Allocator, result_bytes: []const u8) std.json.Value,

        pub fn decode(self: Self, arena: std.mem.Allocator, params: std.json.Value) Decoded {
            return self.decode_fn(arena, params);
        }
        pub fn run(self: Self, decoded: *anyopaque, ctx: *Ctx) Ran {
            return self.run_fn(self.instance, decoded, ctx);
        }
        /// Redacted audit view of the decoded params (the secret-masked `Accepts`).
        pub fn auditParams(self: Self, arena: std.mem.Allocator, decoded: *anyopaque) std.json.Value {
            return self.audit_params_fn(arena, decoded);
        }
        /// Redacted audit view of a success result, from the bytes the run thunk produced.
        pub fn auditResult(self: Self, arena: std.mem.Allocator, result_bytes: []const u8) std.json.Value {
            return self.audit_result_fn(arena, result_bytes);
        }

        /// Monomorphize the thunks over `Service`/`Accepts`/`Returns`/`handler` (all comptime) and
        /// erase them. `instance` is the service object the handler's `self` points at.
        pub fn define(
            comptime Service: type,
            comptime Accepts: type,
            comptime Returns: type,
            instance: *Service,
            comptime handler: fn (*Service, Accepts, *Ctx) anyerror!Returns,
            name: []const u8,
            opts: MethodOpts,
        ) Self {
            const Thunks = struct {
                fn decode(arena: std.mem.Allocator, params: std.json.Value) Decoded {
                    const boxed = arena.create(Accepts) catch return .invalid_params;
                    boxed.* = std.json.parseFromValueLeaky(Accepts, arena, params, .{ .ignore_unknown_fields = true }) catch
                        return .invalid_params;
                    if (@hasDecl(Accepts, "validate")) {
                        boxed.validate() catch return .invalid_params;
                    }
                    return .{ .ok = boxed };
                }
                fn run(instance_ptr: *anyopaque, decoded_ptr: *anyopaque, ctx: *Ctx) Ran {
                    const svc: *Service = @ptrCast(@alignCast(instance_ptr));
                    const accepts: *Accepts = @ptrCast(@alignCast(decoded_ptr));
                    const result: Returns = handler(svc, accepts.*, ctx) catch |e|
                        return .{ .rpc_error = ctx.takeError(e) };
                    if (Returns == void) return .{ .ok_bytes = "null" };
                    const bytes = serializeToBytes(ctx.arena, Returns, result) catch
                        return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.invalid_result } };
                    return .{ .ok_bytes = bytes };
                }
                // Audit views (cold path): serialize the decoded params / take the result bytes, parse
                // back to a Value, and mask secrets by walking the static `Accepts`/`Returns` type.
                fn auditParams(arena: std.mem.Allocator, decoded_ptr: *anyopaque) std.json.Value {
                    const accepts: *Accepts = @ptrCast(@alignCast(decoded_ptr));
                    const bytes = serializeToBytes(arena, Accepts, accepts.*) catch return .null;
                    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch return .null;
                    return reflect.redactValue(Accepts, v);
                }
                fn auditResult(arena: std.mem.Allocator, result_bytes: []const u8) std.json.Value {
                    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, result_bytes, .{}) catch return .null;
                    return reflect.redactValue(Returns, v);
                }
            };
            return .{
                .name = name,
                .pre_auth = opts.pre_auth,
                .audit = opts.audit,
                .cancellable = opts.cancellable,
                .audit_message = opts.audit_message,
                .roles = opts.roles,
                .instance = @ptrCast(instance),
                .decode_fn = &Thunks.decode,
                .run_fn = &Thunks.run,
                .audit_params_fn = &Thunks.auditParams,
                .audit_result_fn = &Thunks.auditResult,
            };
        }
    };
}

/// Serialize a typed value to JSON bytes (arena-owned). The "validate the result" step is implicit in
/// successful serialization. Reused by the control handlers in protocol.zig (e.g. `$/serverInfo`).
pub fn serializeToBytes(arena: std.mem.Allocator, comptime T: type, value: T) ![]u8 {
    return std.json.Stringify.valueAlloc(arena, value, .{});
}

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;
const json_eq = @import("json_eq.zig");
const RequestCtx = session.RequestCtx;
const Session = session.Session;

const CreateArgs = struct { name: []const u8 };
const CreateResult = struct { id: u32, name: []const u8 };
const NoArgs = struct {};

const Svc = struct {
    calls: u32 = 0,

    fn create(self: *Svc, args: CreateArgs, ctx: *RequestCtx(void)) !CreateResult {
        _ = ctx;
        self.calls += 1;
        return .{ .id = 7, .name = args.name };
    }
    fn boom(self: *Svc, args: NoArgs, ctx: *RequestCtx(void)) !NoArgs {
        _ = args;
        _ = ctx;
        self.calls += 1;
        return error.Boom;
    }
    fn customFail(self: *Svc, args: NoArgs, ctx: *RequestCtx(void)) !NoArgs {
        _ = args;
        self.calls += 1;
        return ctx.fail(@enumFromInt(-32001), "custom fail", null);
    }
};

fn fixtureCtx(arena: std.mem.Allocator, sess: *Session(void)) RequestCtx(void) {
    return .{ .arena = arena, .id = "u", .sess = sess };
}

test "define: decode + run happy path produces the result value and calls the handler" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    var svc = Svc{};
    const m = Method(void).define(Svc, CreateArgs, CreateResult, &svc, Svc.create, "pool.create", .{});

    var sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p", .lifecycle = .established };
    var ctx = fixtureCtx(arena, &sess);

    const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"name\":\"tank\"}", .{});
    const dec = m.decode(arena, params);
    try testing.expect(dec == .ok);

    const ran = m.run(dec.ok, &ctx);
    try testing.expect(ran == .ok_bytes);
    const got = try std.json.parseFromSliceLeaky(std.json.Value, arena, ran.ok_bytes, .{});
    const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"id\":7,\"name\":\"tank\"}", .{});
    try testing.expect(json_eq.eql(got, exp));
    try testing.expectEqual(@as(u32, 1), svc.calls);
}

test "decode rejects non-object / wrong-type / missing-required params" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    var svc = Svc{};
    const m = Method(void).define(Svc, CreateArgs, CreateResult, &svc, Svc.create, "pool.create", .{});

    inline for (.{ "[1,2]", "{\"name\":123}", "{}" }) |bad| {
        const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, bad, .{});
        try testing.expect(m.decode(arena, params) == .invalid_params);
    }
    try testing.expectEqual(@as(u32, 0), svc.calls); // never reached the handler
}

test "run maps a non-JsonRpc handler error to internal_error" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    var svc = Svc{};
    const m = Method(void).define(Svc, NoArgs, NoArgs, &svc, Svc.boom, "boom", .{});

    var sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p", .lifecycle = .established };
    var ctx = fixtureCtx(arena, &sess);

    const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{}", .{});
    const ran = m.run(m.decode(arena, params).ok, &ctx);
    try testing.expect(ran == .rpc_error);
    try testing.expectEqual(errors.ErrorCode.internal_error, ran.rpc_error.code);
    try testing.expectEqualStrings(errors.msg.internal_error, ran.rpc_error.message);
}

test "run passes a handler-chosen JsonRpcError through verbatim (custom code)" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    var svc = Svc{};
    const m = Method(void).define(Svc, NoArgs, NoArgs, &svc, Svc.customFail, "custom", .{});

    var sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p", .lifecycle = .established };
    var ctx = fixtureCtx(arena, &sess);

    const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{}", .{});
    const ran = m.run(m.decode(arena, params).ok, &ctx);
    try testing.expect(ran == .rpc_error);
    try testing.expectEqual(@as(i32, -32001), @intFromEnum(ran.rpc_error.code));
    try testing.expectEqualStrings("custom fail", ran.rpc_error.message);
}
