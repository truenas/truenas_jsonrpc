//! `Protocol(S)` — the synchronous dispatch core (Zig equivalent of Python `JSONRPCProtocol`), built
//! by a `Builder` whose `.method` primitive infers `Accepts`/`Returns` from the handler signature.
//! `dispatch(reply_alloc, wire, session)` is a plain function: bytes in → `Dispatched{reply|none}` out,
//! running the pipeline in a per-call arena and duping only the reply into `reply_alloc`.
//!
//! M1 tracer scope: parse → id → structural → method lookup → decode params → run → response. The
//! session gate, authorization, audit, and the five `$/` control messages are layered on next.
const std = @import("std");
const errors = @import("errors.zig");
const types = @import("types.zig");
const envelope = @import("envelope.zig");
const method_mod = @import("method.zig");
const session_mod = @import("session.zig");
const sink_mod = @import("sink.zig");

pub const Dispatched = union(enum) {
    /// Reply bytes owned by the caller's `reply_alloc` — caller frees.
    reply: []u8,
    /// Nothing to send (a notification, or a notification-context fault).
    none,
};

pub fn Protocol(comptime S: type) type {
    const Method = method_mod.Method(S);
    const Session = session_mod.Session(S);
    const RequestCtx = session_mod.RequestCtx(S);
    const AuditSink = sink_mod.AuditSink(S);
    const AuditRecord = sink_mod.AuditRecord(S);

    return struct {
        const Self = @This();

        /// Authorization hook (mirrors Python `authorization_handler`) — a closure over an app object.
        pub const Authorizer = struct {
            ctx: *anyopaque,
            call: *const fn (ctx: *anyopaque, request: types.RequestInfo, session: *Session) types.AuthorizationResponse,
        };

        /// `$/serverInfo` hook — an unauthenticated, infallible server-identity getter (closure over an app object).
        pub const ServerInfoHook = struct {
            ctx: *anyopaque,
            call: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, session: *Session) []const u8,
        };

        /// Outcome of running a session-setup handler: the result serialized to bytes (lifecycle +
        /// `server_state_external` already committed onto the session), or a fault.
        pub const SetupRan = union(enum) {
            ok: []const u8,
            invalid_params,
            rpc_error: errors.JsonRpcError,
        };

        /// `$/sessionSetup` / `$/sessionSetupContinue` hook — decodes the credentials, runs the handler
        /// `fn(*Inst, Accepts, *RequestCtx(S)) !SetupOutcome(Returns)`, then commits the returned
        /// `lifecycle` + `server_state_external` onto the session. Closure over an app object.
        pub const SetupHook = struct {
            ctx: *anyopaque,
            run: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, params: std.json.Value, rid: ?[]const u8, session: *Session) SetupRan,
        };

        gpa: std.mem.Allocator,
        name: []const u8,
        version: []const u8,
        methods: std.StringHashMap(Method),
        authorizer: ?Authorizer = null,
        server_info: ?ServerInfoHook = null,
        audit_sink: ?AuditSink = null,
        session_setup: ?SetupHook = null,
        session_setup_continue: ?SetupHook = null,
        /// True once `$/sessionSetup` is configured; activates the ESTABLISHED gate for non-`pre_auth` methods.
        has_session_setup: bool = false,

        pub const Builder = struct {
            proto: Self,

            /// Register a handler `fn(*Service, Accepts, *RequestCtx(S)) !Returns`; types are inferred
            /// from its signature. `name` must not use a reserved (`$/`, `rpc.`) prefix or duplicate.
            pub fn method(
                b: *Builder,
                name: []const u8,
                instance: anytype,
                comptime handler: anytype,
                opts: method_mod.MethodOpts,
            ) errors.BuildError!void {
                if (std.mem.startsWith(u8, name, "$/") or std.mem.startsWith(u8, name, "rpc."))
                    return error.ReservedMethodName;
                if (b.proto.methods.contains(name)) return error.DuplicateMethod;

                const Service = @typeInfo(@TypeOf(instance)).pointer.child;
                const fn_info = @typeInfo(@TypeOf(handler)).@"fn";
                const Accepts = fn_info.params[1].type.?;
                const Returns = @typeInfo(fn_info.return_type.?).error_union.payload;
                const m = Method.define(Service, Accepts, Returns, instance, handler, name, opts);
                try b.proto.methods.put(name, m);
            }

            /// Register the authorization hook (a closure over `instance`): a function
            /// `fn(*Inst, RequestInfo, *Session(S)) AuthorizationResponse`. Mirrors Python
            /// `register_authorization_handler`.
            pub fn authorizer(b: *Builder, instance: anytype, comptime f: anytype) void {
                const Inst = @typeInfo(@TypeOf(instance)).pointer.child;
                const Wrap = struct {
                    fn call(ctx: *anyopaque, request: types.RequestInfo, session: *Session) types.AuthorizationResponse {
                        const self: *Inst = @ptrCast(@alignCast(ctx));
                        return f(self, request, session);
                    }
                };
                b.proto.authorizer = .{ .ctx = @ptrCast(instance), .call = &Wrap.call };
            }

            /// Enable `$/serverInfo` with an infallible getter `fn(*Inst, *Session(S)) Returns`.
            pub fn serverInfo(b: *Builder, instance: anytype, comptime handler: anytype) void {
                const Inst = @typeInfo(@TypeOf(instance)).pointer.child;
                const Returns = @typeInfo(@TypeOf(handler)).@"fn".return_type.?;
                const Wrap = struct {
                    fn call(ctx: *anyopaque, arena: std.mem.Allocator, session: *Session) []const u8 {
                        const self: *Inst = @ptrCast(@alignCast(ctx));
                        const result: Returns = handler(self, session);
                        return method_mod.serializeToBytes(arena, Returns, result) catch "null";
                    }
                };
                b.proto.server_info = .{ .ctx = @ptrCast(instance), .call = &Wrap.call };
            }

            /// Register the audit sink (a closure over `instance`): `fn(*Inst, AuditRecord) void`, invoked
            /// once per `audit`-flagged method call — success, handler-error, or authorization denial —
            /// with a secret-redacted view. Mirrors Python `register_audit_handler`.
            pub fn auditSink(b: *Builder, instance: anytype, comptime f: anytype) void {
                const Inst = @typeInfo(@TypeOf(instance)).pointer.child;
                const Wrap = struct {
                    fn call(ctx: *anyopaque, record: AuditRecord) void {
                        const self: *Inst = @ptrCast(@alignCast(ctx));
                        f(self, record);
                    }
                };
                b.proto.audit_sink = .{ .ctx = @ptrCast(instance), .call = &Wrap.call };
            }

            /// Monomorphize a setup hook: decode `Accepts`, run the handler
            /// `fn(*Inst, Accepts, *RequestCtx(S)) !SetupOutcome(Returns)`, serialize the result, and
            /// commit `lifecycle` + `server_state_external`. `Returns` is read off the outcome struct.
            fn makeSetupHook(instance: anytype, comptime handler: anytype) SetupHook {
                const Inst = @typeInfo(@TypeOf(instance)).pointer.child;
                const fn_info = @typeInfo(@TypeOf(handler)).@"fn";
                const Accepts = fn_info.params[1].type.?;
                const Outcome = @typeInfo(fn_info.return_type.?).error_union.payload;
                const Returns = @FieldType(Outcome, "result");
                const Thunk = struct {
                    fn run(ctx: *anyopaque, arena: std.mem.Allocator, params: std.json.Value, rid: ?[]const u8, session: *Session) SetupRan {
                        const self: *Inst = @ptrCast(@alignCast(ctx));
                        const accepts = std.json.parseFromValueLeaky(Accepts, arena, params, .{ .ignore_unknown_fields = true }) catch
                            return .invalid_params;
                        if (@hasDecl(Accepts, "validate")) {
                            accepts.validate() catch return .invalid_params;
                        }
                        var rctx = RequestCtx{ .arena = arena, .id = rid, .sess = session };
                        const outcome = handler(self, accepts, &rctx) catch |e|
                            return .{ .rpc_error = rctx.takeError(e) };
                        const bytes = method_mod.serializeToBytes(arena, Returns, outcome.result) catch
                            return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.invalid_result } };
                        // Commit only after a clean run + serialize (a faulted setup leaves the session untouched).
                        session.lifecycle = outcome.lifecycle;
                        session.server_state_external = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch null;
                        return .{ .ok = bytes };
                    }
                };
                return .{ .ctx = @ptrCast(instance), .run = &Thunk.run };
            }

            /// Enable `$/sessionSetup` (the first auth step). Activates the ESTABLISHED gate: thereafter a
            /// non-`pre_auth` method requires an established session. Mirrors Python `add_session_setup`.
            pub fn sessionSetup(b: *Builder, instance: anytype, comptime handler: anytype) void {
                b.proto.session_setup = makeSetupHook(instance, handler);
                b.proto.has_session_setup = true;
            }

            /// Enable `$/sessionSetupContinue` (a later auth step, valid only at lifecycle `init`).
            pub fn sessionSetupContinue(b: *Builder, instance: anytype, comptime handler: anytype) void {
                b.proto.session_setup_continue = makeSetupHook(instance, handler);
            }

            pub fn build(b: *Builder) Self {
                return b.proto;
            }
        };

        pub fn builder(gpa: std.mem.Allocator, name: []const u8, version: []const u8) Builder {
            return .{ .proto = .{
                .gpa = gpa,
                .name = name,
                .version = version,
                .methods = std.StringHashMap(Method).init(gpa),
            } };
        }

        /// Build a protocol from a *service struct* (the primary, ergonomic authoring API — "add a
        /// method = add a `pub fn`"). Every `pub fn` shaped like a handler
        /// (`fn(*Service, Accepts, *RequestCtx(S)) !Returns`) becomes a method, its `Accepts`/`Returns`
        /// inferred. An optional `pub const rpc` decl carries per-method flags + a renamed wire name:
        /// `pub const rpc = .{ .create = .{ .name = "pool.create", .audit = true, .pre_auth = true } }`.
        /// Protocol-wide hooks may be passed in `opts` as closures over the same service instance:
        /// `.{ .authorizer = Svc.authorize, .server_info = Svc.serverInfo, .audit_sink = Svc.onAudit }`.
        /// Pure sugar over `builder().method(...)` (which the A/B suite proves), so behavior is identical.
        /// Note: a `pub fn` shaped like a session-setup handler would also match — keep those non-`pub`
        /// (or on a separate struct) and wire them via `builder().sessionSetup(...)`.
        pub fn fromService(gpa: std.mem.Allocator, name: []const u8, version: []const u8, service: anytype, opts: anytype) errors.BuildError!Self {
            const Service = @typeInfo(@TypeOf(service)).pointer.child;
            var b = builder(gpa, name, version);
            inline for (@typeInfo(Service).@"struct".decls) |decl| {
                const member = @field(Service, decl.name);
                if (@typeInfo(@TypeOf(member)) == .@"fn") {
                    const fi = @typeInfo(@TypeOf(member)).@"fn";
                    if (comptime isServiceMethod(@TypeOf(service), fi)) {
                        const meta = comptime methodMeta(Service, decl.name);
                        try b.method(meta.name, service, member, meta.opts);
                    }
                }
            }
            const O = @TypeOf(opts);
            if (@hasField(O, "authorizer")) b.authorizer(service, opts.authorizer);
            if (@hasField(O, "server_info")) b.serverInfo(service, opts.server_info);
            if (@hasField(O, "audit_sink")) b.auditSink(service, opts.audit_sink);
            return b.build();
        }

        /// A handler-shaped `pub fn`: `fn(*Service, Accepts, *RequestCtx(S)) !Returns`.
        fn isServiceMethod(comptime SelfPtr: type, comptime fi: std.builtin.Type.Fn) bool {
            return fi.params.len == 3 and
                fi.params[0].type == SelfPtr and
                fi.params[2].type == *RequestCtx and
                fi.return_type != null and
                @typeInfo(fi.return_type.?) == .error_union;
        }

        /// Resolve a method's wire name + flags from the optional `rpc` metadata decl (defaults otherwise).
        fn methodMeta(comptime Service: type, comptime decl_name: []const u8) struct { name: []const u8, opts: method_mod.MethodOpts } {
            if (@hasDecl(Service, "rpc") and @hasField(@TypeOf(Service.rpc), decl_name)) {
                const m = @field(Service.rpc, decl_name);
                const M = @TypeOf(m);
                return .{
                    .name = if (@hasField(M, "name")) m.name else decl_name,
                    .opts = .{
                        .pre_auth = if (@hasField(M, "pre_auth")) m.pre_auth else false,
                        .audit = if (@hasField(M, "audit")) m.audit else false,
                        .cancellable = if (@hasField(M, "cancellable")) m.cancellable else false,
                        .audit_message = if (@hasField(M, "audit_message")) m.audit_message else null,
                        .roles = if (@hasField(M, "roles")) m.roles else &.{},
                    },
                };
            }
            return .{ .name = decl_name, .opts = .{} };
        }

        pub fn deinit(self: *Self) void {
            self.methods.deinit();
        }

        /// session_uuid is a fixed placeholder for now (never appears in a response). The injectable
        /// IdGen seam lands with pub/sub, where a *subscription* id does appear on the wire.
        pub fn newSession(self: *Self, server_state: ?S) Session {
            return .{
                .session_uuid = "00000000-0000-4000-8000-000000000000",
                .protocol_name = self.name,
                .server_state_internal = server_state,
            };
        }

        pub fn dispatch(self: *Self, reply_alloc: std.mem.Allocator, wire: []const u8, session: *Session) Dispatched {
            var arena_state = std.heap.ArenaAllocator.init(self.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            const bytes: ?[]const u8 = switch (envelope.parse(arena, wire)) {
                // Stage 1–3 faults are always emitted, even for an id-less message.
                .fail => |f| envelope.errorBytes(arena, f.rid, f.code, f.message, null) catch null,
                .fields => |fields| self.dispatchFields(arena, fields, session),
            };

            if (bytes) |b| {
                const owned = reply_alloc.dupe(u8, b) catch return .none;
                return .{ .reply = owned };
            }
            return .none;
        }

        /// Stages 6/9/11/12 (lookup → decode → run → response). Returns the reply bytes (arena-owned)
        /// or null = nothing to send (a notification, whose side effects still run).
        fn dispatchFields(self: *Self, arena: std.mem.Allocator, fields: envelope.Fields, session: *Session) ?[]const u8 {
            const note = !fields.has_id;

            // Stage 4 — CLOSED short-circuit (a closed session rejects everything, including `$/...`).
            if (session.lifecycle == .closed)
                return if (note) null else (envelope.errorBytes(arena, fields.rid, .session_not_established, errors.msg.session_closed, null) catch null);

            // Stage 5 — control-message interception (`$/...`).
            if (std.mem.startsWith(u8, fields.method, "$/"))
                return self.handleControl(arena, fields, session);

            const m = self.methods.get(fields.method) orelse
                return if (note) null else (envelope.errorBytes(arena, fields.rid, .method_not_found, errors.msg.method_not_found, null) catch null);

            // Stage 8 — session gate (active only when session-setup is configured).
            if (self.has_session_setup and !m.pre_auth and session.lifecycle != .established)
                return if (note) null else (envelope.errorBytes(arena, fields.rid, .session_not_established, errors.msg.session_not_established, null) catch null);

            // Stage 9 — decode params before authorize, so INVALID_PARAMS precedes NOT_AUTHORIZED.
            const decoded = switch (m.decode(arena, fields.params)) {
                .ok => |p| p,
                .invalid_params => return if (note) null else (envelope.errorBytes(arena, fields.rid, .invalid_params, errors.msg.invalid_params, null) catch null),
            };

            // Stage 10 — authorize. A denial is still audited (success/error/denial each audit once).
            if (self.authorizer) |authz| {
                const info: types.RequestInfo = .{ .method = fields.method, .id = fields.rid, .params = fields.params, .roles = m.roles };
                const verdict = authz.call(authz.ctx, info, session);
                if (!verdict.authorized) {
                    self.maybeAudit(arena, m, fields.rid, decoded, .{ .err = .{ .code = .not_authorized, .message = verdict.message, .data = verdict.data } }, null, session);
                    return if (note) null else (envelope.errorBytes(arena, fields.rid, .not_authorized, verdict.message, verdict.data) catch null);
                }
            }

            // Stage 11 — run.
            var ctx: RequestCtx = .{ .arena = arena, .id = fields.rid, .sess = session };
            const ran = m.run(decoded, &ctx);

            // Stage 12 — audit (success or handler-error, carrying the handler's runtime detail). Fires
            // even for a notification, whose response is built for the audit view but not sent (Python parity).
            self.maybeAudit(arena, m, fields.rid, decoded, switch (ran) {
                .ok_bytes => |bytes| .{ .ok_result_bytes = bytes },
                .rpc_error => |e| .{ .err = e },
            }, ctx.audit_message, session);

            if (note) return null; // notification: the handler ran (side effects) but we send nothing.

            return switch (ran) {
                .ok_bytes => |bytes| envelope.successBytesRaw(arena, fields.rid, bytes) catch null,
                .rpc_error => |e| envelope.errorBytes(arena, fields.rid, e.code, e.message, e.data) catch null,
            };
        }

        /// What the audit record's `response` view is built from: `ok_result_bytes` are the success
        /// result bytes (redacted via the method's `Returns` plan); `err` is an error/denial (passed
        /// through — error envelopes carry no secret fields).
        const AuditOutcome = union(enum) {
            ok_result_bytes: []const u8,
            err: errors.JsonRpcError,
        };

        /// Emit one audit record iff the protocol has a sink and the method opted in (`audit = true`).
        /// Off the hot path: builds the redacted params + response Values and the assembled message.
        fn maybeAudit(self: *Self, arena: std.mem.Allocator, m: Method, rid: ?[]const u8, decoded: *anyopaque, outcome: AuditOutcome, detail: ?[]const u8, session: *Session) void {
            const audit = self.audit_sink orelse return;
            if (!m.audit) return;
            const response_v: std.json.Value = switch (outcome) {
                .ok_result_bytes => |bytes| auditSuccessValue(arena, rid, m.auditResult(arena, bytes)),
                .err => |e| auditErrorValue(arena, rid, e),
            };
            audit.call(audit.ctx, .{
                .method = m.name,
                .id = rid,
                .params = m.auditParams(arena, decoded),
                .roles = m.roles,
                .response = response_v,
                .message = assembleAuditMessage(arena, m.audit_message, detail),
                .session = session,
            });
        }

        fn handleControl(self: *Self, arena: std.mem.Allocator, fields: envelope.Fields, session: *Session) ?[]const u8 {
            if (std.mem.eql(u8, fields.method, "$/serverInfo")) return self.handleServerInfo(arena, fields, session);
            if (std.mem.eql(u8, fields.method, "$/sessionSetup")) return self.handleSessionSetup(arena, fields, session);
            if (std.mem.eql(u8, fields.method, "$/sessionSetupContinue")) return self.handleSessionContinue(arena, fields, session);
            if (std.mem.eql(u8, fields.method, "$/sessionClose")) return handleSessionClose(arena, fields, session);
            // Unknown `$/` control: METHOD_NOT_FOUND for a request, ignored for a notification.
            return if (!fields.has_id) null else (envelope.errorBytes(arena, fields.rid, .method_not_found, errors.msg.method_not_found, null) catch null);
        }

        /// `$/serverInfo` — unauthenticated, pre-gate, not audited; requires an id (never suppressed).
        fn handleServerInfo(self: *Self, arena: std.mem.Allocator, fields: envelope.Fields, session: *Session) ?[]const u8 {
            const hook = self.server_info orelse
                return if (!fields.has_id) null else (envelope.errorBytes(arena, fields.rid, .method_not_found, errors.msg.method_not_found, null) catch null);
            if (!fields.has_id)
                return envelope.errorBytes(arena, fields.rid, .invalid_request, errors.msg.invalid_request, null) catch null;
            const result_json = hook.call(hook.ctx, arena, session);
            return envelope.successBytesRaw(arena, fields.rid, result_json) catch null;
        }

        /// `$/sessionSetup` — the first auth step, valid only at lifecycle `none`. Requires an id.
        /// Bypasses authz (it *is* the auth step). (Audit of setup lands with the control-op audit.)
        fn handleSessionSetup(self: *Self, arena: std.mem.Allocator, fields: envelope.Fields, session: *Session) ?[]const u8 {
            const hook = self.session_setup orelse
                return if (!fields.has_id) null else (envelope.errorBytes(arena, fields.rid, .method_not_found, errors.msg.method_not_found, null) catch null);
            if (!fields.has_id)
                return envelope.errorBytes(arena, fields.rid, .invalid_request, errors.msg.invalid_request, null) catch null;
            if (session.lifecycle != .none)
                return envelope.errorBytes(arena, fields.rid, .request_failed, errors.msg.request_failed, null) catch null;
            return runSessionSetup(arena, hook, fields, session);
        }

        /// `$/sessionSetupContinue` — a later auth step, valid only at lifecycle `init`. Requires an id.
        fn handleSessionContinue(self: *Self, arena: std.mem.Allocator, fields: envelope.Fields, session: *Session) ?[]const u8 {
            const hook = self.session_setup_continue orelse
                return if (!fields.has_id) null else (envelope.errorBytes(arena, fields.rid, .method_not_found, errors.msg.method_not_found, null) catch null);
            if (!fields.has_id)
                return envelope.errorBytes(arena, fields.rid, .invalid_request, errors.msg.invalid_request, null) catch null;
            if (session.lifecycle != .init)
                return envelope.errorBytes(arena, fields.rid, .request_failed, errors.msg.request_failed, null) catch null;
            return runSessionSetup(arena, hook, fields, session);
        }

        fn runSessionSetup(arena: std.mem.Allocator, hook: SetupHook, fields: envelope.Fields, session: *Session) ?[]const u8 {
            return switch (hook.run(hook.ctx, arena, fields.params, fields.rid, session)) {
                .ok => |bytes| envelope.successBytesRaw(arena, fields.rid, bytes) catch null,
                .invalid_params => envelope.errorBytes(arena, fields.rid, .invalid_params, errors.msg.invalid_params, null) catch null,
                .rpc_error => |e| envelope.errorBytes(arena, fields.rid, e.code, e.message, e.data) catch null,
            };
        }

        /// `$/sessionClose` — client logout (`init`/`established` → `closed`). Requires an id; no authz.
        fn handleSessionClose(arena: std.mem.Allocator, fields: envelope.Fields, session: *Session) ?[]const u8 {
            if (!fields.has_id)
                return envelope.errorBytes(arena, fields.rid, .invalid_request, errors.msg.invalid_request, null) catch null;
            if (session.lifecycle != .init and session.lifecycle != .established)
                return envelope.errorBytes(arena, fields.rid, .request_failed, errors.msg.request_failed, null) catch null;
            session.lifecycle = .closed;
            return envelope.successBytesRaw(arena, fields.rid, "true") catch null;
        }
    };
}

// Audit-view builders (module scope; independent of `S`). The audit response mirrors the wire envelope
// but carries the *redacted* result, so secrets never reach the audit handler.
fn auditSuccessValue(arena: std.mem.Allocator, rid: ?[]const u8, result: std.json.Value) std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    obj.put(arena, "jsonrpc", .{ .string = "2.0" }) catch return .null;
    obj.put(arena, "result", result) catch return .null;
    obj.put(arena, "id", auditId(rid)) catch return .null;
    return .{ .object = obj };
}

fn auditErrorValue(arena: std.mem.Allocator, rid: ?[]const u8, e: errors.JsonRpcError) std.json.Value {
    var err_obj: std.json.ObjectMap = .empty;
    err_obj.put(arena, "code", .{ .integer = @intFromEnum(e.code) }) catch return .null;
    err_obj.put(arena, "message", .{ .string = e.message }) catch return .null;
    if (e.data) |d| err_obj.put(arena, "data", d) catch {};
    var obj: std.json.ObjectMap = .empty;
    obj.put(arena, "jsonrpc", .{ .string = "2.0" }) catch return .null;
    obj.put(arena, "error", .{ .object = err_obj }) catch return .null;
    obj.put(arena, "id", auditId(rid)) catch return .null;
    return .{ .object = obj };
}

fn auditId(rid: ?[]const u8) std.json.Value {
    return if (rid) |r| .{ .string = r } else .null;
}

/// Join the static per-method audit message (`base`) with the runtime `detail` (`set_audit`) into one:
/// `"base detail"` if both, else whichever is present, else null. Byte-matches Python `_assemble_audit_message`.
fn assembleAuditMessage(arena: std.mem.Allocator, base: ?[]const u8, detail: ?[]const u8) ?[]const u8 {
    if (base) |b| {
        if (detail) |d| return std.fmt.allocPrint(arena, "{s} {s}", .{ b, d }) catch b;
        return b;
    }
    return detail;
}

// ── Tests: the Zig dispatch spine end-to-end ─────────────────────────────────
const testing = std.testing;
const json_eq = @import("json_eq.zig");

const PoolCreateArgs = struct { name: []const u8 };
const PoolCreateResult = struct { id: u32, name: []const u8 };
const AddArgs = struct { a: i64, b: i64 };
const AddResult = struct { sum: i64 };
const NoArgs = struct {};
const ServerInfoResult = struct { name: []const u8, version: []const u8 };

const Api = struct {
    fn create(_: *Api, args: PoolCreateArgs, _: *session_mod.RequestCtx(void)) !PoolCreateResult {
        return .{ .id = 7, .name = args.name };
    }
    fn add(_: *Api, args: AddArgs, _: *session_mod.RequestCtx(void)) !AddResult {
        return .{ .sum = args.a + args.b };
    }
    fn boom(_: *Api, _: NoArgs, _: *session_mod.RequestCtx(void)) !NoArgs {
        return error.Boom;
    }
    fn failing(_: *Api, _: NoArgs, ctx: *session_mod.RequestCtx(void)) !NoArgs {
        return ctx.fail(.request_failed, "expected failure", null);
    }
    fn secretOp(_: *Api, args: AddArgs, _: *session_mod.RequestCtx(void)) !AddResult {
        return .{ .sum = args.a + args.b };
    }
    fn authorize(_: *Api, request: types.RequestInfo, _: *session_mod.Session(void)) types.AuthorizationResponse {
        if (std.mem.eql(u8, request.method, "secret_op")) return .{ .authorized = false, .message = "nope" };
        return .{ .authorized = true };
    }
    fn serverInfo(_: *Api, _: *session_mod.Session(void)) ServerInfoResult {
        return .{ .name = "truenas", .version = "42" };
    }
};

fn buildApi(gpa: std.mem.Allocator, api: *Api) !Protocol(void) {
    var b = Protocol(void).builder(gpa, "test", "1.0.0");
    try b.method("pool.create", api, Api.create, .{});
    try b.method("add", api, Api.add, .{});
    try b.method("boom", api, Api.boom, .{});
    try b.method("fail", api, Api.failing, .{});
    return b.build();
}

/// Dispatch `wire` and return the reply parsed to a Value (or null for `.none`).
fn rj(proto: *Protocol(void), arena: std.mem.Allocator, wire: []const u8) !?std.json.Value {
    var sess = proto.newSession(null);
    switch (proto.dispatch(arena, wire, &sess)) {
        .none => return null,
        .reply => |bytes| return try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}),
    }
}

fn expectJson(arena: std.mem.Allocator, actual: ?std.json.Value, expected_json: []const u8) !void {
    try testing.expect(actual != null);
    const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, expected_json, .{});
    try testing.expect(json_eq.eql(actual.?, exp));
}

fn expectJsonStr(arena: std.mem.Allocator, actual_json: []const u8, expected_json: []const u8) !void {
    const a = try std.json.parseFromSliceLeaky(std.json.Value, arena, actual_json, .{});
    const e = try std.json.parseFromSliceLeaky(std.json.Value, arena, expected_json, .{});
    try testing.expect(json_eq.eql(a, e));
}

test "audit: redacts params+result, joins message, audits denial w/o detail, skips audit=false" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const Secret = @import("meta.zig").Secret;
    const LoginArgs = struct { user: []const u8, password: Secret([]const u8) };
    const LoginResult = struct { token: Secret([]const u8), ok: bool };
    const PingArgs = struct {};
    const PingResult = struct { pong: bool };

    const Svc = struct {
        fn login(_: *@This(), args: LoginArgs, ctx: *session_mod.RequestCtx(void)) !LoginResult {
            ctx.setAudit(std.fmt.allocPrint(ctx.arena, "as {s}", .{args.user}) catch "as ?");
            return .{ .token = .{ .value = "tok-secret" }, .ok = true };
        }
        fn ping(_: *@This(), _: PingArgs, _: *session_mod.RequestCtx(void)) !PingResult {
            return .{ .pong = true };
        }
        fn authorize(_: *@This(), info: types.RequestInfo, _: *session_mod.Session(void)) types.AuthorizationResponse {
            if (info.params == .object) if (info.params.object.get("user")) |u| {
                if (u == .string and std.mem.eql(u8, u.string, "denyme")) return .{ .authorized = false, .message = "denied" };
            };
            return .{ .authorized = true };
        }
    };

    const Capture = struct {
        arena: std.mem.Allocator,
        n: u32 = 0,
        method: ?[]const u8 = null,
        params: ?[]const u8 = null,
        response: ?[]const u8 = null,
        message: ?[]const u8 = null,
        fn onAudit(self: *@This(), rec: sink_mod.AuditRecord(void)) void {
            self.n += 1;
            self.method = rec.method;
            self.params = std.json.Stringify.valueAlloc(self.arena, rec.params, .{}) catch null;
            self.response = std.json.Stringify.valueAlloc(self.arena, rec.response, .{}) catch null;
            self.message = if (rec.message) |m| (self.arena.dupe(u8, m) catch null) else null;
        }
    };

    var svc = Svc{};
    var cap = Capture{ .arena = arena };
    var b = Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("login", &svc, Svc.login, .{ .audit = true, .audit_message = "user login" });
    try b.method("ping", &svc, Svc.ping, .{}); // audit = false
    b.authorizer(&svc, Svc.authorize);
    b.auditSink(&cap, Capture.onAudit);
    var proto = b.build();
    defer proto.deinit();

    const uid = "123e4567-e89b-12d3-a456-426614174000";

    // success: the WIRE carries the real secret; the AUDIT view masks params + result; message is joined.
    cap = .{ .arena = arena };
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"login\",\"params\":{\"user\":\"bob\",\"password\":\"hunter2\"}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"token\":\"tok-secret\",\"ok\":true}}");
    try testing.expectEqual(@as(u32, 1), cap.n);
    try testing.expectEqualStrings("login", cap.method.?);
    try expectJsonStr(arena, cap.params.?, "{\"user\":\"bob\",\"password\":\"********\"}");
    try expectJsonStr(arena, cap.response.?, "{\"jsonrpc\":\"2.0\",\"result\":{\"token\":\"********\",\"ok\":true},\"id\":\"" ++ uid ++ "\"}");
    try testing.expectEqualStrings("user login as bob", cap.message.?);

    // denial: still audited (params redacted, error response), but message has NO detail (handler never ran).
    cap = .{ .arena = arena };
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"login\",\"params\":{\"user\":\"denyme\",\"password\":\"x\"}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32000,\"message\":\"denied\"}}");
    try testing.expectEqual(@as(u32, 1), cap.n);
    try expectJsonStr(arena, cap.params.?, "{\"user\":\"denyme\",\"password\":\"********\"}");
    try expectJsonStr(arena, cap.response.?, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\"denied\"},\"id\":\"" ++ uid ++ "\"}");
    try testing.expectEqualStrings("user login", cap.message.?);

    // audit = false: no record even though a sink is registered.
    cap = .{ .arena = arena };
    _ = try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"ping\",\"params\":{}}");
    try testing.expectEqual(@as(u32, 0), cap.n);
}

test "session lifecycle: gate, pre_auth bypass, setup→init→continue→established, close→closed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const SetupArgs = struct { user: []const u8 };
    const ContinueArgs = struct { otp: []const u8 };
    const SetupAck = struct { stage: []const u8 };
    const Whoami = struct { who: []const u8 };
    const Version = struct { v: []const u8 };

    const Svc = struct {
        fn setup(_: *@This(), _: SetupArgs, _: *session_mod.RequestCtx(void)) !types.SetupOutcome(SetupAck) {
            return .{ .lifecycle = .init, .result = .{ .stage = "init" } };
        }
        fn cont(_: *@This(), _: ContinueArgs, _: *session_mod.RequestCtx(void)) !types.SetupOutcome(SetupAck) {
            return .{ .lifecycle = .established, .result = .{ .stage = "established" } };
        }
        fn whoami(_: *@This(), _: struct {}, _: *session_mod.RequestCtx(void)) !Whoami {
            return .{ .who = "authed" };
        }
        fn version(_: *@This(), _: struct {}, _: *session_mod.RequestCtx(void)) !Version {
            return .{ .v = "1.0" };
        }
    };
    const H = struct {
        fn go(p: *Protocol(void), a: std.mem.Allocator, s: *session_mod.Session(void), wire: []const u8) !?std.json.Value {
            return switch (p.dispatch(a, wire, s)) {
                .none => null,
                .reply => |bytes| try std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}),
            };
        }
    };

    var svc = Svc{};
    var b = Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("whoami", &svc, Svc.whoami, .{});
    try b.method("version", &svc, Svc.version, .{ .pre_auth = true });
    b.sessionSetup(&svc, Svc.setup);
    b.sessionSetupContinue(&svc, Svc.cont);
    var proto = b.build();
    defer proto.deinit();

    const id = "\"123e4567-e89b-12d3-a456-426614174000\"";
    const whoami_wire = "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"method\":\"whoami\",\"params\":{}}";

    var sess = proto.newSession(null);
    // gate: a normal method before setup → SESSION_NOT_ESTABLISHED
    try expectJson(arena, try H.go(&proto, arena, &sess, whoami_wire), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"error\":{\"code\":-32002,\"message\":\"Session not established\"}}");
    // pre_auth method bypasses the gate
    try expectJson(arena, try H.go(&proto, arena, &sess, "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"method\":\"version\",\"params\":{}}"), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"result\":{\"v\":\"1.0\"}}");
    // setup → init
    try expectJson(arena, try H.go(&proto, arena, &sess, "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"method\":\"$/sessionSetup\",\"params\":{\"user\":\"bob\"}}"), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"result\":{\"stage\":\"init\"}}");
    try testing.expectEqual(types.SessionLifecycle.init, sess.lifecycle);
    // still gated at init (needs established, not just init)
    try expectJson(arena, try H.go(&proto, arena, &sess, whoami_wire), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"error\":{\"code\":-32002,\"message\":\"Session not established\"}}");
    // continue → established
    try expectJson(arena, try H.go(&proto, arena, &sess, "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"method\":\"$/sessionSetupContinue\",\"params\":{\"otp\":\"x\"}}"), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"result\":{\"stage\":\"established\"}}");
    try testing.expectEqual(types.SessionLifecycle.established, sess.lifecycle);
    // now the gate passes
    try expectJson(arena, try H.go(&proto, arena, &sess, whoami_wire), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"result\":{\"who\":\"authed\"}}");
    // close → closed, replies true
    try expectJson(arena, try H.go(&proto, arena, &sess, "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"method\":\"$/sessionClose\"}"), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"result\":true}");
    try testing.expectEqual(types.SessionLifecycle.closed, sess.lifecycle);
    // a closed session rejects everything
    try expectJson(arena, try H.go(&proto, arena, &sess, whoami_wire), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"error\":{\"code\":-32002,\"message\":\"Session is closed\"}}");

    // wrong-state / shape errors on a fresh (NONE) session
    var s2 = proto.newSession(null);
    try expectJson(arena, try H.go(&proto, arena, &s2, "{\"jsonrpc\":\"2.0\",\"method\":\"$/sessionSetup\",\"params\":{\"user\":\"bob\"}}"), "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid request\"}}");
    try expectJson(arena, try H.go(&proto, arena, &s2, "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"method\":\"$/sessionSetupContinue\",\"params\":{\"otp\":\"x\"}}"), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"error\":{\"code\":-32803,\"message\":\"Request failed\"}}");
    try expectJson(arena, try H.go(&proto, arena, &s2, "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"method\":\"$/sessionClose\"}"), "{\"jsonrpc\":\"2.0\",\"id\":" ++ id ++ ",\"error\":{\"code\":-32803,\"message\":\"Request failed\"}}");
}

test "fromService: pub fns become methods, rpc renames + flags apply, opts wire hooks" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const FsCreateArgs = struct { name: []const u8 };
    const FsCreateResult = struct { id: u32, name: []const u8 };
    const FsAddArgs = struct { a: i64, b: i64 };
    const FsAddResult = struct { sum: i64 };
    const FsVer = struct { v: []const u8 };

    const Svc = struct {
        pub fn create(_: *@This(), args: FsCreateArgs, _: *session_mod.RequestCtx(void)) !FsCreateResult {
            return .{ .id = 7, .name = args.name };
        }
        pub fn add(_: *@This(), args: FsAddArgs, _: *session_mod.RequestCtx(void)) !FsAddResult {
            return .{ .sum = args.a + args.b };
        }
        pub fn version(_: *@This(), _: struct {}, _: *session_mod.RequestCtx(void)) !FsVer {
            return .{ .v = "1.0" };
        }
        // private + handler-shaped: must NOT be collected (proves pub-only collection).
        fn secret(_: *@This(), _: struct {}, _: *session_mod.RequestCtx(void)) !FsVer {
            return .{ .v = "nope" };
        }
        // 2-param shape (a server-info getter), NOT a method; wired only via opts.server_info.
        pub fn srvInfo(_: *@This(), _: *session_mod.Session(void)) FsVer {
            return .{ .v = "srv" };
        }
        pub const rpc = .{
            .create = .{ .name = "pool.create", .audit = true },
            .version = .{ .pre_auth = true },
        };
    };

    var svc = Svc{};
    var proto = try Protocol(void).fromService(testing.allocator, "test", "1.0.0", &svc, .{ .server_info = Svc.srvInfo });
    defer proto.deinit();

    const uid = "123e4567-e89b-12d3-a456-426614174000";

    // renamed + default-named methods dispatch
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"pool.create\",\"params\":{\"name\":\"tank\"}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"id\":7,\"name\":\"tank\"}}");
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"add\",\"params\":{\"a\":2,\"b\":3}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"sum\":5}}");
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"version\",\"params\":{}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"v\":\"1.0\"}}");
    // the Zig fn name "create" is NOT registered (renamed to pool.create)
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"create\"}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");
    // private + 2-param fns are NOT collected
    try testing.expect(proto.methods.get("secret") == null);
    try testing.expect(proto.methods.get("srvInfo") == null);
    // rpc flags landed on the registered methods
    try testing.expect(proto.methods.get("pool.create").?.audit);
    try testing.expect(proto.methods.get("version").?.pre_auth);
    try testing.expect(!proto.methods.get("add").?.audit);
    // opts.server_info wired the $/serverInfo hook
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"$/serverInfo\"}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"v\":\"srv\"}}");
}

test "dispatch spine: happy / errors / notification" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var api = Api{};
    var proto = try buildApi(testing.allocator, &api);
    defer proto.deinit();

    const uid = "123e4567-e89b-12d3-a456-426614174000";

    // happy path — id echoed verbatim
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"pool.create\",\"params\":{\"name\":\"tank\"}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"id\":7,\"name\":\"tank\"}}");

    // typed add
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"add\",\"params\":{\"a\":2,\"b\":3}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"sum\":5}}");

    // unknown method → METHOD_NOT_FOUND
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"nope\"}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");

    // missing required param → INVALID_PARAMS
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"pool.create\",\"params\":{}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}");

    // array params → INVALID_PARAMS (by-name only)
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"add\",\"params\":[2,3]}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}");

    // handler raises → INTERNAL_ERROR
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"boom\"}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}");

    // handler ctx.fail → chosen code passes through
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"fail\"}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32803,\"message\":\"expected failure\"}}");

    // notification (no id) → no reply
    try testing.expect((try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"method\":\"pool.create\",\"params\":{\"name\":\"tank\"}}")) == null);
    // unknown-method notification → no reply
    try testing.expect((try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"method\":\"nope\"}")) == null);

    // envelope faults (always emitted, id null)
    try expectJson(arena, try rj(&proto, arena, "{not json"), "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}");
    try expectJson(arena, try rj(&proto, arena, "[1,2,3]"), "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid request\"}}");
}

test "authorization: deny → NOT_AUTHORIZED; decode precedes authz" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var api = Api{};
    var b = Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("add", &api, Api.add, .{});
    try b.method("secret_op", &api, Api.secretOp, .{});
    b.authorizer(&api, Api.authorize);
    var proto = b.build();
    defer proto.deinit();

    const uid = "123e4567-e89b-12d3-a456-426614174000";

    // allowed method runs normally
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"add\",\"params\":{\"a\":1,\"b\":1}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"sum\":2}}");

    // denied → NOT_AUTHORIZED carrying the authorizer's message
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"secret_op\",\"params\":{\"a\":1,\"b\":1}}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32000,\"message\":\"nope\"}}");

    // denied method with bad params → INVALID_PARAMS (decode runs before authorize)
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"secret_op\",\"params\":[1,2]}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}");
}

test "control: $/serverInfo, unknown $/, CLOSED short-circuit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var api = Api{};
    var b = Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("add", &api, Api.add, .{});
    b.serverInfo(&api, Api.serverInfo);
    var proto = b.build();
    defer proto.deinit();

    const uid = "123e4567-e89b-12d3-a456-426614174000";

    // $/serverInfo → result (unauthenticated, no params)
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"$/serverInfo\"}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"result\":{\"name\":\"truenas\",\"version\":\"42\"}}");

    // $/serverInfo without an id → INVALID_REQUEST (never suppressed)
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"method\":\"$/serverInfo\"}"), "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid request\"}}");

    // unknown $/ control → METHOD_NOT_FOUND; as a notification → no reply
    try expectJson(arena, try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"$/nope\"}"), "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");
    try testing.expect((try rj(&proto, arena, "{\"jsonrpc\":\"2.0\",\"method\":\"$/nope\"}")) == null);

    // a CLOSED session rejects everything
    var sess = proto.newSession(null);
    sess.lifecycle = .closed;
    switch (proto.dispatch(arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"add\",\"params\":{\"a\":1,\"b\":1}}", &sess)) {
        .reply => |bytes| {
            const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
            const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"error\":{\"code\":-32002,\"message\":\"Session is closed\"}}", .{});
            try testing.expect(json_eq.eql(v, exp));
        },
        .none => try testing.expect(false),
    }
}

test "builder rejects reserved prefixes and duplicates" {
    var api = Api{};
    var b = Protocol(void).builder(testing.allocator, "test", "1.0.0");
    var proto_built = false;
    defer if (!proto_built) {
        var p = b.build();
        p.deinit();
    };

    try b.method("pool.create", &api, Api.create, .{});
    try testing.expectError(error.DuplicateMethod, b.method("pool.create", &api, Api.create, .{}));
    try testing.expectError(error.ReservedMethodName, b.method("$/x", &api, Api.create, .{}));
    try testing.expectError(error.ReservedMethodName, b.method("rpc.x", &api, Api.create, .{}));

    var proto = b.build();
    proto_built = true;
    proto.deinit();
}
