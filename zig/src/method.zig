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
const types = @import("types.zig");
const filter = @import("filter.zig");
const xdr = @import("xdr");
const transfer_mod = @import("transfer.zig");

/// Per-method flags (mirror Python `JSONRPCMethod`). `roles` is metadata only — not enforced here.
pub const MethodOpts = struct {
    pre_auth: bool = false,
    audit: bool = false,
    cancellable: bool = false,
    audit_message: ?[]const u8 = null,
    roles: []const []const u8 = &.{},
    /// Opt the method into the binary XDR wire (in addition to JSON). `xdr_id` is its stable on-the-wire
    /// proc-id (the op-table key); both are assigned in the spec, uniqueness enforced by `gen.py`.
    /// Proc-ids 0..=1000 are reserved for protocol control messages (see `xdr_frame.reserved_proc_max`),
    /// so an application method's `xdr_id` must be >= 1001.
    xdr: bool = false,
    xdr_id: u32 = 0,
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

/// Outcome of a transfer method's `negotiate` phase: the interim serialized to JSON (spliced into the
/// `$/transferReady` `result`), or an error (a denial-style failure, audited like a normal method's).
pub const NegotiateRan = union(enum) {
    ok_interim_json: []const u8,
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
        /// `client_server` for a request method; `server_client` for a subscribable topic (no handler —
        /// dispatch routes it to the subscribe path).
        direction: types.MessageDirection = .client_server,
        instance: *anyopaque,
        decode_fn: *const fn (arena: std.mem.Allocator, params: std.json.Value) Decoded,
        run_fn: *const fn (instance: *anyopaque, decoded: *anyopaque, ctx: *Ctx) Ran,
        // Audit-view producers (only invoked for `audit`-flagged methods on the cold audit path):
        // redact the decoded params, and redact a success result from its serialized bytes.
        audit_params_fn: *const fn (arena: std.mem.Allocator, decoded: *anyopaque) std.json.Value,
        audit_result_fn: *const fn (arena: std.mem.Allocator, result_bytes: []const u8) std.json.Value,
        // server_client topics only: validate a notification `payload` against `Notifies` and build the
        // `{jsonrpc, method, params}` wire (the transport's `sendNotification` calls this). A stub on
        // client_server methods (never invoked — the transport direction-checks first).
        notify_encode_fn: *const fn (arena: std.mem.Allocator, method_name: []const u8, payload: std.json.Value) ?[]const u8,
        // Parallel XDR (binary-wire) thunks — monomorphized from the SAME Accepts/Returns when XDR-compatible
        // (else a stub). `dispatchXdr` calls these instead of decode_fn/run_fn; `Decoded`/`Ran` are reused
        // (both wire-neutral: `ok: *anyopaque`, `ok_bytes: []const u8` + a typed error).
        xdr_decode_fn: *const fn (arena: std.mem.Allocator, params: []const u8) Decoded,
        xdr_run_fn: *const fn (instance: *anyopaque, decoded: *anyopaque, ctx: *Ctx) Ran,
        // Raw-fd transfer methods only (set by `defineTransfer`; defaulted/stubbed otherwise). A non-null
        // `transfer_direction` MARKS a transfer method — `dispatchFields` routes it to the transfer path (a
        // `Transfer` directive) instead of `run`. `negotiate_fn` runs the method's `negotiate` → the
        // `$/transferReady` interim (JSON); `transfer_run_fn` runs `transfer` over the `FileTransfer` →
        // the final response. `decode_fn` still decodes `Accepts`; `run_fn` is unused (a stub).
        transfer_direction: ?transfer_mod.TransferDirection = null,
        transfer_af_unix: bool = false,
        negotiate_fn: *const fn (instance: *anyopaque, decoded: *anyopaque, ctx: *Ctx) NegotiateRan = &negotiateStub,
        transfer_run_fn: *const fn (instance: *anyopaque, decoded: *anyopaque, ft: *const transfer_mod.FileTransfer, ctx: *Ctx) Ran = &transferRunStub,

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
        /// Validate `payload` against this topic's `Notifies` and produce the `{jsonrpc, method, params}`
        /// notification wire bytes (arena-owned), or null if the payload doesn't match `Notifies`. Only
        /// meaningful for a `server_client` topic (the transport checks `direction` before calling).
        pub fn encodeNotification(self: Self, arena: std.mem.Allocator, payload: std.json.Value) ?[]const u8 {
            return self.notify_encode_fn(arena, self.name, payload);
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
                // Parallel XDR thunks — same handler/instance/Accepts/Returns as the JSON thunks; only the
                // codec differs. Real iff the types are XDR-compatible (the `comptime` branch excludes the
                // codec instantiation otherwise, so a non-XDR method still compiles).
                fn xdrDecode(arena: std.mem.Allocator, params: []const u8) Decoded {
                    if (comptime xdr.compatible(Accepts)) {
                        const boxed = arena.create(Accepts) catch return .invalid_params;
                        var r = std.Io.Reader.fixed(params);
                        boxed.* = xdr.decode(Accepts, arena, &r) catch return .invalid_params;
                        if (@hasDecl(Accepts, "validate")) boxed.validate() catch return .invalid_params;
                        return .{ .ok = boxed };
                    } else return .invalid_params;
                }
                fn xdrRun(instance_ptr: *anyopaque, decoded_ptr: *anyopaque, ctx: *Ctx) Ran {
                    if (comptime xdr.compatible(Returns)) {
                        const svc: *Service = @ptrCast(@alignCast(instance_ptr));
                        const accepts: *Accepts = @ptrCast(@alignCast(decoded_ptr));
                        const result: Returns = handler(svc, accepts.*, ctx) catch |e| return .{ .rpc_error = ctx.takeError(e) };
                        if (Returns == void) return .{ .ok_bytes = "" };
                        const bytes = xdr.encodeAlloc(ctx.arena, result) catch
                            return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
                        return .{ .ok_bytes = bytes };
                    } else return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
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
                .notify_encode_fn = &notifyEncodeStub, // a request method never notifies
                .xdr_decode_fn = &Thunks.xdrDecode,
                .xdr_run_fn = &Thunks.xdrRun,
            };
        }

        /// A `server_client` subscribable topic: `Accepts` is the subscribe-request params, `Notifies` is
        /// the published-payload schema. It has no handler — dispatch routes it to the subscribe path
        /// (mint a sub id, ack) so `run`/audit are stubs; the transport's `sendNotification` validates a
        /// payload against `Notifies` + builds the notification wire via `encodeNotification`.
        pub fn defineTopic(comptime Accepts: type, comptime Notifies: type, name: []const u8, opts: MethodOpts) Self {
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
                // Validate+coerce `payload` to `Notifies` (drop unknown fields, like Python's
                // msgspec.convert), then splice the re-encoded params into the notification envelope.
                fn notifyEncode(arena: std.mem.Allocator, method_name: []const u8, payload: std.json.Value) ?[]const u8 {
                    const validated = std.json.parseFromValueLeaky(Notifies, arena, payload, .{ .ignore_unknown_fields = true }) catch return null;
                    if (@hasDecl(Notifies, "validate")) {
                        validated.validate() catch return null;
                    }
                    const params_bytes = serializeToBytes(arena, Notifies, validated) catch return null;
                    const method_json = std.json.Stringify.valueAlloc(arena, std.json.Value{ .string = method_name }, .{}) catch return null;
                    return std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"method\":{s},\"params\":{s}}}", .{ method_json, params_bytes }) catch null;
                }
            };
            return .{
                .name = name,
                .direction = .server_client,
                .pre_auth = opts.pre_auth,
                .audit = opts.audit,
                .cancellable = opts.cancellable,
                .audit_message = opts.audit_message,
                .roles = opts.roles,
                .instance = undefined, // no handler instance — never read for a topic
                .decode_fn = &Thunks.decode,
                .run_fn = &topicRunStub,
                .audit_params_fn = &topicValueStub,
                .audit_result_fn = &topicBytesStub,
                .notify_encode_fn = &Thunks.notifyEncode,
                .xdr_decode_fn = &xdrDecodeStub, // XDR pub-sub lands in a later slice
                .xdr_run_fn = &xdrRunStub,
            };
        }

        /// A `filterable` query method: the handler streams its records into a `FilterSink(Entry)` rather
        /// than returning a value. `BaseAccepts` is the un-augmented params struct; the augmented
        /// `query-filters`/`query-options` arrive as raw JSON. Mirrors Python's filterable dispatch
        /// (`compile_query → handler(filters, options) → finalize`), but on-the-fly: the run thunk compiles
        /// the filters against `Entry`, builds the sink, runs the handler, and serializes the result the
        /// sink produced (a bare integer for `count`, else a JSON array of matched entries). `dispatchFields`
        /// is unchanged — it sees an opaque `Ran.ok_bytes` and splices it like any method's result.
        pub fn defineFilterable(
            comptime Service: type,
            comptime BaseAccepts: type,
            comptime Entry: type,
            instance: *Service,
            comptime handler: fn (*Service, BaseAccepts, *Ctx, *filter.FilterSink(Entry)) anyerror!void,
            name: []const u8,
            opts: MethodOpts,
        ) Self {
            // The decode thunk can't reach the raw params at run time (the dispatcher threads only the typed
            // decode result), so box the typed base AND the raw Value; the run thunk pulls the query fields
            // off the latter. Simpler + safer than synthesizing an augmented struct via `@Type`.
            const Box = struct { base: BaseAccepts, raw: std.json.Value };
            const Sink = filter.FilterSink(Entry);
            const Thunks = struct {
                fn decode(arena: std.mem.Allocator, params: std.json.Value) Decoded {
                    const boxed = arena.create(Box) catch return .invalid_params;
                    boxed.base = std.json.parseFromValueLeaky(BaseAccepts, arena, params, .{ .ignore_unknown_fields = true }) catch
                        return .invalid_params;
                    if (@hasDecl(BaseAccepts, "validate")) {
                        boxed.base.validate() catch return .invalid_params;
                    }
                    boxed.raw = params;
                    return .{ .ok = boxed };
                }
                fn run(instance_ptr: *anyopaque, decoded_ptr: *anyopaque, ctx: *Ctx) Ran {
                    const svc: *Service = @ptrCast(@alignCast(instance_ptr));
                    const box: *Box = @ptrCast(@alignCast(decoded_ptr));
                    const arena = ctx.arena;

                    // Compile the query against `Entry`; any malformed filter / option → INVALID_PARAMS
                    // (mirrors Python `compile_query`'s `ValueError → INVALID_PARAMS`).
                    const qf: std.json.Value = pullField(box.raw, "query-filters") orelse .{ .array = std.json.Array.init(arena) };
                    const compiled = filter.compileFilters(arena, Entry, qf) catch return invalidParamsRan();
                    const options = filter.parseOptions(arena, pullField(box.raw, "query-options")) catch return invalidParamsRan();
                    const order_keys = filter.parseOrderBy(arena, Entry, options.order_by) catch return invalidParamsRan();

                    // Arena-allocate the sink and pass it by pointer — never copy it after `init`.
                    const sink = arena.create(Sink) catch
                        return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
                    sink.init(arena, compiled, options, order_keys);

                    handler(svc, box.base, ctx, sink) catch |e| return .{ .rpc_error = ctx.takeError(e) };

                    const bytes = sink.finalize() catch
                        return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
                    return .{ .ok_bytes = bytes };
                }
                // Audit views (cold path): redact the base params via their plan. The result is a raw array
                // of records / an int (no `Returns` type — Python `returns is None`), so it is reparsed
                // without redaction.
                fn auditParams(arena: std.mem.Allocator, decoded_ptr: *anyopaque) std.json.Value {
                    const box: *Box = @ptrCast(@alignCast(decoded_ptr));
                    const bytes = serializeToBytes(arena, BaseAccepts, box.base) catch return .null;
                    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch return .null;
                    return reflect.redactValue(BaseAccepts, v);
                }
                fn auditResult(arena: std.mem.Allocator, result_bytes: []const u8) std.json.Value {
                    return std.json.parseFromSliceLeaky(std.json.Value, arena, result_bytes, .{}) catch .null;
                }
                // Parallel XDR thunks. The augmented accepts arrive as XDR<base> · XDR<QueryOptions> ·
                // XDR<string> — the query-filters travel as a JSON-text `string<>` (dynamic/recursive
                // filters stay JSON, wrapped in the binary frame), while the base params + query-options are
                // XDR. The run reuses the SAME compileFilters/parseOrderBy/FilterSink, only emitting the
                // result as XDR (count → hyper, list → `u32 count + entry…`). Real iff base + entry are
                // XDR-compatible (else a stub, like the `define` path).
                const XdrBox = struct { base: BaseAccepts, options: filter.QueryOptions, filters_json: []const u8 };
                fn xdrDecode(arena: std.mem.Allocator, params: []const u8) Decoded {
                    if (comptime xdr.compatible(BaseAccepts) and xdr.compatible(Entry)) {
                        const boxed = arena.create(XdrBox) catch return .invalid_params;
                        var r = std.Io.Reader.fixed(params);
                        boxed.base = xdr.decode(BaseAccepts, arena, &r) catch return .invalid_params;
                        if (@hasDecl(BaseAccepts, "validate")) boxed.base.validate() catch return .invalid_params;
                        boxed.options = xdr.decode(filter.QueryOptions, arena, &r) catch return .invalid_params;
                        boxed.filters_json = xdr.decode([]const u8, arena, &r) catch return .invalid_params;
                        return .{ .ok = boxed };
                    } else return .invalid_params;
                }
                fn xdrRun(instance_ptr: *anyopaque, decoded_ptr: *anyopaque, ctx: *Ctx) Ran {
                    if (comptime xdr.compatible(BaseAccepts) and xdr.compatible(Entry)) {
                        const svc: *Service = @ptrCast(@alignCast(instance_ptr));
                        const box: *XdrBox = @ptrCast(@alignCast(decoded_ptr));
                        const arena = ctx.arena;
                        // The filters string is JSON text → parse to a Value → the existing compiler. An
                        // empty string means "no filters" (the JSON wire's `query-filters` default of []).
                        const qf: std.json.Value = if (box.filters_json.len == 0)
                            .{ .array = std.json.Array.init(arena) }
                        else
                            std.json.parseFromSliceLeaky(std.json.Value, arena, box.filters_json, .{}) catch return invalidParamsRan();
                        const compiled = filter.compileFilters(arena, Entry, qf) catch return invalidParamsRan();
                        const order_keys = filter.parseOrderBy(arena, Entry, box.options.order_by) catch return invalidParamsRan();
                        const sink = arena.create(Sink) catch
                            return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
                        sink.initXdr(arena, compiled, box.options, order_keys);
                        handler(svc, box.base, ctx, sink) catch |e| return .{ .rpc_error = ctx.takeError(e) };
                        const bytes = sink.finalizeXdr() catch
                            return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
                        return .{ .ok_bytes = bytes };
                    } else return .{ .rpc_error = .{ .code = .method_not_found, .message = errors.msg.method_not_found } };
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
                .notify_encode_fn = &notifyEncodeStub, // a filterable method never notifies
                .xdr_decode_fn = &Thunks.xdrDecode,
                .xdr_run_fn = &Thunks.xdrRun,
            };
        }

        /// A raw-fd transfer method (Python `JSONRPCFdTransferMethod`/`JSONRPCFdPassMethod`). `negotiate`
        /// validates the request + returns an interim "ready" value (→ the `$/transferReady` `result`);
        /// after the transport's wire handshake, `transfer` gets the connection's `FileTransfer` (the raw
        /// fd) and does the bulk stream, returning the final `Returns`. A non-null `transfer_direction`
        /// routes the method to the transfer path: decode → authz → negotiate → a `Transfer` directive; the
        /// transport then calls `complete(ft)` → `transfer_run_fn` → the final response. `af_unix` marks an
        /// fd-pass (`SCM_RIGHTS`) method, which the transport restricts to an AF_UNIX connection.
        pub fn defineTransfer(
            comptime Service: type,
            comptime Accepts: type,
            comptime Interim: type,
            comptime Returns: type,
            instance: *Service,
            comptime negotiate: fn (*Service, Accepts, *Ctx) anyerror!Interim,
            comptime transfer: fn (*Service, Accepts, *const transfer_mod.FileTransfer, *Ctx) anyerror!Returns,
            direction: transfer_mod.TransferDirection,
            af_unix: bool,
            name: []const u8,
            opts: MethodOpts,
        ) Self {
            const Thunks = struct {
                // Decode `Accepts` (used before negotiate) — same as `define`'s decode.
                fn decode(arena: std.mem.Allocator, params: std.json.Value) Decoded {
                    const boxed = arena.create(Accepts) catch return .invalid_params;
                    boxed.* = std.json.parseFromValueLeaky(Accepts, arena, params, .{ .ignore_unknown_fields = true }) catch
                        return .invalid_params;
                    if (@hasDecl(Accepts, "validate")) boxed.validate() catch return .invalid_params;
                    return .{ .ok = boxed };
                }
                fn negotiateThunk(instance_ptr: *anyopaque, decoded_ptr: *anyopaque, ctx: *Ctx) NegotiateRan {
                    const svc: *Service = @ptrCast(@alignCast(instance_ptr));
                    const accepts: *Accepts = @ptrCast(@alignCast(decoded_ptr));
                    const interim: Interim = negotiate(svc, accepts.*, ctx) catch |e|
                        return .{ .rpc_error = ctx.takeError(e) };
                    const json = serializeToBytes(ctx.arena, Interim, interim) catch
                        return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
                    return .{ .ok_interim_json = json };
                }
                fn transferThunk(instance_ptr: *anyopaque, decoded_ptr: *anyopaque, ft: *const transfer_mod.FileTransfer, ctx: *Ctx) Ran {
                    const svc: *Service = @ptrCast(@alignCast(instance_ptr));
                    const accepts: *Accepts = @ptrCast(@alignCast(decoded_ptr));
                    const result: Returns = transfer(svc, accepts.*, ft, ctx) catch |e|
                        return .{ .rpc_error = ctx.takeError(e) };
                    const bytes = serializeToBytes(ctx.arena, Returns, result) catch
                        return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.invalid_result } };
                    return .{ .ok_bytes = bytes };
                }
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
                .run_fn = &topicRunStub, // a transfer method never goes through the normal `run`
                .audit_params_fn = &Thunks.auditParams,
                .audit_result_fn = &Thunks.auditResult,
                .notify_encode_fn = &notifyEncodeStub,
                .xdr_decode_fn = &xdrDecodeStub, // transfers stay JSON in v1
                .xdr_run_fn = &xdrRunStub,
                .transfer_direction = direction,
                .transfer_af_unix = af_unix,
                .negotiate_fn = &Thunks.negotiateThunk,
                .transfer_run_fn = &Thunks.transferThunk,
            };
        }

        // A topic's request/audit thunks are never called (dispatch branches on `direction` first); these
        // stubs satisfy the non-optional fn-pointer fields.
        fn topicRunStub(_: *anyopaque, _: *anyopaque, _: *Ctx) Ran {
            return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
        }
        fn topicValueStub(_: std.mem.Allocator, _: *anyopaque) std.json.Value {
            return .null;
        }
        fn topicBytesStub(_: std.mem.Allocator, _: []const u8) std.json.Value {
            return .null;
        }
        // A client_server method is never published; the transport never calls this (direction-checked).
        fn notifyEncodeStub(_: std.mem.Allocator, _: []const u8, _: std.json.Value) ?[]const u8 {
            return null;
        }
        // XDR stubs for methods without a binary path yet (topics, filterable) — never reached unless a
        // non-XDR method is mistakenly addressed by proc-id.
        fn xdrDecodeStub(_: std.mem.Allocator, _: []const u8) Decoded {
            return .invalid_params;
        }
        fn xdrRunStub(_: *anyopaque, _: *anyopaque, _: *Ctx) Ran {
            return .{ .rpc_error = .{ .code = .method_not_found, .message = errors.msg.method_not_found } };
        }
        // Transfer thunks for non-transfer methods — never reached (dispatch routes on `transfer_direction`).
        fn negotiateStub(_: *anyopaque, _: *anyopaque, _: *Ctx) NegotiateRan {
            return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
        }
        fn transferRunStub(_: *anyopaque, _: *anyopaque, _: *const transfer_mod.FileTransfer, _: *Ctx) Ran {
            return .{ .rpc_error = .{ .code = .internal_error, .message = errors.msg.internal_error } };
        }
    };
}

/// Serialize a typed value to JSON bytes (arena-owned). The "validate the result" step is implicit in
/// successful serialization. Reused by the control handlers in protocol.zig (e.g. `$/serverInfo`).
pub fn serializeToBytes(arena: std.mem.Allocator, comptime T: type, value: T) ![]u8 {
    return std.json.Stringify.valueAlloc(arena, value, .{});
}

/// Look up a top-level key on a raw params object (null if absent or the params aren't an object). Used by
/// the filterable run thunk to pull the augmented `query-filters`/`query-options` off the request.
fn pullField(raw: std.json.Value, key: []const u8) ?std.json.Value {
    return if (raw == .object) raw.object.get(key) else null;
}

/// The INVALID_PARAMS `Ran` a filterable query compile failure produces (mirrors Python `compile_query`).
fn invalidParamsRan() Ran {
    return .{ .rpc_error = .{ .code = .invalid_params, .message = errors.msg.invalid_params } };
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

// ── defineFilterable ──────────────────────────────────────────────────────────
const FEntry = struct { id: i64, name: []const u8 };
const FArgs = struct {};
const FData = [_]FEntry{ .{ .id = 1, .name = "a" }, .{ .id = 2, .name = "b" }, .{ .id = 3, .name = "a" } };

const FSvc = struct {
    // A streaming push-down handler: emit each record; the sink tests/serializes only matches.
    fn query(_: *FSvc, _: FArgs, _: *RequestCtx(void), sink: *filter.FilterSink(FEntry)) !void {
        for (FData) |e| {
            if (!sink.wantMore()) break;
            try sink.emit(e);
        }
    }
};

test "defineFilterable: decode boxes base+raw; run filters / counts / rejects bad filters" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    var svc = FSvc{};
    const m = Method(void).defineFilterable(FSvc, FArgs, FEntry, &svc, FSvc.query, "x.query", .{});
    var sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p", .lifecycle = .established };
    var ctx = fixtureCtx(arena, &sess);

    // filter name == "a" → the matched records, in input order
    {
        const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"query-filters\":[[\"name\",\"=\",\"a\"]]}", .{});
        const dec = m.decode(arena, params);
        try testing.expect(dec == .ok);
        const ran = m.run(dec.ok, &ctx);
        try testing.expect(ran == .ok_bytes);
        const got = try std.json.parseFromSliceLeaky(std.json.Value, arena, ran.ok_bytes, .{});
        const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, "[{\"id\":1,\"name\":\"a\"},{\"id\":3,\"name\":\"a\"}]", .{});
        try testing.expect(json_eq.eql(got, exp));
    }
    // count → a bare integer (not an array)
    {
        const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"query-filters\":[[\"name\",\"=\",\"a\"]],\"query-options\":{\"count\":true}}", .{});
        const ran = m.run(m.decode(arena, params).ok, &ctx);
        try testing.expect(ran == .ok_bytes);
        try testing.expectEqualStrings("2", ran.ok_bytes);
    }
    // empty body → all records (query-filters defaults to [])
    {
        const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{}", .{});
        const ran = m.run(m.decode(arena, params).ok, &ctx);
        try testing.expect(ran == .ok_bytes);
        const got = try std.json.parseFromSliceLeaky(std.json.Value, arena, ran.ok_bytes, .{});
        try testing.expectEqual(@as(usize, 3), got.array.items.len);
    }
    // an unknown operator → INVALID_PARAMS (mirrors Python compile_query)
    {
        const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"query-filters\":[[\"name\",\"??\",\"a\"]]}", .{});
        const ran = m.run(m.decode(arena, params).ok, &ctx);
        try testing.expect(ran == .rpc_error);
        try testing.expectEqual(errors.ErrorCode.invalid_params, ran.rpc_error.code);
    }
}

test "defineFilterable XDR: augmented accepts decode + filter / count / order over the binary wire" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    var svc = FSvc{};
    const m = Method(void).defineFilterable(FSvc, FArgs, FEntry, &svc, FSvc.query, "x.query", .{});
    var sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p", .lifecycle = .established };
    var ctx = fixtureCtx(arena, &sess);

    // The XDR augmented accepts: XDR<base> · XDR<QueryOptions> · XDR<filters-as-JSON-string>.
    const H = struct {
        fn params(ar: std.mem.Allocator, opts: filter.QueryOptions, filters: []const u8) ![]const u8 {
            var aw: std.Io.Writer.Allocating = .init(ar);
            try xdr.encode(&aw.writer, FArgs{});
            try xdr.encode(&aw.writer, opts);
            try xdr.encode(&aw.writer, filters);
            return aw.writer.buffered();
        }
    };

    // filter name == "a" → a `u32 count + entry…` list of the 2 matches (id 1, then 3), in input order.
    {
        const p = try H.params(arena, .{}, "[[\"name\",\"=\",\"a\"]]");
        const dec = m.xdr_decode_fn(arena, p);
        try testing.expect(dec == .ok);
        const ran = m.xdr_run_fn(m.instance, dec.ok, &ctx);
        try testing.expect(ran == .ok_bytes);
        var r = std.Io.Reader.fixed(ran.ok_bytes);
        try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, try r.takeArray(4), .big));
        const e0 = try xdr.decode(FEntry, arena, &r);
        try testing.expectEqual(@as(i64, 1), e0.id);
        try testing.expectEqualStrings("a", e0.name);
        try testing.expectEqual(@as(i64, 3), (try xdr.decode(FEntry, arena, &r)).id);
    }
    // count → a bare hyper (not a list)
    {
        const p = try H.params(arena, .{ .count = true }, "[[\"name\",\"=\",\"a\"]]");
        const ran = m.xdr_run_fn(m.instance, m.xdr_decode_fn(arena, p).ok, &ctx);
        try testing.expect(ran == .ok_bytes);
        var r = std.Io.Reader.fixed(ran.ok_bytes);
        try testing.expectEqual(@as(i64, 2), try xdr.decode(i64, arena, &r));
    }
    // order_by -id, empty filters → all 3 entries, id 3,2,1
    {
        const p = try H.params(arena, .{ .order_by = &.{"-id"} }, "[]");
        const ran = m.xdr_run_fn(m.instance, m.xdr_decode_fn(arena, p).ok, &ctx);
        try testing.expect(ran == .ok_bytes);
        var r = std.Io.Reader.fixed(ran.ok_bytes);
        try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, try r.takeArray(4), .big));
        try testing.expectEqual(@as(i64, 3), (try xdr.decode(FEntry, arena, &r)).id);
        try testing.expectEqual(@as(i64, 2), (try xdr.decode(FEntry, arena, &r)).id);
        try testing.expectEqual(@as(i64, 1), (try xdr.decode(FEntry, arena, &r)).id);
    }
    // an unknown operator still → INVALID_PARAMS over XDR too
    {
        const p = try H.params(arena, .{}, "[[\"name\",\"??\",\"a\"]]");
        const ran = m.xdr_run_fn(m.instance, m.xdr_decode_fn(arena, p).ok, &ctx);
        try testing.expect(ran == .rpc_error);
        try testing.expectEqual(errors.ErrorCode.invalid_params, ran.rpc_error.code);
    }
}

// ── defineTransfer ──────────────────────────────────────────────────────────────
const DlArgs = struct { size: i64 };
const DlInterim = struct { size: i64 };
const DlResult = struct { sent: i64, sha: []const u8 };

const TSvc = struct {
    fn dlNegotiate(_: *TSvc, args: DlArgs, _: *RequestCtx(void)) !DlInterim {
        return .{ .size = args.size };
    }
    fn dlTransfer(_: *TSvc, args: DlArgs, ft: *const transfer_mod.FileTransfer, _: *RequestCtx(void)) !DlResult {
        // A real DOWNLOAD would `os.sendfile` on `ft.fileno()`; the test returns a canned result (the A/B
        // exercises the directive plumbing, not the fd I/O — that's the deferred transport's job).
        _ = ft;
        return .{ .sent = args.size, .sha = "deadbeef" };
    }
};

test "defineTransfer: marks a transfer method; negotiate → interim JSON; transfer → final result (mock fd)" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();

    var svc = TSvc{};
    const m = Method(void).defineTransfer(TSvc, DlArgs, DlInterim, DlResult, &svc, TSvc.dlNegotiate, TSvc.dlTransfer, .download, false, "file.download", .{});
    try testing.expect(m.transfer_direction.? == .download);
    try testing.expect(!m.transfer_af_unix);

    var sess: Session(void) = .{ .session_uuid = "s", .protocol_name = "p", .lifecycle = .established };
    var ctx = fixtureCtx(arena, &sess);

    const params = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"size\":1024}", .{});
    const dec = m.decode(arena, params);
    try testing.expect(dec == .ok);

    // negotiate → the interim that becomes the $/transferReady `result`
    const neg = m.negotiate_fn(m.instance, dec.ok, &ctx);
    try testing.expect(neg == .ok_interim_json);
    const interim = try std.json.parseFromSliceLeaky(std.json.Value, arena, neg.ok_interim_json, .{});
    try testing.expectEqual(@as(i64, 1024), interim.object.get("size").?.integer);

    // transfer over a mock FileTransfer → the final response result
    const ft: transfer_mod.FileTransfer = .{ .fd = -1, .direction = .download, .af_unix = false, .result_json = neg.ok_interim_json };
    const ran = m.transfer_run_fn(m.instance, dec.ok, &ft, &ctx);
    try testing.expect(ran == .ok_bytes);
    const res = try std.json.parseFromSliceLeaky(std.json.Value, arena, ran.ok_bytes, .{});
    try testing.expectEqual(@as(i64, 1024), res.object.get("sent").?.integer);
    try testing.expectEqualStrings("deadbeef", res.object.get("sha").?.string);
}
