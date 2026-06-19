//! Error codes (the wire contract), the handler-raised `JsonRpcError` payload, and the
//! construction-time `BuildError`. Values mirror Python `truenas_pyjsonrpc.JSONRPCError` exactly.
const std = @import("std");

/// JSON-RPC error codes. Open enum (`_`): a handler may choose any custom code, which passes
/// through verbatim (e.g. `@as(ErrorCode, @enumFromInt(-32001))`).
pub const ErrorCode = enum(i32) {
    invalid_json = -32700,
    invalid_request = -32600,
    method_not_found = -32601,
    invalid_params = -32602,
    internal_error = -32603,
    not_authorized = -32000,
    session_not_established = -32002,
    request_cancelled = -32800,
    request_failed = -32803,
    _,
};

/// A handler-chosen JSON-RPC error. Carried out-of-band beside `error.JsonRpc` (Zig error
/// values hold no payload). `data` is omitted from the wire when null.
pub const JsonRpcError = struct {
    code: ErrorCode,
    message: []const u8,
    data: ?std.json.Value = null,
};

/// The single sentinel a handler returns to signal a chosen JSON-RPC error; the payload travels
/// on `RequestCtx` (see session.zig). ANY other error a handler returns becomes `internal_error`.
pub const HandlerError = error{JsonRpc};

/// Construction-time faults surfaced by the builder (mirrors Python `ValueError`/`TypeError`).
pub const BuildError = error{
    DuplicateMethod,
    ReservedMethodName,
    SessionSetupNotClientServer,
    SessionSetupMissingReturns,
    /// Two XDR-enabled methods share an `xdr_id` proc-id — its dispatch slot is already occupied (also
    /// caught at codegen by `gen.py`).
    DuplicateXdrId,
    /// An `xdr_id` falls in the reserved 0..=1000 band (kept for protocol control messages over the
    /// binary wire); an application method must use a proc-id >= 1001. (Also caught by `gen.py`.)
    ReservedXdrProcId,
    /// An `xdr_id` so far above the application base (1001) that the dispatch slot table — sized to the
    /// max proc-id so lookup is a bare array index — would balloon. Keep proc-ids dense near 1001.
    XdrProcIdTooLarge,
    OutOfMemory,
};

/// Standard error-object `message` strings — must byte-match Python `protocol.py` exactly (the A/B
/// conformance compares `{code, message}`; the variable `data` detail is impl-specific and stripped).
pub const msg = struct {
    pub const parse_error = "Parse error";
    pub const invalid_request = "Invalid request";
    pub const method_not_found = "Method not found";
    pub const invalid_params = "Invalid params";
    pub const internal_error = "Internal error";
    pub const invalid_result = "Invalid result";
    pub const request_failed = "Request failed";
    pub const session_closed = "Session is closed";
    pub const session_not_established = "Session not established";
    pub const request_cancelled = "Request cancelled";
};

test "wire values mirror Python JSONRPCError" {
    const t = std.testing;
    try t.expectEqual(@as(i32, -32700), @intFromEnum(ErrorCode.invalid_json));
    try t.expectEqual(@as(i32, -32600), @intFromEnum(ErrorCode.invalid_request));
    try t.expectEqual(@as(i32, -32601), @intFromEnum(ErrorCode.method_not_found));
    try t.expectEqual(@as(i32, -32602), @intFromEnum(ErrorCode.invalid_params));
    try t.expectEqual(@as(i32, -32603), @intFromEnum(ErrorCode.internal_error));
    try t.expectEqual(@as(i32, -32000), @intFromEnum(ErrorCode.not_authorized));
    try t.expectEqual(@as(i32, -32002), @intFromEnum(ErrorCode.session_not_established));
    try t.expectEqual(@as(i32, -32800), @intFromEnum(ErrorCode.request_cancelled));
    try t.expectEqual(@as(i32, -32803), @intFromEnum(ErrorCode.request_failed));
}

test "custom code passes through the open enum" {
    const custom: ErrorCode = @enumFromInt(-32001);
    try std.testing.expectEqual(@as(i32, -32001), @intFromEnum(custom));
}
