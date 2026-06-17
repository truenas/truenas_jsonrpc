//! Core value types shared across the engine: session lifecycle, method direction, the authz/audit
//! request view, and small wire structs. Mirrors Python `truenas_pyjsonrpc.types`.
const std = @import("std");

/// Per-session lifecycle. `none → (init)* → established → closed`. Internal (never serialized);
/// a session-setup handler returns the next value and the protocol commits it.
pub const SessionLifecycle = enum { none, init, established, closed };

/// Whether a method is a client→server request or a server→client subscription topic.
pub const MessageDirection = enum { client_server, server_client };

/// The authorizer's verdict. `message`/`data` are surfaced on a `not_authorized` error.
pub const AuthorizationResponse = struct {
    authorized: bool,
    message: []const u8 = "Not authorized",
    data: ?std.json.Value = null,
};

/// The authz/audit view of a request (= Python `JSONRPCRequest`). Named `RequestInfo` to avoid
/// confusion with `RequestCtx` (the handler context).
pub const RequestInfo = struct {
    method: []const u8,
    id: ?[]const u8,
    params: std.json.Value,
    roles: []const []const u8 = &.{},
};

/// Unauthenticated server-identity probe payload (`$/serverInfo`).
pub const ServerInfo = struct {
    name: []const u8,
    version: ?[]const u8 = null,
};

/// What a session-setup handler returns: the next `SessionLifecycle` to commit and the client-facing
/// result. Mirrors Python's `(lifecycle, result)` tuple contract. Use as
/// `trpc.SetupOutcome(MyResult){ .lifecycle = .established, .result = ... }`; `.init` instead signals a
/// further `$/sessionSetupContinue` step.
pub fn SetupOutcome(comptime R: type) type {
    return struct {
        lifecycle: SessionLifecycle,
        result: R,
    };
}

test "lifecycle / direction enums are distinct" {
    try std.testing.expect(@as(SessionLifecycle, .none) != .established);
    try std.testing.expect(@as(MessageDirection, .client_server) != .server_client);
}
