//! truenas_jsonrpc — a synchronous JSON-RPC 2.0 dispatch core (Zig port).
//!
//! The Python `truenas_pyjsonrpc` library and the repo-root `ARCHITECTURE.md` wire contract are the
//! normative reference. `dispatch` is a plain synchronous function (bytes in → bytes/none/transfer out);
//! concurrency and transports live in a later layer. Consumers reach the API namespace-qualified, e.g.
//! `const trpc = @import("truenas_jsonrpc"); trpc.Protocol(S)`.
const std = @import("std");

// ── Public API (curated re-exports) ──────────────────────────────────────────
pub const errors = @import("errors.zig");
pub const ErrorCode = errors.ErrorCode;
pub const JsonRpcError = errors.JsonRpcError;
pub const BuildError = errors.BuildError;

pub const types = @import("types.zig");
pub const SessionLifecycle = types.SessionLifecycle;
pub const MessageDirection = types.MessageDirection;
pub const AuthorizationResponse = types.AuthorizationResponse;
pub const RequestInfo = types.RequestInfo;
pub const ServerInfo = types.ServerInfo;
pub const SetupOutcome = types.SetupOutcome;

const session = @import("session.zig");
pub const Session = session.Session;
pub const RequestCtx = session.RequestCtx;

/// `Secret(T)` — wire-transparent wrapper marking a field secret for audit redaction.
pub const Secret = @import("meta.zig").Secret;

const method = @import("method.zig");
pub const MethodOpts = method.MethodOpts;

const protocol = @import("protocol.zig");
pub const Protocol = protocol.Protocol;
pub const Dispatched = protocol.Dispatched;

const sink = @import("sink.zig");
pub const AuditSink = sink.AuditSink;
pub const AuditRecord = sink.AuditRecord;

/// Test-support utilities for consumers writing conformance / A-B tests against this protocol
/// (e.g. the suite under `zig/conformance/`, which consumes this module like any downstream user).
pub const testing = struct {
    /// Structural, order-insensitive JSON equality over `std.json.Value`.
    pub const jsonEql = @import("json_eq.zig").eql;
};

// envelope is internal dispatch machinery; not re-exported.

test {
    // Aggregate every module's `test {}` blocks so `zig build test` runs them all.
    _ = @import("errors.zig");
    _ = @import("json_eq.zig");
    _ = @import("types.zig");
    _ = @import("session.zig");
    _ = @import("meta.zig");
    _ = @import("reflect.zig");
    _ = @import("sink.zig");
    _ = @import("envelope.zig");
    _ = @import("method.zig");
    _ = @import("protocol.zig");
    // The A/B conformance suite is a separate consumer artifact (see zig/conformance/), not aggregated here.
}
