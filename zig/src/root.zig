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

/// The filterable-query layer: the regex-free filter engine + the streaming `FilterSink(Entry)` a
/// filterable handler pushes its records through (a method becomes filterable via `Builder.filterableMethod`,
/// which codegen emits for a spec method marked `filterable`). Consumers reach the value/option types as
/// `trpc.filter.FilterValue` etc.; the two most-used names are re-exported directly.
pub const filter = @import("filter.zig");
pub const FilterSink = filter.FilterSink;
pub const QueryOptions = filter.QueryOptions;

/// Raw-fd transfer (the sans-I/O contract): `TransferDirection`, the `FileTransfer` handle the transport
/// supplies, and the `Transfer` directive `dispatch` returns. The actual fd I/O is the transport's.
const transfer = @import("transfer.zig");
pub const TransferDirection = transfer.TransferDirection;
pub const FileTransfer = transfer.FileTransfer;
pub const Transfer = transfer.Transfer;

const protocol = @import("protocol.zig");
pub const Protocol = protocol.Protocol;
pub const Dispatched = protocol.Dispatched;

/// `Transport(S)` — the Io-aware pub/sub delivery layer (registry + `sendNotification` + `pollNotification`).
/// It consumes the core's `Dispatched.subscribe` directive and owns the mutable, Io-synchronized state, so
/// the `Protocol(S)` core stays sans-I/O and lock-free. Mirrors Python's `send_notification`/`poll_notification`.
const transport = @import("transport.zig");
pub const Transport = transport.Transport;
pub const NotifyError = transport.NotifyError;

const sink = @import("sink.zig");
pub const AuditSink = sink.AuditSink;
pub const AuditRecord = sink.AuditRecord;

/// The id-generation seam (the deterministic generator for tests is a consumer concern, like the
/// capturing audit sink — see the conformance suite). `uuid_len` is the buffer size a custom `IdGen`
/// writes into (a canonical UUID is 36 bytes).
pub const IdGen = @import("idgen.zig").IdGen;
pub const uuid_len = @import("idgen.zig").uuid_len;

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
    _ = @import("idgen.zig");
    _ = @import("envelope.zig");
    _ = @import("xdr_frame.zig");
    _ = @import("filter.zig");
    _ = @import("transfer.zig");
    _ = @import("method.zig");
    _ = @import("protocol.zig");
    _ = @import("transport.zig");
    // The A/B conformance suite is a separate consumer artifact (see zig/conformance/), not aggregated here.
}
