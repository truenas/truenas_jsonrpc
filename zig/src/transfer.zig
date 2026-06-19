//! Raw-fd transfer — the sans-I/O contract. A transfer method lends its `transfer` callback exclusive
//! access to the connection's raw socket fd for a self-delimiting bulk stream (e.g. libzfs
//! `lzc_send`/`lzc_receive` for `zfs send`/`recv`), then resumes normal JSON-RPC. The dispatch core never
//! touches a socket: it authorizes, runs the method's `negotiate` callback, and emits a `Transfer`
//! DIRECTIVE carrying the `$/transferReady` envelope + a `complete` thunk. The (Io-aware) transport drives
//! the wire handshake (`$/transferReady` → `$/transferGo` → the raw stream) and supplies the concrete
//! `FileTransfer`; a conformance mock supplies a canned one. The actual fd-I/O helpers
//! (sendfile/splice/SCM_RIGHTS) land with the Zig transport — DEFERRED + non-normative, like the
//! `std.Io.net` server. Mirrors Python `truenas_pyjsonrpc/transfer.py`.
const std = @import("std");

/// Which way the bulk stream flows once the fd is handed over.
pub const TransferDirection = enum {
    /// The server PRODUCES and the client consumes (server writes the stream).
    download,
    /// The client PRODUCES and the server consumes (server reads the stream).
    upload,
    /// The wire spelling (matches Python `TransferDirection`'s StrEnum values).
    pub fn wire(self: TransferDirection) []const u8 {
        return switch (self) {
            .download => "download",
            .upload => "upload",
        };
    }
};

/// Exclusive handle to the connection's raw socket fd for one transfer, handed to a method's `transfer`
/// callback after the transport's wire handshake. The core defines only the contract; the (Io-aware)
/// transport supplies the real `fd` (and, later, the bulk-stream helpers), while a conformance mock
/// supplies a canned `fd`. The fd is blocking for the duration and is plaintext even over kTLS.
pub const FileTransfer = struct {
    /// The raw, blocking socket fd to read/write the stream on.
    fd: std.posix.fd_t,
    direction: TransferDirection,
    /// True iff the connection is AF_UNIX (required for `SCM_RIGHTS` fd passing).
    af_unix: bool,
    /// The `negotiate` interim — the `$/transferReady` `result` — as JSON. The producer's channel to tell
    /// the consumer about the stream (e.g. a DOWNLOAD reports its byte count so the client knows how much
    /// to read).
    result_json: []const u8,

    /// The raw fd to hand to libzfs / sendfile / splice / etc.
    pub fn fileno(self: *const FileTransfer) std.posix.fd_t {
        return self.fd;
    }
};

/// The directive `dispatch` returns for a transfer method (parallels `Dispatched.subscribe`). The transport
/// sends `ready` (the `$/transferReady` envelope), runs the handshake for `direction`, builds a concrete
/// `FileTransfer` from the connection's fd, then calls `complete(ft)` — which runs the `transfer` callback,
/// validates the result against the method's `Returns`, and yields the final response bytes to send.
pub const Transfer = struct {
    /// The request id (echoed in `ready` and the final response).
    rid: []const u8,
    direction: TransferDirection,
    /// An fd-pass method (`SCM_RIGHTS`) requires an AF_UNIX connection; the transport enforces it.
    af_unix: bool,
    /// The `$/transferReady` envelope JSON bytes the transport sends before the handshake.
    ready: []const u8,
    /// Erased `complete` (monomorphized in method.zig): runs the `transfer` callback over `ft`, validates
    /// `Returns`, and builds the final response bytes (arena-owned). The transport calls it post-handshake.
    complete_ctx: *anyopaque,
    complete_fn: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, ft: *const FileTransfer) ?[]const u8,

    pub fn complete(self: Transfer, arena: std.mem.Allocator, ft: *const FileTransfer) ?[]const u8 {
        return self.complete_fn(self.complete_ctx, arena, ft);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────────
test "TransferDirection wire spelling matches Python StrEnum" {
    try std.testing.expectEqualStrings("download", TransferDirection.download.wire());
    try std.testing.expectEqualStrings("upload", TransferDirection.upload.wire());
}

test "FileTransfer.fileno hands back the raw fd" {
    const ft: FileTransfer = .{ .fd = 7, .direction = .download, .af_unix = true, .result_json = "{}" };
    try std.testing.expectEqual(@as(std.posix.fd_t, 7), ft.fileno());
    try std.testing.expect(ft.af_unix);
}
