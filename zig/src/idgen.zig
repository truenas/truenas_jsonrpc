//! The `IdGen` seam — the library's injection point for the one non-deterministic id pub/sub puts on the
//! wire (the subscription id). Production is a UUIDv4: hand-rolled (Zig std ships no UUID type) from 16
//! random bytes, landing with the `std.Io` transport that carries the entropy source. Tests/conformance
//! inject a deterministic generator instead — a *consumer* concern, like the capturing audit sink lives
//! in the conformance app, not here — so the A/B golden's subscription ids stay reproducible. The seam is
//! held by value and mutated through `ctx`, so it composes with `*const Self` dispatch.
const std = @import("std");

/// A canonical UUID string is 36 bytes (8-4-4-4-12 hex with hyphens).
pub const uuid_len = 36;

/// Closure over an id source: writes the next id into `buf` and returns the written slice.
pub const IdGen = struct {
    ctx: *anyopaque,
    nextFn: *const fn (ctx: *anyopaque, buf: *[uuid_len]u8) []const u8,

    pub fn next(self: IdGen, buf: *[uuid_len]u8) []const u8 {
        return self.nextFn(self.ctx, buf);
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;

test "IdGen dispatches to the injected source and mutates it through ctx" {
    // A throwaway deterministic source — exactly how a test/conformance build supplies reproducible ids
    // (a downstream test owns this, the same way the conformance suite owns its capturing audit sink).
    const Seq = struct {
        n: u64 = 0,
        fn nextImpl(ctx: *anyopaque, buf: *[uuid_len]u8) []const u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.n += 1;
            return std.fmt.bufPrint(buf, "00000000-0000-4000-8000-{d:0>12}", .{self.n}) catch unreachable;
        }
    };
    var seq = Seq{};
    const ig = IdGen{ .ctx = @ptrCast(&seq), .nextFn = &Seq.nextImpl };
    var buf: [uuid_len]u8 = undefined;
    try testing.expectEqualStrings("00000000-0000-4000-8000-000000000001", ig.next(&buf));
    try testing.expectEqualStrings("00000000-0000-4000-8000-000000000002", ig.next(&buf));
    try testing.expect(@import("envelope.zig").isUuid(ig.next(&buf))); // a valid id the envelope accepts
}
