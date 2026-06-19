//! `Transport(S)` — the Io-aware pub/sub delivery layer (the direct port of Python `JSONRPCProtocol`'s
//! `_subscriptions` registry + `send_notification` + `_outbound` queue + `poll_notification`). It sits
//! *beside* the sans-I/O `Protocol(S)` core: the core stays lock-free and `*const`, returning a
//! `Dispatched.subscribe` directive; this layer consumes that directive (registers the subscription) and
//! owns the mutable, Io-synchronized state. In 0.16 a blocking lock *requires* an `Io`, so all shared
//! state lives here, never in the core.
//!
//! Design (faithful to Python): ONE unbounded outbound FIFO of session-tagged notifications, guarded by an
//! `Io.Mutex` + `Io.Condition`. `sendNotification` validates+encodes the payload ONCE (outside the lock,
//! against the topic's `Notifies` schema) then fans out one entry per subscriber under a brief lock;
//! `pollNotification` drains `(session, bytes)` for the application's writer thread to route to the wire.
//! Unbounded append never blocks the publisher (matching Python's `deque`) — no slow-consumer back-pressure.
const std = @import("std");
const session_mod = @import("session.zig");
const protocol_mod = @import("protocol.zig");
const method_mod = @import("method.zig");
const types = @import("types.zig");

pub const NotifyError = error{
    UnknownTopic, // no method by that name
    NotATopic, // the method exists but isn't a server_client topic (Python's ValueError)
    InvalidPayload, // payload doesn't validate against the topic's Notifies (Python's ValidationError)
    OutOfMemory,
    EncodeFailed,
};

pub fn Transport(comptime S: type) type {
    const Session = session_mod.Session(S);
    const Proto = protocol_mod.Protocol(S);

    return struct {
        const Self = @This();

        /// A registered subscription to a topic (Python `Subscription`): its minted id + the connection's
        /// session (the routing target). `sub_id` is owned by `gpa`; `session` is borrowed (the app keeps
        /// it alive for the connection's lifetime, then calls `unsubscribeAll` on close).
        pub const Subscription = struct {
            sub_id: []const u8,
            session: *Session,
        };

        /// One queued outbound notification (Python `_Pending`): the target connection + the wire bytes,
        /// plus the originating `request_id` for a `$/progress` entry (null for a pub/sub notification) so
        /// completion can purge a request's still-queued progress. `data`/`request_id` are owned by `gpa`.
        pub const Pending = struct {
            session: *Session,
            data: []const u8,
            request_id: ?[]const u8 = null,
        };

        /// An in-flight request (Python's `_inflight[rid]`): its routing session, whether it has emitted any
        /// progress (so completion can skip the purge scan), and the shared cooperative-cancel flag (a
        /// gpa-owned atomic, allocated only for a `cancellable` method; freed at `end`).
        const Inflight = struct {
            session: *Session,
            emitted: bool = false,
            cancel: ?*std.Io.Event = null,
        };

        gpa: std.mem.Allocator,
        /// The sans-I/O core — read-only here (look up a topic + its `Notifies` encoder). Must outlive `self`.
        proto: *const Proto,
        /// topic name → its subscriptions. Keys borrow the core's long-lived method names (no dupe).
        registry: std.StringHashMap(std.ArrayList(Subscription)),
        /// In-flight id-bearing requests (for `$/progress` correlation + `$/cancelRequest` later). Keys are
        /// `gpa`-owned dupes of the request id, registered at `begin` and freed at `end`.
        inflight: std.StringHashMap(Inflight),
        /// Unbounded FIFO of notifications, drained front-first via `head` (reclaimed when fully drained).
        outbound: std.ArrayList(Pending),
        head: usize = 0,
        mutex: std.Io.Mutex = .init,
        cond: std.Io.Condition = .init,

        pub fn init(gpa: std.mem.Allocator, proto: *const Proto) Self {
            return .{
                .gpa = gpa,
                .proto = proto,
                .registry = std.StringHashMap(std.ArrayList(Subscription)).init(gpa),
                .inflight = std.StringHashMap(Inflight).init(gpa),
                .outbound = .empty,
            };
        }

        /// Free a drained `Pending` (its `data` + any `request_id`) — call after sending/comparing it.
        pub fn freeNotification(self: *Self, p: Pending) void {
            self.gpa.free(p.data);
            if (p.request_id) |q| self.gpa.free(q);
        }

        /// Free all owned memory. Teardown is single-threaded by contract (no concurrent access), so it
        /// takes no `io` / no lock — undrained notifications + every subscription id are released here.
        pub fn deinit(self: *Self) void {
            var it = self.registry.iterator();
            while (it.next()) |entry| {
                for (entry.value_ptr.items) |sub| self.gpa.free(sub.sub_id);
                entry.value_ptr.deinit(self.gpa);
            }
            self.registry.deinit();
            for (self.outbound.items[self.head..]) |p| self.freeNotification(p);
            self.outbound.deinit(self.gpa);
            // Normally empty (every begin has a matching end), but free any leftover in-flight keys + flags.
            var iit = self.inflight.iterator();
            while (iit.next()) |e| {
                if (e.value_ptr.cancel) |flag| self.gpa.destroy(flag);
                self.gpa.free(e.key_ptr.*);
            }
            self.inflight.deinit();
        }

        /// Apply a `Dispatched.subscribe` directive from the core: register the subscription (its minted
        /// `sub_id` + the connection's `session`) under the topic. The core already validated/gated/
        /// authorized/minted; this only records it (Python's `_subscriptions[method][sub_id] = ...`).
        pub fn applySubscribe(self: *Self, io: std.Io, dir: protocol_mod.Dispatched.Subscribe, session: *Session) NotifyError!void {
            const sub_id = self.gpa.dupe(u8, dir.sub_id) catch return error.OutOfMemory;
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            const gop = self.registry.getOrPut(dir.topic) catch {
                self.gpa.free(sub_id);
                return error.OutOfMemory;
            };
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            gop.value_ptr.append(self.gpa, .{ .sub_id = sub_id, .session = session }) catch {
                self.gpa.free(sub_id);
                return error.OutOfMemory;
            };
        }

        /// Publish `payload` to every subscriber of a `server_client` topic (Python `send_notification`):
        /// validate+encode the `{jsonrpc, method, params}` wire ONCE against the topic's `Notifies`
        /// (outside the lock), then fan out one outbound entry per subscriber under a brief lock and wake
        /// a blocked poller. No subscribers → no-op. A bad payload → `InvalidPayload` (server-side misuse).
        pub fn sendNotification(self: *Self, io: std.Io, method: []const u8, payload: anytype) NotifyError!void {
            const m = self.proto.methods.get(method) orelse return error.UnknownTopic;
            if (m.direction != .server_client) return error.NotATopic;

            // Encode once, off the lock (matches Python encoding before taking `_cond`).
            var arena_state = std.heap.ArenaAllocator.init(self.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const payload_bytes = method_mod.serializeToBytes(arena, @TypeOf(payload), payload) catch return error.EncodeFailed;
            const payload_value = std.json.parseFromSliceLeaky(std.json.Value, arena, payload_bytes, .{}) catch return error.EncodeFailed;
            const wire = m.encodeNotification(arena, payload_value) orelse return error.InvalidPayload;

            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            const subs = self.registry.getPtr(method) orelse return; // never subscribed → no-op
            if (subs.items.len == 0) return;
            for (subs.items) |sub| {
                const data = self.gpa.dupe(u8, wire) catch return error.OutOfMemory; // each entry owns its bytes
                self.outbound.append(self.gpa, .{ .session = sub.session, .data = data, .request_id = null }) catch return error.OutOfMemory;
            }
            self.cond.signal(io);
        }

        /// Drain one queued notification as `(session, wire_bytes)` for the application's writer thread
        /// (Python `poll_notification`). `block = false` returns null immediately when empty; `block = true`
        /// waits on the condition. The returned `Pending.data` is `gpa`-owned — the CALLER frees it.
        pub fn pollNotification(self: *Self, io: std.Io, block: bool) ?Pending {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            while (self.head == self.outbound.items.len) {
                if (!block) return null;
                self.cond.waitUncancelable(io, &self.mutex);
            }
            const entry = self.outbound.items[self.head];
            self.head += 1;
            if (self.head == self.outbound.items.len) { // fully drained → reclaim the backing storage
                self.outbound.clearRetainingCapacity();
                self.head = 0;
            }
            return entry;
        }

        /// Drop one subscription by id (Python `unsubscribe`). Returns true if it existed.
        pub fn unsubscribe(self: *Self, io: std.Io, sub_id: []const u8) bool {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            return self.unsubscribeLocked(sub_id);
        }

        /// Drop one subscription by id; the caller holds the lock (shared by `unsubscribe` + `trackCancel`).
        fn unsubscribeLocked(self: *Self, sub_id: []const u8) bool {
            var it = self.registry.iterator();
            while (it.next()) |entry| {
                const subs = entry.value_ptr;
                for (subs.items, 0..) |sub, i| {
                    if (std.mem.eql(u8, sub.sub_id, sub_id)) {
                        self.gpa.free(sub.sub_id);
                        _ = subs.orderedRemove(i);
                        return true;
                    }
                }
            }
            return false;
        }

        /// Drop every subscription owned by `session` (Python `unsubscribe_all`) — the app calls this on
        /// connection close so subscriptions don't leak. Matches by connection identity (the `Session`
        /// pointer; one session per connection ⇔ Python's `session_uuid` match). Returns the count removed.
        pub fn unsubscribeAll(self: *Self, io: std.Io, session: *Session) usize {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            var removed: usize = 0;
            var it = self.registry.iterator();
            while (it.next()) |entry| {
                const subs = entry.value_ptr;
                var i: usize = 0;
                while (i < subs.items.len) {
                    if (subs.items[i].session == session) {
                        self.gpa.free(subs.items[i].sub_id);
                        _ = subs.orderedRemove(i);
                        removed += 1;
                    } else i += 1;
                }
            }
            return removed;
        }

        // ── $/progress: in-flight tracking + the back-channel the core's Tracker drives ──────────────

        /// Dispatch with progress tracking: hands the core a `Tracker` (pointing back here) so an id-bearing
        /// request is registered in-flight before its handler runs and a `ProgressSink` is wired into the
        /// `RequestCtx`; on completion the request is dropped and its still-queued progress purged. Use this
        /// (not the core's bare `dispatch`) when handlers emit `$/progress`. Returns the same `Dispatched`.
        pub fn dispatchTracked(self: *Self, io: std.Io, reply_alloc: std.mem.Allocator, wire: []const u8, session: *Session) protocol_mod.Dispatched {
            const tracker: protocol_mod.Tracker = .{
                .ctx = @ptrCast(self),
                .io = io,
                .begin_fn = &trackBegin,
                .end_fn = &trackEnd,
                .resolve_fn = &trackResolve,
                .act_fn = &trackAct,
            };
            return self.proto.dispatchWith(reply_alloc, wire, session, tracker);
        }

        /// Tracker.begin: register `rid` in-flight (capturing its routing session; minting a cooperative-
        /// cancel flag when the method is `cancellable`) and return the request's per-request handles. On
        /// OOM the registration is skipped but a sink is still returned (its `emit` then finds no in-flight
        /// entry → drops, the safe degradation); the cancel flag is null (→ a cancel sees not-cancellable).
        fn trackBegin(ctx: *anyopaque, io: std.Io, rid: []const u8, session_opaque: *anyopaque, cancellable: bool) protocol_mod.Tracked {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const session: *Session = @ptrCast(@alignCast(session_opaque));
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            var flag: ?*std.Io.Event = null;
            if (self.gpa.dupe(u8, rid)) |key| {
                const gop = self.inflight.getOrPut(key) catch {
                    self.gpa.free(key);
                    return .{ .progress = progressSink(self, io), .cancel = null };
                };
                if (gop.found_existing) {
                    self.gpa.free(key);
                } else {
                    // Mint the cancel event only for a cancellable method (Python's per-request Event).
                    if (cancellable) {
                        if (self.gpa.create(std.Io.Event)) |f| {
                            f.* = .unset;
                            flag = f;
                        } else |_| {}
                    }
                    gop.value_ptr.* = .{ .session = session, .cancel = flag };
                }
            } else |_| {}
            return .{ .progress = progressSink(self, io), .cancel = flag };
        }

        fn progressSink(self: *Self, io: std.Io) types.ProgressSink {
            return .{ .ctx = @ptrCast(self), .io = io, .emit_fn = &emitProgress };
        }

        /// ProgressSink.emit: enqueue a `$/progress` notification for an in-flight `rid`. Returns false (a
        /// drop) when the request is no longer in-flight — Python `_update_progress`'s `if rid not in
        /// _inflight: return`. Encoded inside the lock (cold path); the bytes + a `request_id` copy are
        /// `gpa`-owned (the `request_id` lets completion purge this entry if it's still queued).
        fn emitProgress(ctx: *anyopaque, io: std.Io, rid: []const u8, update: types.ProgressUpdate) bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            const entry = self.inflight.getPtr(rid) orelse return false; // completed → dropped
            const data = encodeProgress(self.gpa, rid, update) catch return false;
            const req_id = self.gpa.dupe(u8, rid) catch {
                self.gpa.free(data);
                return false;
            };
            self.outbound.append(self.gpa, .{ .session = entry.session, .data = data, .request_id = req_id }) catch {
                self.gpa.free(data);
                self.gpa.free(req_id);
                return false;
            };
            entry.emitted = true;
            self.cond.signal(io);
            return true;
        }

        /// Tracker.end: drop `rid` from in-flight, free its cancel flag, and (if it emitted progress) purge
        /// its still-queued notifications (Python `_complete`: the response supersedes them). Already-drained
        /// progress is gone from the queue, so it's delivered; only undrained progress is dropped. Freeing
        /// the cancel flag here is safe — the handler has returned (it no longer reads it), and a concurrent
        /// `$/cancelRequest` only touches it while holding this lock + while the entry exists.
        fn trackEnd(ctx: *anyopaque, io: std.Io, rid: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            if (self.inflight.fetchRemove(rid)) |kv| {
                if (kv.value.emitted) self.purgeLocked(rid);
                if (kv.value.cancel) |flag| self.gpa.destroy(flag);
                self.gpa.free(kv.key);
            }
        }

        /// Tracker.resolve (`$/cancelRequest`, phase 1): find `target_id` among the in-flight requests then
        /// the subscriptions and return its OWNING session (for the core's session-scoped authz), or null.
        /// The session pointer is stable (it outlives the request/subscription), so the core may hold it
        /// across the lock release; the target itself may complete before `act` runs (re-resolved there).
        fn trackResolve(ctx: *anyopaque, io: std.Io, target_id: []const u8) ?*anyopaque {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            if (self.inflight.getPtr(target_id)) |entry| return @ptrCast(entry.session);
            if (self.findSubscriptionSession(target_id)) |s| return @ptrCast(s);
            return null;
        }

        /// Tracker.act (`$/cancelRequest`, phase 2, post-authz): re-resolve `target_id` and act — set a
        /// cancellable request's cooperative flag (the handler polls it via `ctx.cancelled()`), or drop a
        /// subscription (a wire-level unsubscribe). Mirrors Python `_authorize_and_cancel`'s action half.
        /// For a cancelled request the lock is released and the optional cancellation callback runs (an
        /// error → `.handler_error` → INTERNAL_ERROR); `canceller` is the cancelling session.
        fn trackAct(ctx: *anyopaque, io: std.Io, target_id: []const u8, canceller_opaque: *anyopaque) protocol_mod.CancelOutcome {
            const self: *Self = @ptrCast(@alignCast(ctx));
            {
                self.mutex.lockUncancelable(io);
                defer self.mutex.unlock(io);
                if (self.inflight.getPtr(target_id)) |entry| {
                    const flag = entry.cancel orelse return .not_cancellable; // in flight, but not cancellable
                    flag.set(io); // the cooperative signal: wakes a waitForCancel + flips isSet() for pollers
                    // fall through (lock released) to the cancellation callback below
                } else {
                    return if (self.unsubscribeLocked(target_id)) .ok else .not_found; // subscription / unknown
                }
            }
            // A cancellable request was signalled — run the active-abort callback off the lock (Python
            // calls it after the cooperative event.set, outside `_cond`); its error → INTERNAL_ERROR.
            if (self.proto.cancellation_handler) |ch| {
                const canceller: *Session = @ptrCast(@alignCast(canceller_opaque));
                if (!ch.call(ch.ctx, target_id, canceller)) return .handler_error;
            }
            return .ok;
        }

        /// Find a subscription by id and return its session; the caller holds the lock.
        fn findSubscriptionSession(self: *Self, sub_id: []const u8) ?*Session {
            var it = self.registry.iterator();
            while (it.next()) |entry| {
                for (entry.value_ptr.items) |sub| {
                    if (std.mem.eql(u8, sub.sub_id, sub_id)) return sub.session;
                }
            }
            return null;
        }

        /// Compact `outbound[head..]`, freeing entries whose `request_id == rid` (caller holds the lock).
        fn purgeLocked(self: *Self, rid: []const u8) void {
            var w = self.head;
            var r = self.head;
            while (r < self.outbound.items.len) : (r += 1) {
                const p = self.outbound.items[r];
                if (p.request_id) |q| if (std.mem.eql(u8, q, rid)) {
                    self.freeNotification(p);
                    continue;
                };
                self.outbound.items[w] = p;
                w += 1;
            }
            self.outbound.shrinkRetainingCapacity(w);
            if (self.head == self.outbound.items.len) { // nothing left after head → reclaim
                self.outbound.clearRetainingCapacity();
                self.head = 0;
            }
        }

        /// Build the `{jsonrpc, method:"$/progress", params:{id, percent?, description?, extra?}}` wire
        /// (gpa-owned). Absent optional fields are omitted from `params` (Python builds the dict the same way).
        fn encodeProgress(gpa: std.mem.Allocator, rid: []const u8, update: types.ProgressUpdate) ![]u8 {
            var arena_state = std.heap.ArenaAllocator.init(gpa);
            defer arena_state.deinit();
            const a = arena_state.allocator();
            var params: std.json.ObjectMap = .empty;
            try params.put(a, "id", .{ .string = rid });
            if (update.percent) |pct| try params.put(a, "percent", .{ .float = pct });
            if (update.description) |d| try params.put(a, "description", .{ .string = d });
            if (update.extra) |e| try params.put(a, "extra", e);
            var obj: std.json.ObjectMap = .empty;
            try obj.put(a, "jsonrpc", .{ .string = "2.0" });
            try obj.put(a, "method", .{ .string = "$/progress" });
            try obj.put(a, "params", .{ .object = params });
            return std.json.Stringify.valueAlloc(gpa, std.json.Value{ .object = obj }, .{});
        }
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;
const json_eq = @import("json_eq.zig");

const SubArgs = struct { channel: []const u8 };
const AlertEvent = struct { level: []const u8, text: []const u8 };
const NoArgs = struct {};
const WorkResult = struct { id: i64, name: []const u8 };
const work_uid = "123e4567-e89b-12d3-a456-426614174000";
const work_wire = "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ work_uid ++ "\",\"method\":\"work\",\"params\":{}}";
const cancel_uid = "99999999-9999-4999-8999-999999999999"; // the $/cancelRequest envelope id
fn cancelWire(comptime target: []const u8) []const u8 {
    return "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ cancel_uid ++ "\",\"method\":\"$/cancelRequest\",\"params\":{\"target_id\":\"" ++ target ++ "\"}}";
}
const cancel_work_wire = cancelWire(work_uid); // cancel the `work` request by its id
const cancel_sub_wire = cancelWire("00000000-0000-4000-8000-000000000001"); // cancel the FixedIdGen sub_id
const cancel_unknown_wire = cancelWire("00000000-0000-4000-8000-0000000000ff"); // a target that never exists

fn buildPubSub(gpa: std.mem.Allocator, seq: *Seq) !protocol_mod.Protocol(void) {
    var b = protocol_mod.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.subscription("alerts.subscribe", SubArgs, AlertEvent, .{});
    b.idGen(.{ .ctx = @ptrCast(seq), .nextFn = &Seq.nextImpl });
    return b.build();
}

// A deterministic id source (a consumer concern, inline for the test).
const Seq = struct {
    n: u64 = 0,
    fn nextImpl(ctx: *anyopaque, buf: *[36]u8) []const u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.n += 1;
        return std.fmt.bufPrint(buf, "00000000-0000-4000-8000-{d:0>12}", .{self.n}) catch unreachable;
    }
};

/// Subscribe through the real dispatch path and apply the resulting directive to the transport.
fn subscribeVia(proto: *protocol_mod.Protocol(void), tr: *Transport(void), io: std.Io, reply_alloc: std.mem.Allocator, sess: *session_mod.Session(void), wire: []const u8) !void {
    switch (proto.dispatch(reply_alloc, wire, sess)) {
        .subscribe => |dir| try tr.applySubscribe(io, dir, sess),
        else => return error.ExpectedSubscribe,
    }
}

test "transport: subscribe → publish fans out in order; unsubscribeAll makes publish a no-op" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    var seq = Seq{};
    var proto = try buildPubSub(testing.allocator, &seq);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    const uid = "123e4567-e89b-12d3-a456-426614174000";
    var sess = proto.newSession(null);
    try subscribeVia(&proto, &tr, io, arena, &sess, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"alerts.subscribe\",\"params\":{\"channel\":\"pool\"}}");

    // publish two payloads (one typed struct, one anonymous struct) → two outbound notifications, in order
    try tr.sendNotification(io, "alerts.subscribe", AlertEvent{ .level = "warn", .text = "pool degraded" });
    try tr.sendNotification(io, "alerts.subscribe", .{ .level = "info", .text = "scrub done" });

    try expectNextNotification(&tr, io, arena, &sess, "{\"jsonrpc\":\"2.0\",\"method\":\"alerts.subscribe\",\"params\":{\"level\":\"warn\",\"text\":\"pool degraded\"}}");
    try expectNextNotification(&tr, io, arena, &sess, "{\"jsonrpc\":\"2.0\",\"method\":\"alerts.subscribe\",\"params\":{\"level\":\"info\",\"text\":\"scrub done\"}}");
    try testing.expect(tr.pollNotification(io, false) == null); // fully drained

    // unsubscribeAll → a subsequent publish is a no-op (nothing queued)
    try testing.expectEqual(@as(usize, 1), tr.unsubscribeAll(io, &sess));
    try tr.sendNotification(io, "alerts.subscribe", AlertEvent{ .level = "x", .text = "y" });
    try testing.expect(tr.pollNotification(io, false) == null);
}

test "transport: unknown topic, non-topic method, and bad payload are rejected" {
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();
    var seq = Seq{};
    var proto = try buildPubSub(testing.allocator, &seq);
    defer proto.deinit();
    var api = struct {
        fn add(_: *@This(), a: struct { x: i64 }, _: *session_mod.RequestCtx(void)) !struct { y: i64 } {
            return .{ .y = a.x };
        }
    }{};
    // add a client_server method so we can prove NotATopic
    var b = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.subscription("alerts.subscribe", SubArgs, AlertEvent, .{});
    try b.method("add", &api, @TypeOf(api).add, .{});
    b.idGen(.{ .ctx = @ptrCast(&seq), .nextFn = &Seq.nextImpl });
    var proto2 = b.build();
    defer proto2.deinit();
    var tr = Transport(void).init(testing.allocator, &proto2);
    defer tr.deinit();

    try testing.expectError(error.UnknownTopic, tr.sendNotification(io, "nope", AlertEvent{ .level = "a", .text = "b" }));
    try testing.expectError(error.NotATopic, tr.sendNotification(io, "add", AlertEvent{ .level = "a", .text = "b" }));
    // a payload missing a required `notifies` field → InvalidPayload (no subscribers needed; validated first)
    try testing.expectError(error.InvalidPayload, tr.sendNotification(io, "alerts.subscribe", .{ .level = "warn" }));
}

test "transport: a concurrent producer wakes a blocking poll (Io.Condition handshake)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var t: std.Io.Threaded = .init(testing.allocator, .{});
    defer t.deinit();
    const io = t.io();

    var seq = Seq{};
    var proto = try buildPubSub(testing.allocator, &seq);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    const uid = "123e4567-e89b-12d3-a456-426614174000";
    var sess = proto.newSession(null);
    try subscribeVia(&proto, &tr, io, arena, &sess, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ uid ++ "\",\"method\":\"alerts.subscribe\",\"params\":{\"channel\":\"pool\"}}");

    // Publish from a concurrent task; the main task blocks in pollNotification until the signal arrives.
    const Pub = struct {
        fn go(trp: *Transport(void), pio: std.Io) void {
            trp.sendNotification(pio, "alerts.subscribe", AlertEvent{ .level = "info", .text = "hi" }) catch {};
        }
    };
    var fut = io.concurrent(Pub.go, .{ &tr, io }) catch |e| return e;
    defer _ = fut.await(io);

    const got = tr.pollNotification(io, true).?; // blocks until the producer signals
    defer tr.freeNotification(got);
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, got.data, .{});
    const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"jsonrpc\":\"2.0\",\"method\":\"alerts.subscribe\",\"params\":{\"level\":\"info\",\"text\":\"hi\"}}", .{});
    try testing.expect(json_eq.eql(v, exp));
}

// ── $/progress (mirrors Python tests/test_notifications.py) ───────────────────

fn buildWork(gpa: std.mem.Allocator, svc: anytype) !protocol_mod.Protocol(void) {
    var b = protocol_mod.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.method("work", svc, @TypeOf(svc.*).work, .{});
    return b.build();
}

test "progress: enqueued during a handler, purged on completion when undrained" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    // A handler that emits two progress updates, then records the count it observed.
    const Work = struct {
        observed: u32 = 99,
        fn work(self: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
            ctx.updateProgress(.{ .percent = 10 });
            ctx.updateProgress(.{ .percent = 90 });
            self.observed = ctx.count;
            return .{ .id = 1, .name = "x" };
        }
    };
    var svc = Work{};
    var proto = try buildWork(testing.allocator, &svc);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    switch (tr.dispatchTracked(io, arena, work_wire, &sess)) {
        .reply => {},
        else => try testing.expect(false),
    }
    try testing.expectEqual(@as(u32, 2), svc.observed); // both were enqueued (count incremented)...
    try testing.expect(tr.pollNotification(io, false) == null); // ...then purged at completion
    try testing.expectEqual(@as(usize, 0), tr.inflight.count()); // in-flight registry cleared
}

test "progress: a notification (no id) handler's updateProgress is a no-op" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    const Work = struct {
        observed: u32 = 99,
        fn work(self: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
            ctx.updateProgress(.{ .percent = 10 }); // no id to correlate → dropped
            self.observed = ctx.count;
            return .{ .id = 1, .name = "x" };
        }
    };
    var svc = Work{};
    var proto = try buildWork(testing.allocator, &svc);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    try testing.expect(tr.dispatchTracked(io, arena, "{\"jsonrpc\":\"2.0\",\"method\":\"work\",\"params\":{}}", &sess) == .none);
    try testing.expectEqual(@as(u32, 0), svc.observed); // never enqueued
    try testing.expect(tr.pollNotification(io, false) == null);
    try testing.expectEqual(@as(usize, 0), tr.inflight.count()); // a notification is never registered
}

test "progress: emitted after the request completed is dropped" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    // The handler captures its sink + a durable copy of the id, but emits nothing during dispatch.
    const Cap = struct { sink: ?types.ProgressSink = null, rid: ?[]const u8 = null };
    const Work = struct {
        cap: *Cap,
        dupe_into: std.mem.Allocator,
        fn work(self: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
            self.cap.sink = ctx.progress;
            self.cap.rid = self.dupe_into.dupe(u8, ctx.id.?) catch null;
            return .{ .id = 1, .name = "x" };
        }
    };
    var cap = Cap{};
    var svc = Work{ .cap = &cap, .dupe_into = arena };
    var proto = try buildWork(testing.allocator, &svc);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    _ = tr.dispatchTracked(io, arena, work_wire, &sess); // request completes → end() drops it from in-flight
    try testing.expect(cap.sink != null and cap.rid != null);
    try testing.expect(!cap.sink.?.emit(cap.rid.?, .{ .percent = 99 })); // no longer in-flight → dropped (false)
    try testing.expect(tr.pollNotification(io, false) == null);
}

test "progress: delivered live (correct wire) when drained before completion" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init(testing.allocator, .{});
    defer t.deinit();
    const io = t.io();

    // The handler emits one progress update, then spins until the main task signals it has drained it —
    // so the progress leaves the queue before completion and is NOT purged (mirrors Python's threaded test).
    const Shared = struct { proceed: std.atomic.Value(bool) = .init(false) };
    var shared = Shared{};
    const Work = struct {
        sh: *Shared,
        fn work(self: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
            ctx.updateProgress(.{ .percent = 50, .description = "half" });
            while (!self.sh.proceed.load(.acquire)) std.atomic.spinLoopHint();
            return .{ .id = 1, .name = "x" };
        }
    };
    var svc = Work{ .sh = &shared };
    var proto = try buildWork(testing.allocator, &svc);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    // Run dispatch concurrently (its own reply_alloc, freed in-task — no arena shared across threads).
    const Task = struct {
        fn go(trp: *Transport(void), pio: std.Io, ra: std.mem.Allocator, s: *session_mod.Session(void)) void {
            switch (trp.dispatchTracked(pio, ra, work_wire, s)) {
                .reply => |b| ra.free(b),
                else => {},
            }
        }
    };
    var fut = io.concurrent(Task.go, .{ &tr, io, testing.allocator, &sess }) catch |e| return e;
    defer _ = fut.await(io);

    const p = tr.pollNotification(io, true).?; // blocks until the handler emits
    defer tr.freeNotification(p);
    shared.proceed.store(true, .release); // let the handler finish (its end() now purges nothing)
    try testing.expect(p.session == &sess);
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, p.data, .{});
    const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"jsonrpc\":\"2.0\",\"method\":\"$/progress\",\"params\":{\"id\":\"" ++ work_uid ++ "\",\"percent\":50,\"description\":\"half\"}}", .{});
    try testing.expect(json_eq.eql(v, exp));
}

test "progress: the in-flight registry is cleared even when the handler errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    const Work = struct {
        fn work(_: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
            return ctx.fail(.request_failed, "boom", null);
        }
    };
    var svc = Work{};
    var proto = try buildWork(testing.allocator, &svc);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    switch (tr.dispatchTracked(io, arena, work_wire, &sess)) {
        .reply => {}, // an error envelope
        else => try testing.expect(false),
    }
    try testing.expectEqual(@as(usize, 0), tr.inflight.count()); // end() (≈ Python's finally) always runs
}

// ── $/cancelRequest target resolution + cooperative cancel (mirrors tests/test_cancel.py) ─────

fn expectReply(arena: std.mem.Allocator, bytes: []const u8, expected_json: []const u8) !void {
    const got = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
    const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, expected_json, .{});
    try testing.expect(json_eq.eql(got, exp));
}

/// True if `bytes` is a `{... "result": true ...}` envelope (parsed in a scratch arena).
fn replyIsResultTrue(gpa: std.mem.Allocator, bytes: []const u8) bool {
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const v = std.json.parseFromSliceLeaky(std.json.Value, a.allocator(), bytes, .{}) catch return false;
    if (v != .object) return false;
    const r = v.object.get("result") orelse return false;
    return r == .bool and r.bool;
}

/// The `error.code` of a `bytes` envelope, or null if it isn't an error (parsed in a scratch arena).
fn replyErrorCode(gpa: std.mem.Allocator, bytes: []const u8) ?i64 {
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const v = std.json.parseFromSliceLeaky(std.json.Value, a.allocator(), bytes, .{}) catch return null;
    if (v != .object) return null;
    const e = v.object.get("error") orelse return null;
    if (e != .object) return null;
    const c = e.object.get("code") orelse return null;
    return if (c == .integer) c.integer else null;
}

test "cancel: a subscription target is dropped (wire-level unsubscribe) → result true" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    var seq = Seq{};
    var proto = try buildPubSub(testing.allocator, &seq);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    try subscribeVia(&proto, &tr, io, arena, &sess, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ work_uid ++ "\",\"method\":\"alerts.subscribe\",\"params\":{\"channel\":\"pool\"}}");
    switch (tr.dispatchTracked(io, arena, cancel_sub_wire, &sess)) {
        .reply => |b| try expectReply(arena, b, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ cancel_uid ++ "\",\"result\":true}"),
        else => try testing.expect(false),
    }
    // dropped server-side → a publish is now a no-op
    try tr.sendNotification(io, "alerts.subscribe", AlertEvent{ .level = "x", .text = "y" });
    try testing.expect(tr.pollNotification(io, false) == null);
}

test "cancel: an unknown target via the transport → REQUEST_FAILED" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();
    var seq = Seq{};
    var proto = try buildPubSub(testing.allocator, &seq);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();
    var sess = proto.newSession(null);
    switch (tr.dispatchTracked(io, arena, cancel_unknown_wire, &sess)) {
        .reply => |b| try expectReply(arena, b, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ cancel_uid ++ "\",\"error\":{\"code\":-32803,\"message\":\"Request failed\"}}"),
        else => try testing.expect(false),
    }
}

// A handler that cancels its OWN in-flight request inline (its id is registered between begin and end),
// so the in-flight cancel paths are exercised deterministically, single-threaded (no concurrency needed).
const SelfCancel = struct {
    tr: *Transport(void) = undefined,
    io: std.Io,
    ra: std.mem.Allocator,
    cancel_code: i64 = 0, // 0 = the self-cancel returned a result (not an error)
    fn run(self: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
        switch (self.tr.dispatchTracked(self.io, self.ra, cancel_work_wire, ctx.sess)) {
            .reply => |b| self.cancel_code = replyErrorCode(self.ra, b) orelse 0,
            else => {},
        }
        try ctx.raiseIfCancelled(); // raises REQUEST_CANCELLED iff the cancel set the flag
        return .{ .id = 1, .name = "ran-to-completion" };
    }
};

test "cancel: a cancellable in-flight request — flag set, handler raises REQUEST_CANCELLED" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    var svc = SelfCancel{ .io = io, .ra = arena };
    var b = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("work", &svc, SelfCancel.run, .{ .cancellable = true });
    var proto = b.build();
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();
    svc.tr = &tr;

    var sess = proto.newSession(null);
    switch (tr.dispatchTracked(io, arena, work_wire, &sess)) {
        .reply => |bts| try expectReply(arena, bts, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ work_uid ++ "\",\"error\":{\"code\":-32800,\"message\":\"Request cancelled\"}}"),
        else => try testing.expect(false),
    }
    try testing.expectEqual(@as(i64, 0), svc.cancel_code); // the self-cancel returned {result:true}
    try testing.expectEqual(@as(usize, 0), tr.inflight.count()); // in-flight + flag cleaned up at end
}

test "cancel: an in-flight non-cancellable request → REQUEST_FAILED; the handler runs on" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    var svc = SelfCancel{ .io = io, .ra = arena };
    var b = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("work", &svc, SelfCancel.run, .{}); // NOT cancellable
    var proto = b.build();
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();
    svc.tr = &tr;

    var sess = proto.newSession(null);
    // The cancel fails (not cancellable), the flag is never set, so the handler runs to completion.
    switch (tr.dispatchTracked(io, arena, work_wire, &sess)) {
        .reply => |bts| try expectReply(arena, bts, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ work_uid ++ "\",\"result\":{\"id\":1,\"name\":\"ran-to-completion\"}}"),
        else => try testing.expect(false),
    }
    try testing.expectEqual(@as(i64, -32803), svc.cancel_code); // the self-cancel got REQUEST_FAILED
}

test "cancel: cooperative cancel across threads (handler blocks until cancelled, then raises)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init(testing.allocator, .{});
    defer t.deinit();
    const io = t.io();

    const Shared = struct { started: std.atomic.Value(bool) = .init(false) };
    var shared = Shared{};
    const Slow = struct {
        sh: *Shared,
        fn slow(self: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
            self.sh.started.store(true, .release);
            while (!ctx.cancelled()) std.atomic.spinLoopHint(); // block until $/cancelRequest sets the flag
            try ctx.raiseIfCancelled(); // → REQUEST_CANCELLED
            return .{ .id = 1, .name = "unreached" };
        }
    };
    var svc = Slow{ .sh = &shared };
    var b = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("work", &svc, Slow.slow, .{ .cancellable = true });
    var proto = b.build();
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    var code = std.atomic.Value(i64).init(0);
    const Task = struct {
        fn go(trp: *Transport(void), pio: std.Io, ra: std.mem.Allocator, s: *session_mod.Session(void), out: *std.atomic.Value(i64)) void {
            switch (trp.dispatchTracked(pio, ra, work_wire, s)) {
                .reply => |bb| {
                    out.store(replyErrorCode(ra, bb) orelse 0, .release);
                    ra.free(bb);
                },
                else => {},
            }
        }
    };
    var fut = io.concurrent(Task.go, .{ &tr, io, testing.allocator, &sess, &code }) catch |e| return e;
    defer _ = fut.await(io);

    while (!shared.started.load(.acquire)) std.atomic.spinLoopHint(); // wait until the request is in-flight
    switch (tr.dispatchTracked(io, arena, cancel_work_wire, &sess)) { // cancel it from this thread
        .reply => |bb| try expectReply(arena, bb, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ cancel_uid ++ "\",\"result\":true}"),
        else => try testing.expect(false),
    }
    _ = fut.await(io); // wait for the slow handler to notice + raise
    try testing.expectEqual(@as(i64, -32800), code.load(.acquire)); // REQUEST_CANCELLED
}

// An authorizer that scopes `$/cancelRequest` to the target's owning session (compared by pointer, since
// every void-session shares the placeholder uuid) and records whether it saw a null target.
const ScopedAuthz = struct {
    saw_null_target: bool = false,
    fn authorize(self: *@This(), request: types.RequestInfo, session: *session_mod.Session(void), target: ?*session_mod.Session(void)) types.AuthorizationResponse {
        if (!std.mem.eql(u8, request.method, "$/cancelRequest")) return .{ .authorized = true }; // allow subscribe
        if (target) |tg| {
            if (tg == session) return .{ .authorized = true }; // the owner may cancel its own
        } else self.saw_null_target = true;
        return .{ .authorized = false, .message = "not your subscription" };
    }
};

fn buildScopedPubSub(gpa: std.mem.Allocator, seq: *Seq, authz: *ScopedAuthz) !protocol_mod.Protocol(void) {
    var b = protocol_mod.Protocol(void).builder(gpa, "test", "1.0.0");
    try b.subscription("alerts.subscribe", SubArgs, AlertEvent, .{});
    b.idGen(.{ .ctx = @ptrCast(seq), .nextFn = &Seq.nextImpl });
    b.authorizer(authz, ScopedAuthz.authorize);
    return b.build();
}

test "cancel: session-scoped authz — another session is denied, the owner may cancel its own subscription" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    var seq = Seq{};
    var authz = ScopedAuthz{};
    var proto = try buildScopedPubSub(testing.allocator, &seq, &authz);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var owner = proto.newSession(null);
    var other = proto.newSession(null);
    try subscribeVia(&proto, &tr, io, arena, &owner, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ work_uid ++ "\",\"method\":\"alerts.subscribe\",\"params\":{\"channel\":\"pool\"}}");

    // a different session cannot cancel the owner's subscription (authz sees target = the owner's session)
    switch (tr.dispatchTracked(io, arena, cancel_sub_wire, &other)) {
        .reply => |b| try expectReply(arena, b, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ cancel_uid ++ "\",\"error\":{\"code\":-32000,\"message\":\"not your subscription\"}}"),
        else => try testing.expect(false),
    }
    // still subscribed (denied) → a publish is delivered
    try tr.sendNotification(io, "alerts.subscribe", AlertEvent{ .level = "info", .text = "still here" });
    const p = tr.pollNotification(io, false) orelse return error.NoNotification;
    tr.freeNotification(p);

    // the owner may cancel its own subscription
    switch (tr.dispatchTracked(io, arena, cancel_sub_wire, &owner)) {
        .reply => |b| try expectReply(arena, b, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ cancel_uid ++ "\",\"result\":true}"),
        else => try testing.expect(false),
    }
    // now dropped → a publish is a no-op
    try tr.sendNotification(io, "alerts.subscribe", AlertEvent{ .level = "x", .text = "y" });
    try testing.expect(tr.pollNotification(io, false) == null);
}

test "cancel: the authorizer sees a null target for an unknown id (denied before revealing existence)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    var seq = Seq{};
    var authz = ScopedAuthz{};
    var proto = try buildScopedPubSub(testing.allocator, &seq, &authz);
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    // unknown target → authz sees target = null and denies → NOT_AUTHORIZED (not REQUEST_FAILED — the
    // caller is rejected without learning whether the target exists)
    switch (tr.dispatchTracked(io, arena, cancel_unknown_wire, &sess)) {
        .reply => |b| try expectReply(arena, b, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ cancel_uid ++ "\",\"error\":{\"code\":-32000,\"message\":\"not your subscription\"}}"),
        else => try testing.expect(false),
    }
    try testing.expect(authz.saw_null_target);
}

// ── cancellation_handler + wait_for_cancel (mirrors tests/test_cancel.py) ─────

test "cancel: the cancellation callback runs on a request cancel (captures the target id)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    const Cap = struct {
        dupe_into: std.mem.Allocator,
        target_id: ?[]const u8 = null,
        fn onCancel(self: *@This(), target_id: []const u8, _: *session_mod.Session(void)) !void {
            self.target_id = self.dupe_into.dupe(u8, target_id) catch null;
        }
    };
    var cap = Cap{ .dupe_into = arena };
    var svc = SelfCancel{ .io = io, .ra = arena };
    var b = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("work", &svc, SelfCancel.run, .{ .cancellable = true });
    b.cancellationHandler(&cap, Cap.onCancel);
    var proto = b.build();
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();
    svc.tr = &tr;

    var sess = proto.newSession(null);
    switch (tr.dispatchTracked(io, arena, work_wire, &sess)) {
        .reply => |bts| try expectReply(arena, bts, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ work_uid ++ "\",\"error\":{\"code\":-32800,\"message\":\"Request cancelled\"}}"),
        else => try testing.expect(false),
    }
    try testing.expectEqual(@as(i64, 0), svc.cancel_code); // the cancel succeeded (callback ran cleanly)
    try testing.expect(cap.target_id != null);
    try testing.expectEqualStrings(work_uid, cap.target_id.?); // the callback received the target id
}

test "cancel: a cancellation callback that errors → INTERNAL_ERROR (the flag is still set)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init_single_threaded;
    const io = t.io();

    var bad = struct {
        fn onCancel(_: *@This(), _: []const u8, _: *session_mod.Session(void)) !void {
            return error.Boom;
        }
    }{};
    var svc = SelfCancel{ .io = io, .ra = arena };
    var b = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("work", &svc, SelfCancel.run, .{ .cancellable = true });
    b.cancellationHandler(&bad, @TypeOf(bad).onCancel);
    var proto = b.build();
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();
    svc.tr = &tr;

    var sess = proto.newSession(null);
    // the callback errors → the cancel response is INTERNAL_ERROR; but the flag WAS set first, so the
    // outer handler still raises REQUEST_CANCELLED.
    switch (tr.dispatchTracked(io, arena, work_wire, &sess)) {
        .reply => |bts| try expectReply(arena, bts, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ work_uid ++ "\",\"error\":{\"code\":-32800,\"message\":\"Request cancelled\"}}"),
        else => try testing.expect(false),
    }
    try testing.expectEqual(@as(i64, -32603), svc.cancel_code); // the self-cancel got INTERNAL_ERROR
}

test "wait_for_cancel: blocks until the request is cancelled, then returns true (cross-thread)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init(testing.allocator, .{});
    defer t.deinit();
    const io = t.io();

    const Shared = struct { started: std.atomic.Value(bool) = .init(false), woke: std.atomic.Value(bool) = .init(false) };
    var shared = Shared{};
    const Waiter = struct {
        sh: *Shared,
        fn run(self: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
            self.sh.started.store(true, .release);
            self.sh.woke.store(ctx.waitForCancel(.none), .release); // block until cancelled
            return .{ .id = 1, .name = "x" };
        }
    };
    var svc = Waiter{ .sh = &shared };
    var b = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("work", &svc, Waiter.run, .{ .cancellable = true });
    var proto = b.build();
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();

    var sess = proto.newSession(null);
    const Task = struct {
        fn go(trp: *Transport(void), pio: std.Io, ra: std.mem.Allocator, s: *session_mod.Session(void)) void {
            switch (trp.dispatchTracked(pio, ra, work_wire, s)) {
                .reply => |b2| ra.free(b2),
                else => {},
            }
        }
    };
    var fut = io.concurrent(Task.go, .{ &tr, io, testing.allocator, &sess }) catch |e| return e;
    defer _ = fut.await(io);
    while (!shared.started.load(.acquire)) std.atomic.spinLoopHint();
    switch (tr.dispatchTracked(io, arena, cancel_work_wire, &sess)) {
        .reply => |b2| try expectReply(arena, b2, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ cancel_uid ++ "\",\"result\":true}"),
        else => try testing.expect(false),
    }
    _ = fut.await(io);
    try testing.expect(shared.woke.load(.acquire)); // waitForCancel returned true
}

test "wait_for_cancel: times out → false; a non-cancellable request returns false immediately" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var t: std.Io.Threaded = .init(testing.allocator, .{});
    defer t.deinit();
    const io = t.io();

    // A handler that waits a short bounded time for a cancel that never comes.
    const Waiter = struct {
        woke: bool = true, // sentinel: must become false
        timeout: std.Io.Timeout,
        fn run(self: *@This(), _: NoArgs, ctx: *session_mod.RequestCtx(void)) !WorkResult {
            self.woke = ctx.waitForCancel(self.timeout);
            return .{ .id = 1, .name = "x" };
        }
    };
    const short: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(20) } };

    // (a) cancellable but never cancelled → the wait times out → false
    var svc = Waiter{ .timeout = short };
    var b = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b.method("work", &svc, Waiter.run, .{ .cancellable = true });
    var proto = b.build();
    defer proto.deinit();
    var tr = Transport(void).init(testing.allocator, &proto);
    defer tr.deinit();
    var sess = proto.newSession(null);
    _ = tr.dispatchTracked(io, arena, work_wire, &sess);
    try testing.expect(!svc.woke); // timed out

    // (b) a non-cancellable method has no event → waitForCancel returns false immediately
    var svc2 = Waiter{ .timeout = .none };
    var b2 = protocol_mod.Protocol(void).builder(testing.allocator, "test", "1.0.0");
    try b2.method("work", &svc2, Waiter.run, .{}); // NOT cancellable
    var proto2 = b2.build();
    defer proto2.deinit();
    var tr2 = Transport(void).init(testing.allocator, &proto2);
    defer tr2.deinit();
    var sess2 = proto2.newSession(null);
    _ = tr2.dispatchTracked(io, arena, work_wire, &sess2);
    try testing.expect(!svc2.woke); // no event → immediate false
}

/// Pop the next notification, assert it targets `sess` and matches `expected_json`, then free it.
fn expectNextNotification(tr: *Transport(void), io: std.Io, arena: std.mem.Allocator, sess: *session_mod.Session(void), expected_json: []const u8) !void {
    const p = tr.pollNotification(io, false) orelse return error.NoNotification;
    defer tr.freeNotification(p);
    try testing.expect(p.session == sess);
    const got = try std.json.parseFromSliceLeaky(std.json.Value, arena, p.data, .{});
    const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, expected_json, .{});
    try testing.expect(json_eq.eql(got, exp));
}
