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

        /// One queued outbound notification (Python `_Pending`): the target connection + the wire bytes.
        /// `data` is owned by `gpa`; whoever drains it via `pollNotification` frees it after sending.
        pub const Pending = struct {
            session: *Session,
            data: []const u8,
        };

        gpa: std.mem.Allocator,
        /// The sans-I/O core — read-only here (look up a topic + its `Notifies` encoder). Must outlive `self`.
        proto: *const Proto,
        /// topic name → its subscriptions. Keys borrow the core's long-lived method names (no dupe).
        registry: std.StringHashMap(std.ArrayList(Subscription)),
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
                .outbound = .empty,
            };
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
            for (self.outbound.items[self.head..]) |p| self.gpa.free(p.data);
            self.outbound.deinit(self.gpa);
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
                self.outbound.append(self.gpa, .{ .session = sub.session, .data = data }) catch return error.OutOfMemory;
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
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────
const testing = std.testing;
const json_eq = @import("json_eq.zig");

const SubArgs = struct { channel: []const u8 };
const AlertEvent = struct { level: []const u8, text: []const u8 };

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
    defer testing.allocator.free(got.data);
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, got.data, .{});
    const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"jsonrpc\":\"2.0\",\"method\":\"alerts.subscribe\",\"params\":{\"level\":\"info\",\"text\":\"hi\"}}", .{});
    try testing.expect(json_eq.eql(v, exp));
}

/// Pop the next notification, assert it targets `sess` and matches `expected_json`, then free it.
fn expectNextNotification(tr: *Transport(void), io: std.Io, arena: std.mem.Allocator, sess: *session_mod.Session(void), expected_json: []const u8) !void {
    const p = tr.pollNotification(io, false) orelse return error.NoNotification;
    defer tr.gpa.free(p.data);
    try testing.expect(p.session == sess);
    const got = try std.json.parseFromSliceLeaky(std.json.Value, arena, p.data, .{});
    const exp = try std.json.parseFromSliceLeaky(std.json.Value, arena, expected_json, .{});
    try testing.expect(json_eq.eql(got, exp));
}
