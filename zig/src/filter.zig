//! Filter engine (a regex-free port of the C `tnfilter`) + a streaming `FilterSink`. The api-spec marks a
//! method `filterable`; codegen emits `b.filterableMethod(...)`, whose run thunk (method.zig) compiles the
//! request's `query-filters` against the method's typed `Entry` struct, then streams the handler's pushed
//! entries through a `FilterSink` that tests-then-serializes ONLY matches — so dropped records cost no
//! allocation and no serialization, however enormous the input.
//!
//! Normative reference: /CODE/claudedir/truens_pos/src/cext/filter_utils (filter_list.c / filter_options.c).
//! Deliberate, documented forks from that engine (each user-mandated or forced by typing):
//!   * regex (`~`) dropped — the only true regex op; `rin`/`rnin` are reverse-in (source CONTAINS value),
//!     NOT regex, and stay. So no regex engine is needed.
//!   * `select`/`get` dropped — we never project/mutate output values nor unwrap to a single record.
//!   * the filter literal is coerced to the field's STATIC type at compile time, so cross-type comparisons
//!     can't arise at eval (the C engine defers to CPython richcompare). `bool` is distinct from int (no
//!     CPython `True==1`); int↔float compare via f64.
//!   * the `C` (case-insensitive) prefix uses ASCII-lowercase, not full Unicode casefold; it affects
//!     equality / membership / starts-/ends-with, not ordering comparisons.
//!   * ordering (`>`/`>=`/`<`/`<=`) against a null source → no-match (the C engine raises); `order_by` with
//!     no `nulls_first:`/`nulls_last:` prefix places nulls LAST (the C engine raises on a null in natural order).
//!   * field paths are FLAT (a single field name) in this slice; nested-dotted / `*` wildcard / array
//!     indexing is a follow-on — a dotted/unknown name resolves to no field and surfaces as INVALID_PARAMS.
const std = @import("std");
const xdr = @import("xdr"); // the binary-wire codec — used by the sink's XDR result encoding (no cycle: xdr is std-only)

// ── Values ─────────────────────────────────────────────────────────────────────

/// A value pulled from a record field, or a coerced filter literal. `nul` is a distinct variant (not
/// `?FilterValue`) so the per-operator null-guard table is a plain switch. `int` is `i128` to losslessly
/// hold a `u64` field above `i64`'s max.
pub const FilterValue = union(enum) {
    str: []const u8,
    int: i128,
    flt: f64,
    boolean: bool,
    nul,
    list: []const FilterValue, // only ever a LITERAL (the `in`/`nin` right-hand side)
};

/// The static kind of an `Entry` scalar field (an optional unwraps to its child's kind), used to coerce a
/// JSON literal to a `FilterValue` of the matching shape (rejecting a type mismatch at compile time).
pub const FieldKind = enum { str, int, flt, boolean };

pub const CompileError = error{ InvalidFilter, UnknownField, TypeMismatch, OutOfMemory };

/// Coerce a scalar JSON literal to the field's kind. A JSON `null` literal is accepted for ANY kind (→ `nul`)
/// so `["x", "=", null]` works against an optional field. Handles `.number_string` (0.16 emits it for
/// large/edge numbers).
pub fn coerceScalar(v: std.json.Value, kind: FieldKind) CompileError!FilterValue {
    if (v == .null) return .nul;
    return switch (kind) {
        .str => switch (v) {
            .string => |s| .{ .str = s },
            else => error.TypeMismatch,
        },
        .int => switch (v) {
            .integer => |i| .{ .int = i },
            .number_string => |s| .{ .int = std.fmt.parseInt(i128, s, 10) catch return error.TypeMismatch },
            else => error.TypeMismatch,
        },
        .flt => switch (v) {
            .integer => |i| .{ .flt = @floatFromInt(i) },
            .float => |f| .{ .flt = f },
            .number_string => |s| .{ .flt = std.fmt.parseFloat(f64, s) catch return error.TypeMismatch },
            else => error.TypeMismatch,
        },
        .boolean => switch (v) {
            .bool => |b| .{ .boolean = b },
            else => error.TypeMismatch,
        },
    };
}

fn coerceList(arena: std.mem.Allocator, v: std.json.Value, kind: FieldKind) CompileError!FilterValue {
    if (v != .array) return error.TypeMismatch;
    const out = try arena.alloc(FilterValue, v.array.items.len);
    for (v.array.items, 0..) |el, i| out[i] = try coerceScalar(el, kind);
    return .{ .list = out };
}

// ── Comptime flat field accessor ───────────────────────────────────────────────

/// Resolve a flat field name to its kind, or null if `E` has no such SCALAR field. An optional field unwraps
/// to its child's kind. A dotted / nested / array name has no flat field, so it returns null here and the
/// caller surfaces it as UnknownField (nested addressing is a later slice).
pub fn fieldKind(comptime E: type, name: []const u8) ?FieldKind {
    inline for (@typeInfo(E).@"struct".fields) |f| {
        if (std.mem.eql(u8, f.name, name)) {
            const Base = switch (@typeInfo(f.type)) {
                .optional => |o| o.child,
                else => f.type,
            };
            return switch (@typeInfo(Base)) {
                .int => .int,
                .float => .flt,
                .bool => .boolean,
                .pointer => |p| if (p.size == .slice and p.child == u8) FieldKind.str else null,
                else => null,
            };
        }
    }
    return null;
}

/// Extract a flat field's value into a `FilterValue` (`?T` present → its value, null → `nul`). Precondition:
/// `name` passed `fieldKind` at compile time, so it always names a real scalar field here. The `inline for`
/// compiles to a small, well-predicted field dispatch — pre-resolving it to an indirect getter measured
/// NO faster (and forcing the entry to memory to pass it by pointer was slightly slower), so it stays inline.
pub fn extract(comptime E: type, entry: E, name: []const u8) FilterValue {
    inline for (@typeInfo(E).@"struct".fields) |f| {
        if (std.mem.eql(u8, f.name, name)) return valToFilter(f.type, @field(entry, f.name));
    }
    unreachable;
}

/// Total over any field type: unsupported types (a non-`[]const u8` pointer, a nested struct, an array)
/// yield `nul`. Those never reach here for a valid query (fieldKind rejected them → UnknownField), but
/// keeping it total lets the `inline for` compile for an `Entry` that also carries such fields.
fn valToFilter(comptime T: type, v: T) FilterValue {
    return switch (@typeInfo(T)) {
        .optional => |o| if (v) |inner| valToFilter(o.child, inner) else FilterValue.nul,
        .int => .{ .int = @intCast(v) },
        .float => .{ .flt = @floatCast(v) },
        .bool => .{ .boolean = v },
        .pointer => |p| if (p.size == .slice and p.child == u8) FilterValue{ .str = v } else FilterValue.nul,
        else => FilterValue.nul,
    };
}

// ── Operators ──────────────────────────────────────────────────────────────────

pub const Op = enum { eq, ne, gt, ge, lt, le, in, nin, rin, rnin, sw, nsw, ew, new };
pub const ParsedOp = struct { op: Op, ci: bool };

/// Parse an operator string, stripping a leading `C` (case-insensitive). Unknown — including the dropped
/// `~` (regex) — returns null, which the caller maps to INVALID_PARAMS.
pub fn parseOp(raw: []const u8) ?ParsedOp {
    var s = raw;
    var ci = false;
    if (s.len > 0 and s[0] == 'C') {
        ci = true;
        s = s[1..];
    }
    const op: Op = if (std.mem.eql(u8, s, "="))
        .eq
    else if (std.mem.eql(u8, s, "!="))
        .ne
    else if (std.mem.eql(u8, s, ">"))
        .gt
    else if (std.mem.eql(u8, s, ">="))
        .ge
    else if (std.mem.eql(u8, s, "<"))
        .lt
    else if (std.mem.eql(u8, s, "<="))
        .le
    else if (std.mem.eql(u8, s, "in"))
        .in
    else if (std.mem.eql(u8, s, "nin"))
        .nin
    else if (std.mem.eql(u8, s, "rin"))
        .rin
    else if (std.mem.eql(u8, s, "rnin"))
        .rnin
    else if (std.mem.eql(u8, s, "^"))
        .sw
    else if (std.mem.eql(u8, s, "!^"))
        .nsw
    else if (std.mem.eql(u8, s, "$"))
        .ew
    else if (std.mem.eql(u8, s, "!$"))
        .new
    else
        return null;
    return .{ .op = op, .ci = ci };
}

/// Apply an operator. The null-guard table mirrors the C engine exactly: `in` has NO guard;
/// `nin`/`rin`/`rnin`/`^`/`!^`/`$`/`!$` are no-match on a null source; `=`/`!=`/ordering go to compare
/// (`null == null` is true; ordering against null is no-match here).
pub fn apply(op: Op, ci: bool, src: FilterValue, lit: FilterValue) bool {
    return switch (op) {
        .eq => valueEq(src, lit, ci),
        .ne => !valueEq(src, lit, ci),
        .gt, .ge, .lt, .le => orderCmp(op, src, lit),
        .in => switch (lit) {
            .list => |l| memberOf(src, l, ci),
            else => false,
        },
        .nin => if (src == .nul) false else switch (lit) {
            .list => |l| !memberOf(src, l, ci),
            else => false,
        },
        .rin => if (src == .nul) false else reverseIn(src, lit, ci),
        .rnin => if (src == .nul) false else !reverseIn(src, lit, ci),
        .sw => if (src == .nul) false else strMatch(src, lit, ci, .starts),
        .nsw => if (src == .nul) false else !strMatch(src, lit, ci, .starts),
        .ew => if (src == .nul) false else strMatch(src, lit, ci, .ends),
        .new => if (src == .nul) false else !strMatch(src, lit, ci, .ends),
    };
}

fn valueEq(a: FilterValue, b: FilterValue, ci: bool) bool {
    if (a == .nul or b == .nul) return (a == .nul and b == .nul); // null == null is true; null == x is false
    return switch (a) {
        .str => |as| (b == .str and eqlCi(as, b.str, ci)),
        else => if (cmpScalar(a, b)) |o| o == .eq else false,
    };
}

fn orderCmp(op: Op, src: FilterValue, lit: FilterValue) bool {
    const o = cmpScalar(src, lit) orelse return false; // null source / type mismatch → no-match
    return switch (op) {
        .gt => o == .gt,
        .ge => o != .lt,
        .lt => o == .lt,
        .le => o != .gt,
        else => unreachable,
    };
}

/// Order two scalars of the same family: int↔int, flt↔flt, int↔flt via f64, str (bytewise), bool. Any
/// other pairing (incl. a `nul` or `list` operand) → null = incomparable. `ci` is not honored for ordering.
fn cmpScalar(a: FilterValue, b: FilterValue) ?std.math.Order {
    return switch (a) {
        .int => |x| switch (b) {
            .int => |y| std.math.order(x, y),
            .flt => |y| std.math.order(@as(f64, @floatFromInt(x)), y),
            else => null,
        },
        .flt => |x| switch (b) {
            .int => |y| std.math.order(x, @as(f64, @floatFromInt(y))),
            .flt => |y| std.math.order(x, y),
            else => null,
        },
        .str => |x| switch (b) {
            .str => |y| std.mem.order(u8, x, y),
            else => null,
        },
        .boolean => |x| switch (b) {
            .boolean => |y| std.math.order(@intFromBool(x), @intFromBool(y)),
            else => null,
        },
        else => null,
    };
}

fn memberOf(src: FilterValue, list: []const FilterValue, ci: bool) bool {
    for (list) |item| if (valueEq(src, item, ci)) return true;
    return false;
}

/// `rin`/`rnin`: the literal is contained in the source. For a string source this is substring containment
/// (an array source — element containment — arrives with nested/array support in a later slice).
fn reverseIn(src: FilterValue, lit: FilterValue, ci: bool) bool {
    if (src != .str or lit != .str) return false;
    return containsCi(src.str, lit.str, ci);
}

const StrMode = enum { starts, ends };
fn strMatch(src: FilterValue, lit: FilterValue, ci: bool, mode: StrMode) bool {
    if (src != .str or lit != .str) return false;
    return switch (mode) {
        .starts => startsWithCi(src.str, lit.str, ci),
        .ends => endsWithCi(src.str, lit.str, ci),
    };
}

fn eqlCi(a: []const u8, b: []const u8, ci: bool) bool {
    if (!ci) return std.mem.eql(u8, a, b);
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    return true;
}
fn startsWithCi(hay: []const u8, pre: []const u8, ci: bool) bool {
    if (pre.len > hay.len) return false;
    return eqlCi(hay[0..pre.len], pre, ci);
}
fn endsWithCi(hay: []const u8, suf: []const u8, ci: bool) bool {
    if (suf.len > hay.len) return false;
    return eqlCi(hay[hay.len - suf.len ..], suf, ci);
}
fn containsCi(hay: []const u8, needle: []const u8, ci: bool) bool {
    if (!ci) return std.mem.indexOf(u8, hay, needle) != null;
    if (needle.len == 0) return true;
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (eqlCi(hay[i .. i + needle.len], needle, true)) return true;
    }
    return false;
}

// ── Compiled filter tree ────────────────────────────────────────────────────────

pub const Leaf = struct { field: []const u8, op: Op, ci: bool, lit: FilterValue };

/// A compiled filter node. The top level (and any AND-group) is `and_`; an `["OR",[...]]` node is `or_`.
pub const Compiled = union(enum) {
    leaf: Leaf,
    or_: []const Compiled,
    and_: []const Compiled,
};

const MAX_DEPTH: u32 = 64;

/// Compile the request's `query-filters` array against `E`. Top-level entries are AND'd. Returns
/// INVALID_PARAMS-class errors for any malformed node, unknown field, type mismatch, or excess depth.
pub fn compileFilters(arena: std.mem.Allocator, comptime E: type, filters: std.json.Value) CompileError!Compiled {
    if (filters != .array) return error.InvalidFilter;
    return .{ .and_ = try compileBranchList(arena, E, filters.array.items, 1) };
}

fn compileBranchList(arena: std.mem.Allocator, comptime E: type, items: []const std.json.Value, depth: u32) CompileError![]const Compiled {
    if (depth > MAX_DEPTH) return error.InvalidFilter;
    const out = try arena.alloc(Compiled, items.len);
    for (items, 0..) |node, i| out[i] = try compileNode(arena, E, node, depth);
    return out;
}

fn compileNode(arena: std.mem.Allocator, comptime E: type, node: std.json.Value, depth: u32) CompileError!Compiled {
    if (depth > MAX_DEPTH) return error.InvalidFilter;
    if (node != .array) return error.InvalidFilter;
    const items = node.array.items;
    // Classify in this order: OR (len 2, [0] == "OR") → AND-group ([0] is an array) → leaf (len 3).
    if (items.len == 2 and items[0] == .string and std.mem.eql(u8, items[0].string, "OR")) {
        if (items[1] != .array) return error.InvalidFilter;
        return .{ .or_ = try compileBranchList(arena, E, items[1].array.items, depth + 1) };
    }
    if (items.len > 0 and items[0] == .array) {
        return .{ .and_ = try compileBranchList(arena, E, items, depth + 1) };
    }
    if (items.len == 3 and items[0] == .string and items[1] == .string) {
        const field = items[0].string;
        const kind = fieldKind(E, field) orelse return error.UnknownField;
        const parsed = parseOp(items[1].string) orelse return error.InvalidFilter;
        const lit: FilterValue = switch (parsed.op) {
            .in, .nin => try coerceList(arena, items[2], kind),
            else => try coerceScalar(items[2], kind),
        };
        return .{ .leaf = .{ .field = field, .op = parsed.op, .ci = parsed.ci, .lit = lit } };
    }
    return error.InvalidFilter;
}

/// Evaluate the compiled tree against one entry. Top-level/AND require all children; OR requires any. An
/// empty `query-filters` compiles to an empty `and_`, which matches every entry.
pub fn matches(comptime E: type, node: Compiled, entry: E) bool {
    return switch (node) {
        .leaf => |lf| apply(lf.op, lf.ci, extract(E, entry, lf.field), lf.lit),
        .and_ => |kids| {
            for (kids) |k| if (!matches(E, k, entry)) return false;
            return true;
        },
        .or_ => |kids| {
            for (kids) |k| if (matches(E, k, entry)) return true;
            return false;
        },
    };
}

// ── Query options (count / order_by / offset / limit; get + select are dropped) ──

pub const QueryOptions = struct {
    count: bool = false,
    order_by: ?[]const []const u8 = null,
    offset: u64 = 0,
    limit: u64 = 0,
};

pub const OrderKey = struct { field: []const u8, desc: bool, nulls_first: bool };

/// Decode the raw `query-options` Value (absent/null → defaults). Unknown keys (the dropped get/select) are
/// ignored. A non-object, or a decode failure, is INVALID_PARAMS-class.
pub fn parseOptions(arena: std.mem.Allocator, qo: ?std.json.Value) CompileError!QueryOptions {
    const v = qo orelse return .{};
    if (v == .null) return .{};
    if (v != .object) return error.InvalidFilter;
    return std.json.parseFromValueLeaky(QueryOptions, arena, v, .{ .ignore_unknown_fields = true }) catch error.InvalidFilter;
}

/// Parse each `order_by` string into an `OrderKey`, validating the field against `E`. Prefix order:
/// optional `nulls_first:`/`nulls_last:`, then an optional leading `-` (descending). `order_by[0]` is the
/// most-significant key.
pub fn parseOrderBy(arena: std.mem.Allocator, comptime E: type, order_by: ?[]const []const u8) CompileError![]const OrderKey {
    const list = order_by orelse return &.{};
    const out = try arena.alloc(OrderKey, list.len);
    for (list, 0..) |s, i| out[i] = try parseOrderKey(E, s);
    return out;
}

fn parseOrderKey(comptime E: type, raw: []const u8) CompileError!OrderKey {
    var rest = raw;
    var nulls_first = false;
    if (std.mem.startsWith(u8, rest, "nulls_first:")) {
        nulls_first = true;
        rest = rest["nulls_first:".len..];
    } else if (std.mem.startsWith(u8, rest, "nulls_last:")) {
        nulls_first = false;
        rest = rest["nulls_last:".len..];
    }
    var desc = false;
    if (rest.len > 0 and rest[0] == '-') {
        desc = true;
        rest = rest[1..];
    }
    if (rest.len == 0) return error.InvalidFilter;
    if (fieldKind(E, rest) == null) return error.UnknownField;
    return .{ .field = rest, .desc = desc, .nulls_first = nulls_first };
}

// ── Streaming sink ───────────────────────────────────────────────────────────────

/// The handler pushes each candidate entry through `emit`; the sink tests it and, per mode, counts /
/// buffers-for-sort / serializes-on-match. A non-matching record costs nothing. Pipeline order mirrors the
/// C engine: `count` precedes order/offset/limit, so count = number of matches regardless of paging.
pub fn FilterSink(comptime E: type) type {
    return struct {
        const Self = @This();
        const Mode = enum { count, stream, ordered };
        /// Output wire for the result: a JSON array / bare int (default), or canonical XDR (count → hyper,
        /// list → `u32 count + each entry`). The streaming/filtering pipeline is identical for both — only
        /// the per-match serialization (`emit`) and the assembly (`finalize` vs `finalizeXdr`) differ.
        const Wire = enum { json, xdr };

        arena: std.mem.Allocator,
        compiled: Compiled,
        opts: QueryOptions,
        order_keys: []const OrderKey,
        mode: Mode,
        wire: Wire = .json,

        counter: u64 = 0, // count mode
        skipped: u64 = 0, // stream mode: matches dropped to honor `offset`
        emitted: u64 = 0, // stream mode: matches written
        done: bool = false, // stream mode: `limit` reached
        out: std.ArrayList(u8) = .empty, // stream mode: "elem,elem,…" (no brackets yet)
        buf: std.ArrayList(E) = .empty, // ordered mode: matched typed copies

        /// In-place init — the sink is arena-allocated and never moved (the run thunk passes `&sink`).
        pub fn init(self: *Self, arena: std.mem.Allocator, compiled: Compiled, opts: QueryOptions, order_keys: []const OrderKey) void {
            self.* = .{
                .arena = arena,
                .compiled = compiled,
                .opts = opts,
                .order_keys = order_keys,
                .mode = if (opts.count) .count else if (order_keys.len > 0) .ordered else .stream,
            };
        }

        /// Same as `init` but the result is emitted as canonical XDR (used by the XDR filterable run thunk).
        pub fn initXdr(self: *Self, arena: std.mem.Allocator, compiled: Compiled, opts: QueryOptions, order_keys: []const OrderKey) void {
            self.init(arena, compiled, opts, order_keys);
            self.wire = .xdr;
        }

        pub fn emit(self: *Self, entry: E) !void {
            if (!matches(E, self.compiled, entry)) return;
            switch (self.mode) {
                .count => self.counter += 1,
                .ordered => try self.buf.append(self.arena, entry),
                .stream => {
                    if (self.skipped < self.opts.offset) {
                        self.skipped += 1;
                        return;
                    }
                    if (self.opts.limit != 0 and self.emitted >= self.opts.limit) {
                        self.done = true;
                        return;
                    }
                    switch (self.wire) {
                        // JSON: "elem,elem,…" (the brackets are added in finalize).
                        .json => {
                            if (self.out.items.len != 0) try self.out.append(self.arena, ',');
                            try self.out.appendSlice(self.arena, try std.json.Stringify.valueAlloc(self.arena, entry, .{}));
                        },
                        // XDR: the canonically-encoded entries back-to-back (the u32 count is prepended in
                        // finalizeXdr) — still serialize-on-match, so an over-limit record is never encoded.
                        .xdr => try self.out.appendSlice(self.arena, try xdr.encodeAlloc(self.arena, entry)),
                    }
                    self.emitted += 1;
                    if (self.opts.limit != 0 and self.emitted >= self.opts.limit) self.done = true;
                },
            }
        }

        /// False only once a streaming `limit` is reached (so the handler can stop early). count/ordered
        /// always want more — count must see every match; ordered needs the full set before windowing.
        pub fn wantMore(self: *const Self) bool {
            return !(self.mode == .stream and self.done);
        }

        /// The result JSON bytes: a bare integer (count) or a JSON array of matched entries — spliced raw
        /// into the response `result`.
        pub fn finalize(self: *Self) ![]const u8 {
            return switch (self.mode) {
                .count => std.fmt.allocPrint(self.arena, "{d}", .{self.counter}),
                .stream => std.fmt.allocPrint(self.arena, "[{s}]", .{self.out.items}),
                .ordered => self.finalizeOrdered(),
            };
        }

        /// The result as canonical XDR — the binary-wire analog of `finalize`: a bare hyper (count) or a
        /// `u32 count + each matched entry` array, spliced into the XDR reply frame. The filtering/paging/
        /// ordering pipeline is identical; only the per-match encoding (`emit`) + this assembly differ.
        pub fn finalizeXdr(self: *Self) ![]const u8 {
            var aw: std.Io.Writer.Allocating = .init(self.arena);
            const w = &aw.writer;
            switch (self.mode) {
                .count => try xdr.encode(w, @as(i64, @intCast(self.counter))),
                .stream => {
                    try w.writeInt(u32, @intCast(self.emitted), .big);
                    try w.writeAll(self.out.items); // the per-match XDR encodings, already concatenated
                },
                .ordered => {
                    const items = self.buf.items;
                    const window = try self.sortedWindow();
                    try w.writeInt(u32, @intCast(window.len), .big);
                    for (window) |pi| try xdr.encode(w, items[pi]);
                },
            }
            return aw.writer.buffered();
        }

        // Decorate-sort-undecorate: extract each order-key value ONCE per row (so the comparator never
        // re-resolves a field name), then sort a `u32` permutation with the fast unstable sort + an
        // original-index tiebreak (which makes it effectively STABLE). This keeps order_by at O(M·nkeys)
        // extractions + one pdq sort, instead of a field-name lookup on every one of the O(M log M)
        // comparisons. Returns the sorted+windowed `buf` indices — shared by the JSON + XDR assembly.
        fn sortedWindow(self: *Self) ![]const u32 {
            const items = self.buf.items;
            const m = items.len;
            const nkeys = self.order_keys.len;
            const keys = try self.arena.alloc(FilterValue, m * nkeys);
            for (items, 0..) |e, i| {
                for (self.order_keys, 0..) |k, j| keys[i * nkeys + j] = extract(E, e, k.field);
            }
            const perm = try self.arena.alloc(u32, m);
            for (perm, 0..) |*p, i| p.* = @intCast(i);
            std.mem.sortUnstable(u32, perm, PermCtx{ .keys = keys, .nkeys = nkeys, .order_keys = self.order_keys }, PermCtx.lessThan);
            const off: usize = @intCast(@min(self.opts.offset, @as(u64, m)));
            const end = if (self.opts.limit == 0) m else @min(off + @as(usize, @intCast(self.opts.limit)), m);
            return perm[off..end];
        }

        fn finalizeOrdered(self: *Self) ![]const u8 {
            const items = self.buf.items;
            const window = try self.sortedWindow();
            var out: std.ArrayList(u8) = .empty;
            try out.append(self.arena, '[');
            for (window, 0..) |pi, i| {
                if (i != 0) try out.append(self.arena, ',');
                try out.appendSlice(self.arena, try std.json.Stringify.valueAlloc(self.arena, items[pi], .{}));
            }
            try out.append(self.arena, ']');
            return out.items;
        }
    };
}

/// Comparator over a precomputed key matrix (`keys[row*nkeys + j]` = the j-th order key's value for `row`),
/// sorting a permutation of row indices. Multi-key by short-circuiting on the first non-equal key; nulls are
/// placed per `nulls_first` (independent of `desc`); a full tie falls back to the original index, so the
/// unstable sort is effectively STABLE (ties keep input order — what tnfilter's stable sort guarantees).
const PermCtx = struct {
    keys: []const FilterValue,
    nkeys: usize,
    order_keys: []const OrderKey,
    fn lessThan(ctx: PermCtx, a: u32, b: u32) bool {
        const base_a = @as(usize, a) * ctx.nkeys;
        const base_b = @as(usize, b) * ctx.nkeys;
        for (ctx.order_keys, 0..) |k, j| {
            const av = ctx.keys[base_a + j];
            const bv = ctx.keys[base_b + j];
            const an = (av == .nul);
            const bn = (bv == .nul);
            if (an or bn) {
                if (an and bn) continue;
                return if (k.nulls_first) an else bn;
            }
            const o = cmpScalar(av, bv) orelse continue;
            if (o == .eq) continue;
            const lt = (o == .lt);
            return if (k.desc) !lt else lt;
        }
        return a < b; // original-index tiebreak → stable
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────────
const testing = std.testing;

const TestEntry = struct {
    id: i64,
    name: []const u8,
    ratio: f64,
    active: bool,
    note: ?[]const u8 = null,
};

fn parseV(arena: std.mem.Allocator, json: []const u8) std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{}) catch unreachable;
}

test "fieldKind classifies scalar + optional fields; rejects unknown" {
    try testing.expectEqual(FieldKind.int, fieldKind(TestEntry, "id").?);
    try testing.expectEqual(FieldKind.str, fieldKind(TestEntry, "name").?);
    try testing.expectEqual(FieldKind.flt, fieldKind(TestEntry, "ratio").?);
    try testing.expectEqual(FieldKind.boolean, fieldKind(TestEntry, "active").?);
    try testing.expectEqual(FieldKind.str, fieldKind(TestEntry, "note").?); // ?[]const u8 → str
    try testing.expect(fieldKind(TestEntry, "missing") == null);
    try testing.expect(fieldKind(TestEntry, "name.sub") == null); // nested deferred → unknown
}

test "extract surfaces values; optional null → nul" {
    const e: TestEntry = .{ .id = 5, .name = "tank", .ratio = 1.5, .active = true, .note = null };
    try testing.expectEqual(@as(i128, 5), extract(TestEntry, e, "id").int);
    try testing.expectEqualStrings("tank", extract(TestEntry, e, "name").str);
    try testing.expectEqual(@as(f64, 1.5), extract(TestEntry, e, "ratio").flt);
    try testing.expectEqual(true, extract(TestEntry, e, "active").boolean);
    try testing.expect(extract(TestEntry, e, "note") == .nul);
    const e2: TestEntry = .{ .id = 1, .name = "x", .ratio = 0, .active = false, .note = "hi" };
    try testing.expectEqualStrings("hi", extract(TestEntry, e2, "note").str);
}

test "parseOp strips C prefix; unknown + dropped ~ → null" {
    try testing.expectEqual(Op.eq, parseOp("=").?.op);
    try testing.expect(!parseOp("=").?.ci);
    try testing.expectEqual(Op.eq, parseOp("C=").?.op);
    try testing.expect(parseOp("C=").?.ci);
    try testing.expectEqual(Op.rin, parseOp("rin").?.op);
    try testing.expectEqual(Op.nsw, parseOp("!^").?.op);
    try testing.expect(parseOp("~") == null); // regex dropped
    try testing.expect(parseOp("??") == null);
}

test "apply: equality / ordering / null guards" {
    const s = FilterValue{ .str = "abc" };
    const n = FilterValue.nul;
    // equality
    try testing.expect(apply(.eq, false, .{ .int = 3 }, .{ .int = 3 }));
    try testing.expect(!apply(.eq, false, .{ .int = 3 }, .{ .int = 4 }));
    try testing.expect(apply(.eq, false, n, n)); // null == null
    try testing.expect(!apply(.eq, false, n, .{ .int = 1 })); // null == x → false
    try testing.expect(apply(.ne, false, n, .{ .str = "a" })); // null != "a" → match (no guard)
    // case-insensitive equality
    try testing.expect(apply(.eq, true, .{ .str = "ABC" }, s));
    try testing.expect(!apply(.eq, false, .{ .str = "ABC" }, s));
    // ordering: int↔float via f64
    try testing.expect(apply(.gt, false, .{ .int = 3 }, .{ .flt = 2.5 }));
    try testing.expect(apply(.le, false, .{ .flt = 2.5 }, .{ .int = 3 }));
    try testing.expect(!apply(.gt, false, n, .{ .int = 0 })); // ordering vs null → no-match
    // string ops are null-guarded
    try testing.expect(apply(.sw, false, s, .{ .str = "ab" }));
    try testing.expect(apply(.ew, false, s, .{ .str = "bc" }));
    try testing.expect(!apply(.sw, false, n, .{ .str = "ab" }));
    try testing.expect(apply(.nsw, false, s, .{ .str = "z" }));
    try testing.expect(!apply(.nsw, false, n, .{ .str = "z" })); // null source → no-match (guard)
}

test "apply: in / nin / rin / rnin" {
    const list = [_]FilterValue{ .{ .str = "a" }, .{ .str = "c" } };
    const lit = FilterValue{ .list = &list };
    try testing.expect(apply(.in, false, .{ .str = "a" }, lit));
    try testing.expect(!apply(.in, false, .{ .str = "b" }, lit));
    try testing.expect(apply(.nin, false, .{ .str = "b" }, lit));
    try testing.expect(!apply(.nin, false, FilterValue.nul, lit)); // nin null source → no-match
    // rin/rnin: literal is contained in the source string
    try testing.expect(apply(.rin, false, .{ .str = "abcdef" }, .{ .str = "cd" }));
    try testing.expect(!apply(.rin, false, .{ .str = "abcdef" }, .{ .str = "zz" }));
    try testing.expect(apply(.rnin, false, .{ .str = "abcdef" }, .{ .str = "zz" }));
    try testing.expect(!apply(.rin, false, FilterValue.nul, .{ .str = "cd" })); // rin null source → no-match
}

test "compileFilters: leaf, OR, AND-group, errors" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    const e: TestEntry = .{ .id = 2, .name = "a", .ratio = 1, .active = true };

    const leaf = try compileFilters(ar, TestEntry, parseV(ar, "[[\"name\",\"=\",\"a\"]]"));
    try testing.expect(matches(TestEntry, leaf, e));

    const or_node = try compileFilters(ar, TestEntry, parseV(ar, "[[\"OR\",[[\"name\",\"=\",\"z\"],[\"id\",\"=\",2]]]]"));
    try testing.expect(matches(TestEntry, or_node, e)); // id==2 matches via OR

    // AND-group inside OR: (name==a AND id==2) OR (name==z)
    const and_in_or = try compileFilters(ar, TestEntry, parseV(ar, "[[\"OR\",[[[\"name\",\"=\",\"a\"],[\"id\",\"=\",2]],[\"name\",\"=\",\"z\"]]]]"));
    try testing.expect(matches(TestEntry, and_in_or, e));

    // empty filters → match-all
    try testing.expect(matches(TestEntry, try compileFilters(ar, TestEntry, parseV(ar, "[]")), e));

    // errors
    try testing.expectError(error.UnknownField, compileFilters(ar, TestEntry, parseV(ar, "[[\"nope\",\"=\",1]]")));
    try testing.expectError(error.InvalidFilter, compileFilters(ar, TestEntry, parseV(ar, "[[\"name\",\"??\",\"a\"]]")));
    try testing.expectError(error.InvalidFilter, compileFilters(ar, TestEntry, parseV(ar, "[[\"name\",\"=\"]]"))); // bad arity
    try testing.expectError(error.TypeMismatch, compileFilters(ar, TestEntry, parseV(ar, "[[\"id\",\"=\",\"x\"]]"))); // str literal for int field
    try testing.expectError(error.InvalidFilter, compileFilters(ar, TestEntry, parseV(ar, "{}"))); // not an array
}

const sink_data = [_]TestEntry{
    .{ .id = 1, .name = "a", .ratio = 0.5, .active = true, .note = null },
    .{ .id = 2, .name = "b", .ratio = 2.5, .active = false, .note = "x" },
    .{ .id = 3, .name = "a", .ratio = 1.5, .active = true, .note = null },
};

fn runSink(ar: std.mem.Allocator, filters_json: []const u8, opts: QueryOptions) ![]const u8 {
    const compiled = try compileFilters(ar, TestEntry, parseV(ar, filters_json));
    const order_keys = try parseOrderBy(ar, TestEntry, opts.order_by);
    var sink: FilterSink(TestEntry) = undefined;
    sink.init(ar, compiled, opts, order_keys);
    for (sink_data) |e| {
        if (!sink.wantMore()) break;
        try sink.emit(e);
    }
    return sink.finalize();
}

test "FilterSink: filter narrows; stream preserves input order" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const got = try runSink(ar, "[[\"name\",\"=\",\"a\"]]", .{});
    const v = parseV(ar, got);
    try testing.expectEqual(@as(usize, 2), v.array.items.len);
    try testing.expectEqual(@as(i64, 1), v.array.items[0].object.get("id").?.integer);
    try testing.expectEqual(@as(i64, 3), v.array.items[1].object.get("id").?.integer);
}

test "FilterSink: count returns a bare integer (ignores offset/limit)" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const got = try runSink(ar, "[[\"name\",\"=\",\"a\"]]", .{ .count = true, .offset = 1, .limit = 1 });
    try testing.expectEqualStrings("2", got);
}

test "FilterSink: offset + limit page the stream" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const got = try runSink(ar, "[]", .{ .offset = 1, .limit = 1 });
    const v = parseV(ar, got);
    try testing.expectEqual(@as(usize, 1), v.array.items.len);
    try testing.expectEqual(@as(i64, 2), v.array.items[0].object.get("id").?.integer); // skipped id 1, took id 2
}

test "FilterSink: order_by descending by ratio, then offset/limit window" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const order = [_][]const u8{"-ratio"};
    const got = try runSink(ar, "[]", .{ .order_by = &order });
    const v = parseV(ar, got);
    // ratios 2.5, 1.5, 0.5 → ids 2, 3, 1
    try testing.expectEqual(@as(i64, 2), v.array.items[0].object.get("id").?.integer);
    try testing.expectEqual(@as(i64, 3), v.array.items[1].object.get("id").?.integer);
    try testing.expectEqual(@as(i64, 1), v.array.items[2].object.get("id").?.integer);
}

test "FilterSink: order_by nulls_first places null notes ahead" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const order = [_][]const u8{"nulls_first:note"};
    const got = try runSink(ar, "[]", .{ .order_by = &order });
    const v = parseV(ar, got);
    // notes: null,null,"x" → nulls first (ids 1,3 in stable input order), then "x" (id 2)
    try testing.expect(v.array.items[0].object.get("note").? == .null);
    try testing.expect(v.array.items[1].object.get("note").? == .null);
    try testing.expectEqualStrings("x", v.array.items[2].object.get("note").?.string);
}
