const std = @import("std");

// truenas_jsonrpc is a library (no executable). `zig build test` runs every module's
// inline `test {}` block plus the A/B conformance suite, aggregated through src/root.zig.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The public module; consumers `@import("truenas_jsonrpc")`.
    const mod = b.addModule("truenas_jsonrpc", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The generic XDR (RFC 4506) codec — its own module/library (zig/xdr/), byte-validated against the
    // FreeBSD sys/xdr canonical bytes. The main library imports it (`@import("xdr")`) for the binary wire.
    const xdr_mod = b.createModule(.{
        .root_source_file = b.path("xdr/xdr.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("xdr", xdr_mod);
    const xdr_tests = b.addTest(.{ .root_module = xdr_mod });
    const run_xdr_tests = b.addRunArtifact(xdr_tests);

    // Library unit tests (every module's inline `test {}`, aggregated through src/root.zig).
    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // A/B conformance suite — a *consumer* of the public module: it `@import("truenas_jsonrpc")`
    // and uses only the re-exported API, exactly like a downstream user (no reach into internals).
    const conf_mod = b.createModule(.{
        .root_source_file = b.path("conformance/conformance_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "truenas_jsonrpc", .module = mod }},
    });
    const conf_tests = b.addTest(.{ .root_module = conf_mod });
    const run_conf_tests = b.addRunArtifact(conf_tests);

    const test_step = b.step("test", "Run library unit tests + the A/B conformance suite + the XDR codec");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_conf_tests.step);
    test_step.dependOn(&run_xdr_tests.step);

    // Dispatch microbenchmark — another *consumer* of the public module. The Python mirror lives at
    // bench/bench.py; the two share a corpus/handlers so their ns/op are comparable. Run optimized:
    //   zig build bench -Doptimize=ReleaseFast
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/bench.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "truenas_jsonrpc", .module = mod }},
    });
    const bench_exe = b.addExecutable(.{ .name = "bench", .root_module = bench_mod });
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run the dispatch microbenchmark (pass -Doptimize=ReleaseFast)");
    bench_step.dependOn(&run_bench.step);

    // Filtering microbenchmark — the A/B counterpart for the query engine. Mirror: bench/filter_bench.py
    // (Python's truenas_pyfilter C engine over the same dataset). Run optimized:
    //   zig build filter-bench -Doptimize=ReleaseFast
    const filter_bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/filter_bench.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "truenas_jsonrpc", .module = mod }},
    });
    const filter_bench_exe = b.addExecutable(.{ .name = "filter-bench", .root_module = filter_bench_mod });
    const run_filter_bench = b.addRunArtifact(filter_bench_exe);
    const filter_bench_step = b.step("filter-bench", "Run the filtering microbenchmark (pass -Doptimize=ReleaseFast)");
    filter_bench_step.dependOn(&run_filter_bench.step);
}
