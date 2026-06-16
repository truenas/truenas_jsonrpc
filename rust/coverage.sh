#!/usr/bin/env bash
# Native source-based line coverage for the workspace, using only the toolchain's own
# tools: `rustc -C instrument-coverage` to instrument, and the `llvm-profdata`/`llvm-cov`
# that ship in the toolchain's rustlib bin dir. No third-party cargo subcommands.
#
#   ./coverage.sh [min_pct]   # default 100; exits non-zero if src/ line coverage < min
#
# Mechanism (see https://doc.rust-lang.org/rustc/instrument-coverage.html):
#   1. build+run tests with `-C instrument-coverage` → one .profraw per test process
#   2. `llvm-profdata merge -sparse` the .profraw → a .profdata
#   3. `llvm-cov export --format=lcov` over the instrumented test binaries, scoped to
#      truenas-jsonrpc/src, then assert the line total and list any uncovered lines.
set -euo pipefail
cd "$(dirname "$0")"

MIN="${1:-100}"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
LLVMBIN="$(rustc --print sysroot)/lib/rustlib/$HOST/bin"
PROFDIR="target/coverage"

rm -rf "$PROFDIR"
mkdir -p "$PROFDIR/raw"

export RUSTFLAGS="-C instrument-coverage"
# %p (pid) + %m (binary signature) keep each test binary's raw profile distinct.
export LLVM_PROFILE_FILE="$PWD/$PROFDIR/raw/%p-%m.profraw"

# Build + run every test (──tests excludes doctests, which don't instrument).
cargo test --all-features --tests --locked --quiet

# The instrumented test binaries are the `-object`s llvm-cov reads coverage maps from.
mapfile -t BINS < <(
  cargo test --all-features --tests --locked --no-run --message-format=json 2>/dev/null \
    | tr ',' '\n' | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | sort -u
)
OBJ=()
for b in "${BINS[@]}"; do [ -n "$b" ] && OBJ+=(--object "$b"); done

"$LLVMBIN/llvm-profdata" merge -sparse "$PROFDIR"/raw/*.profraw -o "$PROFDIR/cov.profdata"

# Scope to this crate's src/: exclude deps, std, and our own tests/examples/build output.
IGNORE='--ignore-filename-regex=(/\.cargo/|/rustc/|/library/|/tests/|/examples/|/target/)'

# Merged line coverage, exported as lcov (the standard interchange format Codecov/Coveralls
# consume): a source line is covered if ANY test executed it. We deliberately gate on this
# rather than `llvm-cov report`'s line column — `report` sums lines *per object*, so the
# crate's generic code, monomorphized into each of the several test binaries, gets
# double-counted and shows phantom "missed" lines. The lcov merge is the true coverage.
"$LLVMBIN/llvm-cov" export --format=lcov --instr-profile="$PROFDIR/cov.profdata" "${OBJ[@]}" \
  "$IGNORE" >"$PROFDIR/cov.lcov"

echo "=== line coverage (merged, lcov) — gate: min ${MIN}% ==="
awk -v min="$MIN" '
  /^SF:/ { f = substr($0, 4); sub(/.*\/truenas-jsonrpc\//, "", f)
           if (!(f in seen)) { seen[f] = 1; order[++n] = f }
           cur = f }
  /^DA:/ { rec = substr($0, 4); k = index(rec, ",")
           ln = substr(rec, 1, k-1); c = substr(rec, k+1) + 0
           lf[cur]++; total++
           if (c == 0) miss[cur] = miss[cur] ln " "; else { lh[cur]++; hit++ } }
  END {
    printf "  %-22s %14s   %s\n", "file", "lines", "cover"
    printf "  %s\n", "----------------------------------------------------------"
    for (i = 1; i <= n; i++) { f = order[i]
      cov = lf[f] ? 100 * lh[f] / lf[f] : 100
      printf "  %-22s %6d/%-6d %7.2f%%\n", f, lh[f] + 0, lf[f] + 0, cov }
    printf "  %s\n", "----------------------------------------------------------"
    pct = total ? 100 * hit / total : 100
    printf "  %-22s %6d/%-6d %7.2f%%\n", "TOTAL", hit, total, pct
    for (i = 1; i <= n; i++) { f = order[i]; if (miss[f] != "") printf "\nUNCOVERED %s: %s", f, miss[f] }
    if (pct + 0 < min + 0) { printf "\nFAIL: line coverage %.2f%% < %d%%\n", pct, min; exit 1 }
    printf "\nOK: line coverage %.2f%% >= %d%%\n", pct, min
  }
' "$PROFDIR/cov.lcov"
