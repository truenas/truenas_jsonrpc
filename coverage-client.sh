#!/usr/bin/env bash
# Line coverage for `truenas-rpc-client/src` — the async client engine + transports + auth.
#
# The client is a behavioral, socket-I/O crate (kTLS, SCM_RIGHTS, WebSocket), so it is excluded from
# the workspace `coverage.sh` 100% gate — but it is still held to a floor here so its coverage does
# not silently regress. The remaining gap to 100% is hard-to-inject I/O error branches and the
# WebSocket adapter's `poll` edge cases; the floor guards the behavioral surface we *can* cover.
#
#   ./coverage-client.sh [min_pct]   # default 85; exits non-zero if src/ line coverage < min
#
# Uses only the toolchain's own tools (`rustc -C instrument-coverage` + the bundled
# llvm-profdata/llvm-cov), mirroring coverage.sh. Runs the client's own tests (all features)
# SERIALLY — the transfer tests race on shared temp files under the slower instrumented parallel run.
set -euo pipefail
cd "$(dirname "$0")"

MIN="${1:-85}"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
LLVMBIN="$(rustc --print sysroot)/lib/rustlib/$HOST/bin"
PROFDIR="target/coverage-client"

rm -rf "$PROFDIR"
mkdir -p "$PROFDIR/raw"
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="$PWD/$PROFDIR/raw/%p-%m.profraw"

cargo test -p truenas-rpc-client --all-features --tests --locked --quiet -- --test-threads=1

mapfile -t BINS < <(
  cargo test -p truenas-rpc-client --all-features --tests --locked --no-run --message-format=json 2>/dev/null \
    | tr ',' '\n' | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | sort -u
)
OBJ=()
for b in "${BINS[@]}"; do [ -n "$b" ] && OBJ+=(--object "$b"); done

"$LLVMBIN/llvm-profdata" merge -sparse "$PROFDIR"/raw/*.profraw -o "$PROFDIR/cov.profdata"

# Scope to truenas-rpc-client/src only: drop deps/std, tests/examples, and every other workspace crate.
IGNORE='--ignore-filename-regex=(/\.cargo/|/rustc/|/library/|/tests/|/examples/|/target/|truenas-rpc/|truenas-xdr|truenas-filter/|truenas-rpc-server/|truenas-rpc-codegen/|truenas-rpc-auth/|truenas-gssapi/|truenas-keyring/|truenas-audit/|truenas-rpc-pyo3/)'
"$LLVMBIN/llvm-cov" export --format=lcov --instr-profile="$PROFDIR/cov.profdata" "${OBJ[@]}" \
  "$IGNORE" >"$PROFDIR/cov.lcov"

echo "=== truenas-rpc-client/src line coverage — floor: min ${MIN}% ==="
awk -v min="$MIN" '
  /^SF:/ { f=substr($0,4); sub(/.*truenas-rpc-client\//,"",f)
           if (!(f in seen)) { seen[f]=1; order[++n]=f } cur=f }
  /^DA:/ { rec=substr($0,4); k=index(rec,","); ln=substr(rec,1,k-1); c=substr(rec,k+1)+0
           lf[cur]++; total++; if (c==0) miss[cur]=miss[cur] ln " "; else { lh[cur]++; hit++ } }
  END {
    for (i=1;i<=n;i++){ f=order[i]; cov=lf[f]?100*lh[f]/lf[f]:100
      printf "  %-22s %5d/%-5d %6.1f%%\n", f, lh[f]+0, lf[f]+0, cov }
    printf "  --------------------------------------------\n"
    pct = total ? 100*hit/total : 100
    printf "  %-22s %5d/%-5d %6.1f%%\n", "TOTAL", hit, total, pct
    for (i=1;i<=n;i++){ f=order[i]; if (miss[f]!="") printf "\nUNCOVERED %s: %s", f, miss[f] }
    if (pct + 0 < min + 0) { printf "\nFAIL: line coverage %.1f%% < %d%%\n", pct, min; exit 1 }
    printf "\nOK: line coverage %.1f%% >= %d%%\n", pct, min
  }' "$PROFDIR/cov.lcov"
