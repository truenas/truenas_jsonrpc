#!/usr/bin/env bash

######################################################################
# Rust dispatch-core A/B conformance, run inside the VM against a golden
# corpus generated from THIS repo's *real* Python.
#
# The VM has the full optional stack (truenas_pyfilter, SCRAM, PAM), so the
# corpus is authoritative as conformance grows to cover filterable/auth
# methods — and this guest is where Rust<->Python client/server conformance
# will eventually run (the Python server + its deps already live here).
#
#   1. (re)generate both golden corpora (protocol + filter-engine) from the repo's Python
#   2. cargo test  -> tests/conformance.rs replays them through the Rust core + filter engine
#   3. drift-check each committed golden against the freshly generated one
######################################################################

set -eu

echo "Running Rust conformance in the VM (golden from the repo's Python)..."

# Load VM info
source /tmp/vm-info.sh

ssh debian@$VM_IP 'bash -s' <<'REMOTE_SCRIPT'
set -eu

# Rust toolchain (Debian Trixie ships a recent rustc/cargo; `cargo` pulls `rustc`).
sudo apt-get install -y cargo

cd ~/truenas_pyjsonrpc
# Two golden corpora: the protocol A/B (dispatch core vs the Python reference) and the
# filter-engine A/B (truenas-filter vs the truenas_pyfilter C engine). Both are generated
# from the repo's Python and drift-checked.
PROTO_GOLDEN="rust/truenas-jsonrpc/tests/conformance/golden.json"
FILTER_GOLDEN="rust/truenas-filter/tests/conformance/golden.json"
cp "$PROTO_GOLDEN" /tmp/proto.committed.json
cp "$FILTER_GOLDEN" /tmp/filter.committed.json

echo "=========================================="
echo "Generating both golden corpora from the repo's Python"
echo "=========================================="
python3 rust/conformance/generate.py
python3 rust/truenas-filter/conformance/generate.py

echo "=========================================="
echo "cargo test (replays both goldens via tests/conformance.rs)"
echo "=========================================="
# conformance.rs embeds each golden.json via include_str! at compile time, so the
# regeneration above is exactly what this build/test runs against.
( cd rust && cargo test --locked )

echo "=========================================="
echo "Drift check: committed goldens vs the repo's Python"
echo "=========================================="
drift=0
if ! diff -u /tmp/proto.committed.json "$PROTO_GOLDEN"; then
  echo "ERROR: the committed protocol golden is stale — run 'python3 rust/conformance/generate.py' and commit."
  drift=1
fi
if ! diff -u /tmp/filter.committed.json "$FILTER_GOLDEN"; then
  echo "ERROR: the committed filter-engine golden is stale — run 'python3 rust/truenas-filter/conformance/generate.py' and commit."
  drift=1
fi
[ "$drift" -eq 0 ] || exit 1

echo "Rust conformance OK (Rust core + filter engine match, and both committed goldens are in sync)"
REMOTE_SCRIPT

echo "Rust conformance complete in VM"
