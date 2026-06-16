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
#   1. (re)generate rust/.../golden.json from the repo's Python
#   2. cargo test  -> tests/conformance.rs replays it through the Rust core
#   3. drift-check the committed golden against the freshly generated one
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
GOLDEN="rust/truenas-jsonrpc/tests/conformance/golden.json"
cp "$GOLDEN" /tmp/golden.committed.json

echo "=========================================="
echo "Generating the golden corpus from the repo's Python"
echo "=========================================="
python3 rust/conformance/generate.py

echo "=========================================="
echo "cargo test (incl. tests/conformance.rs vs the freshly generated golden)"
echo "=========================================="
# conformance.rs embeds golden.json via include_str! at compile time, so the
# regeneration above is exactly what this build/test runs against.
( cd rust && cargo test --locked )

echo "=========================================="
echo "Drift check: committed golden vs the repo's Python"
echo "=========================================="
if ! diff -u /tmp/golden.committed.json "$GOLDEN"; then
  echo "ERROR: the committed golden corpus is stale vs the repo's Python."
  echo "Regenerate it ('python3 rust/conformance/generate.py') and commit."
  exit 1
fi

echo "Rust conformance OK (Rust core matches, and the committed golden is in sync)"
REMOTE_SCRIPT

echo "Rust conformance complete in VM"
