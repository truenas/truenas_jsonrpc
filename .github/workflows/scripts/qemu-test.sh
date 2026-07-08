#!/usr/bin/env bash
# rsync the repo into the VM and run the tests that need a real kernel a GitHub runner can't give us:
# the kTLS (`TlsMode::Kernel`) feature combos, the client line-coverage floor (coverage-client.sh,
# which exercises those same kTLS paths), and the embedded-CPython demo-py round-trip. The guest exit
# code propagates out (over SSH) to fail the CI step. Logs are pulled back by qemu-logs.sh.
set -eu

VM_IP="192.168.122.10"

# The Debian cloud image ships without rsync; it must be present on BOTH ends, so install it in the
# guest before syncing (matches truenas_ros's qemu-3-build.sh).
echo "Installing rsync in the VM..."
ssh "debian@$VM_IP" "sudo apt-get update && sudo apt-get install -y rsync"

echo "Syncing the repo into the VM..."
ssh "debian@$VM_IP" "mkdir -p ~/repo"
rsync -az --exclude '.git' --exclude 'target/' --exclude '*/node_modules/' ./ "debian@$VM_IP:~/repo/"

echo "Running the VM-based tests..."
ssh "debian@$VM_IP" 'sudo bash -s' <<'REMOTE'
set -eu
export DEBIAN_FRONTEND=noninteractive CARGO_TERM_COLOR=never

apt-get update
# build-essential gives the linker/C toolchain; libssl-dev + pkg-config for the OpenSSL-backed `tls`
# feature and the core's OpenSSL RNG; libkrb5-dev is harmless headroom; python3-dev + pip for demo-py's
# embedded CPython; curl to fetch rustup.
apt-get install -y --no-install-recommends \
  build-essential libssl-dev libkrb5-dev pkg-config ca-certificates curl \
  python3 python3-dev python3-pip

# Rust via rustup, NOT apt `cargo`: coverage-client.sh instruments with `-C instrument-coverage` and
# needs the toolchain's own llvm-profdata/llvm-cov (the `llvm-tools-preview` component), which the
# Debian cargo package does not ship. Minimal profile keeps it lean.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --component llvm-tools-preview
. "$HOME/.cargo/env"

# msgspec into the system python3 (the interpreter demo-py's pyo3-ffi embeds). Trixie's pip is
# PEP 668 externally-managed, hence --break-system-packages.
pip3 install --break-system-packages msgspec

# kTLS needs the kernel `tls` ULP (in-tree in Debian's stock kernel). Load it and fail loudly if the
# config isn't there — otherwise the tests' own EBUSY would be a confusing failure.
modprobe tls || true
grep -qE 'CONFIG_TLS=[ym]' "/boot/config-$(uname -r)" || { echo "ERROR: guest kernel lacks CONFIG_TLS"; exit 1; }

# Absolute paths, not ~: this heredoc runs under `sudo bash`, where HOME=/root, but the repo was
# rsynced as the `debian` user to /home/debian/repo (and qemu-logs.sh scps the output from there).
cd /home/debian/repo
# Tee everything for the log artifact; accumulate failures so all suites run, then exit non-zero if any failed.
exec > >(tee /home/debian/test-output.txt) 2>&1
rc=0
# kTLS (`TlsMode::Kernel`) feature combos — the reason a runner can't host these.
cargo test -p truenas-rpc-client --no-default-features --features "tls" --locked || rc=1
cargo test -p truenas-rpc-client --no-default-features --features "scram" --locked || rc=1
cargo test -p truenas-rpc-client --no-default-features --features "tls websocket scram fd-passing" --locked || rc=1
cargo test -p truenas-rpc-server --no-default-features --features "tls" --locked || rc=1
cargo test -p truenas-rpc-server --no-default-features --features "tls websocket passthrough" --locked || rc=1
# Client line-coverage floor — measured here where kTLS actually engages, so tls.rs is fully covered.
bash coverage-client.sh 85 || rc=1
# demo-py: the generated msgspec client round-trip + a python:true body over embedded CPython.
cargo test -p demo-py --locked || rc=1
echo "$rc" > /home/debian/test-exitcode.txt
exit "$rc"
REMOTE
