#!/usr/bin/env bash
# rsync the repo into the VM, install Rust + the TLS/krb5 deps, load the kernel `tls` ULP, and run
# the kTLS-dependent test combos. The guest cargo exit code propagates out (over SSH) to fail the
# CI step. Logs are pulled back by qemu-logs.sh in a separate always() step.
set -eu

VM_IP="192.168.122.10"

# The Debian cloud image ships without rsync; it must be present on BOTH ends, so install it in the
# guest before syncing (matches truenas_ros's qemu-3-build.sh).
echo "Installing rsync in the VM..."
ssh "debian@$VM_IP" "sudo apt-get update && sudo apt-get install -y rsync"

echo "Syncing the repo into the VM..."
ssh "debian@$VM_IP" "mkdir -p ~/repo"
rsync -az --exclude '.git' --exclude 'target/' --exclude '*/node_modules/' ./ "debian@$VM_IP:~/repo/"

echo "Running the kTLS tests in the VM..."
ssh "debian@$VM_IP" 'sudo bash -s' <<'REMOTE'
set -eu
export DEBIAN_FRONTEND=noninteractive CARGO_TERM_COLOR=never

apt-get update
# build-essential gives the linker/C toolchain cargo needs (the cloud image has none); libssl-dev +
# pkg-config for the OpenSSL-backed tls feature; libkrb5-dev is harmless headroom. Matches truenas_ros.
apt-get install -y --no-install-recommends build-essential cargo libssl-dev libkrb5-dev pkg-config ca-certificates

# kTLS needs the kernel `tls` ULP (in-tree in Debian's stock kernel). Load it and fail loudly if the
# config isn't there — otherwise the tests' own EBUSY would be a confusing failure.
modprobe tls || true
grep -qE 'CONFIG_TLS=[ym]' "/boot/config-$(uname -r)" || { echo "ERROR: guest kernel lacks CONFIG_TLS"; exit 1; }

cd ~/repo
# Tee everything for the log artifact; accumulate failures so all combos run, then exit non-zero if any failed.
exec > >(tee ~/test-output.txt) 2>&1
rc=0
cargo test -p truenas-rpc-client --no-default-features --features "tls" --locked || rc=1
cargo test -p truenas-rpc-client --no-default-features --features "scram" --locked || rc=1
cargo test -p truenas-rpc-client --no-default-features --features "tls websocket scram fd-passing" --locked || rc=1
cargo test -p truenas-rpc-server --no-default-features --features "tls" --locked || rc=1
cargo test -p truenas-rpc-server --no-default-features --features "tls websocket passthrough" --locked || rc=1
echo "$rc" > ~/test-exitcode.txt
exit "$rc"
REMOTE
