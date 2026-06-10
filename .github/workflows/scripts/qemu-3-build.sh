#!/usr/bin/env bash

######################################################################
# Build the TrueNAS PAM/SCRAM dependency stack and stage
# truenas_pyjsonrpc inside the VM.
#
# test_pam.py drives the real pam_truenas module, so the VM needs the
# whole chain that test imports:
#   truenas_scram     -> python3-truenas-scram      (truenas_pyscram)
#   truenas_pwenc     -> python3-truenas-pwenc       (truenas_pypwenc)
#   truenas_pykeyring -> python3-truenas-pykeyring   (truenas_keyring + truenas_api_key)
#   truenas_pypam     -> python3-truenas-pypam       (truenas_pypam + truenas_authenticator)
#   pam_truenas       -> libpam-truenas + python3-truenas-pam-utils
#                                                    (pam_truenas.so + truenas_pam_faillog)
######################################################################

set -eu

echo "Building dependency stack and staging truenas_pyjsonrpc..."

# Load VM info
source /tmp/vm-info.sh

# Wait for cloud-init to finish
echo "Waiting for cloud-init to complete..."
ssh debian@$VM_IP "cloud-init status --wait" || true

# Install rsync in the VM first
echo "Installing rsync in VM..."
ssh debian@$VM_IP "sudo apt-get update && sudo apt-get install -y rsync"

# Copy this repo into the VM
echo "Copying source code to VM..."
ssh debian@$VM_IP "mkdir -p ~/truenas_pyjsonrpc"
rsync -az --exclude='.git' "$GITHUB_WORKSPACE/" debian@$VM_IP:~/truenas_pyjsonrpc/

# Build the dependency chain and install runtime/test deps in the VM
ssh debian@$VM_IP 'bash -s' <<'REMOTE_SCRIPT'
set -eu

sudo apt-get update

# Build deps for the TrueNAS C/PAM stack + runtime/test deps for truenas_pyjsonrpc
sudo apt-get install -y \
  build-essential devscripts debhelper dh-autoreconf dh-python \
  autoconf automake libtool pkg-config \
  libpam0g-dev libkeyutils-dev libjansson-dev uuid-dev libssl-dev libbsd-dev libidn-dev \
  python3-dev python3-all-dev python3-pip python3-setuptools python3-build python3-installer \
  python3-pycryptodome pybuild-plugin-pyproject git \
  python3-msgspec python3-pytest python3-cryptography python3-websockets python3-mypy

# Clone + build a TrueNAS source package in /tmp (its .debs land in /tmp).
clone_build() {
  local repo="$1"
  echo "=== Building ${repo} ==="
  cd /tmp
  rm -rf "${repo}"
  git clone --depth 1 "https://github.com/truenas/${repo}.git"
  cd "${repo}"
  dpkg-buildpackage -us -uc -b
}

# 1. SCRAM (RFC 5802) C library + Python bindings -> truenas_pyscram
clone_build truenas_scram
sudo dpkg -i ../libtruenas-scram1_*.deb \
             ../libtruenas-scram-dev_*.deb \
             ../python3-truenas-scram_*.deb

# 2. Password-encryption library -> truenas_pypwenc
clone_build truenas_pwenc
sudo dpkg -i ../libtruenas-pwenc1_*.deb \
             ../libtruenas-pwenc-dev_*.deb \
             ../python3-truenas-pwenc_*.deb

# 3. Keyring + API-key helpers -> truenas_keyring + truenas_api_key
clone_build truenas_pykeyring
sudo dpkg -i ../python3-truenas-pykeyring_*.deb

# 4. PAM authenticator bindings -> truenas_pypam + truenas_authenticator
clone_build truenas_pypam
sudo dpkg -i ../python3-truenas-pypam_*.deb

# 5. The PAM module itself -> pam_truenas.so + truenas_pam_faillog
clone_build pam_truenas
sudo dpkg -i ../libpam-truenas_*.deb \
             ../python3-truenas-pam-utils_*.deb

# Verify everything test_pam.py imports is present
echo "Verifying dependency stack..."
python3 -c "import truenas_pyscram, truenas_pypwenc, truenas_keyring, truenas_api_key, truenas_authenticator, truenas_pypam; from truenas_pam_faillog import PamFaillog; print('dependency stack OK')"
test -f /usr/lib/security/pam_truenas.so || (echo "ERROR: pam_truenas.so not found"; exit 1)

echo "Dependency stack built and installed"
REMOTE_SCRIPT

echo "Build complete in VM"
