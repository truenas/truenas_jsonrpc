#!/usr/bin/env bash
# Set up the QEMU/libvirt environment on the GitHub runner: packages, a throwaway SSH key for the
# guest, and a running libvirtd. Adapted from truenas_ros's qemu-1-setup.sh (no ZFS bits).
set -eu

export DEBIAN_FRONTEND=noninteractive
sudo apt-get -y update
sudo apt-get install -y --no-install-recommends \
  cloud-image-utils guestfs-tools virtinst qemu-system-x86 qemu-utils \
  libvirt-daemon-system libvirt-clients ovmf dnsmasq rsync wget

# A throwaway SSH key the guest trusts (public half goes into cloud-init).
rm -f ~/.ssh/id_ed25519
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -q -N ""

# Free resources and let libvirt own its own dnsmasq instance.
sudo systemctl stop docker.socket || true
sudo systemctl stop multipathd.socket || true
sudo systemctl stop dnsmasq || true
sudo systemctl disable dnsmasq || true
sudo systemctl mask dnsmasq || true

# The guest is an ephemeral VM on a fixed local IP — don't prompt or persist host keys.
mkdir -p "$HOME/.ssh"
cat <<'EOF' >> "$HOME/.ssh/config"
Host 192.168.122.10
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  ConnectTimeout 10
EOF

sudo systemctl start libvirtd
sudo systemctl enable libvirtd
sudo usermod -a -G libvirt "$USER"

echo "qemu/libvirt setup complete"
