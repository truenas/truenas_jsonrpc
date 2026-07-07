#!/usr/bin/env bash
# Download the Debian Trixie cloud image, boot it via virt-install + cloud-init, and wait for SSH.
# Adapted from truenas_ros's qemu-2-start.sh — kTLS needs no ZFS/kernel build, just a stock kernel.
set -eu

URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2"
VM_NAME="ktls"
VM_IP="192.168.122.10"
VM_MAC="52:54:00:83:79:10"
CACHE_DIR="$HOME/vm-cache"
WORK_DIR="/tmp/qemu-work"
mkdir -p "$CACHE_DIR" "$WORK_DIR"

# Base image, cached across runs (actions/cache on ~/vm-cache); download to a temp name and rename
# only on success so a partial download is never cached as complete.
if [ ! -f "$CACHE_DIR/debian-trixie.qcow2" ]; then
  echo "Downloading Debian Trixie cloud image..."
  wget -q --continue --tries=3 --timeout=120 "$URL" -O "$CACHE_DIR/debian-trixie.qcow2.part"
  mv "$CACHE_DIR/debian-trixie.qcow2.part" "$CACHE_DIR/debian-trixie.qcow2"
fi

# A fresh overlay on top of the pristine base (cloud-init writes only to the overlay).
qemu-img create -f qcow2 -F qcow2 -b "$CACHE_DIR/debian-trixie.qcow2" "$WORK_DIR/vm-disk.qcow2" 40G

PUBKEY=$(cat ~/.ssh/id_ed25519.pub)
cat <<EOF > /tmp/user-data
#cloud-config
hostname: ktls
users:
- name: debian
  sudo: ALL=(ALL) NOPASSWD:ALL
  shell: /bin/bash
  ssh_authorized_keys:
    - $PUBKEY
growpart:
  mode: auto
  devices: ['/']
  ignore_growroot_disabled: false
EOF

# libvirt default network + a static DHCP reservation, so the VM lands on a known IP.
sudo virsh net-destroy default 2>/dev/null || true
sudo virsh net-start default
sudo virsh net-autostart default
for _ in $(seq 1 10); do ip link show virbr0 >/dev/null 2>&1 && break; sleep 2; done
sudo virsh net-update default add ip-dhcp-host "<host mac='$VM_MAC' ip='$VM_IP'/>" --live --config || true

echo "Starting VM..."
sudo virt-install \
  --name "$VM_NAME" \
  --os-variant debian12 \
  --cpu host-passthrough \
  --virt-type=kvm \
  --vcpus=4 \
  --memory 8192 \
  --graphics none \
  --network bridge=virbr0,model=virtio,mac="$VM_MAC" \
  --cloud-init user-data=/tmp/user-data \
  --disk path="$WORK_DIR/vm-disk.qcow2",format=qcow2,bus=virtio \
  --boot uefi=on,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no \
  --import \
  --noautoconsole >/dev/null

echo "Waiting for SSH..."
for i in $(seq 1 60); do
  if ssh -o ConnectTimeout=2 "debian@$VM_IP" "echo ready" 2>/dev/null; then
    echo "VM is up"
    break
  fi
  echo "waiting for VM... ($i/60)"
  sleep 5
done
ssh "debian@$VM_IP" "uname -a" || { echo "ERROR: VM not reachable over SSH"; exit 1; }
