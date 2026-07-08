#!/usr/bin/env bash
# Best-effort: pull the test output + guest kernel/system logs back and tar them for the artifact.
# Never fails the step (runs in an always() step).
set +e

VM_IP="192.168.122.10"
LOG_DIR="/tmp/vm-test-logs"
mkdir -p "$LOG_DIR"

scp "debian@$VM_IP:~/test-output.txt" "$LOG_DIR/" 2>/dev/null
scp "debian@$VM_IP:~/test-exitcode.txt" "$LOG_DIR/" 2>/dev/null
ssh "debian@$VM_IP" "sudo journalctl -n 1000 --no-pager" > "$LOG_DIR/journalctl.log" 2>/dev/null
ssh "debian@$VM_IP" "dmesg | tail -200" > "$LOG_DIR/dmesg.log" 2>/dev/null

tar czf /tmp/vm-test-logs.tar.gz -C /tmp vm-test-logs 2>/dev/null
echo "logs collected"
exit 0
