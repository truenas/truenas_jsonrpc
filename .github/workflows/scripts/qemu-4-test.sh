#!/usr/bin/env bash

######################################################################
# Provision the PAM services + test user, then run the full
# truenas_pyjsonrpc suite (incl. the real-PAM test_pam.py) and mypy.
######################################################################

set -eu

echo "Running tests..."

# Load VM info
source /tmp/vm-info.sh

# Run checks in the VM
ssh debian@$VM_IP 'bash -s' <<'REMOTE_SCRIPT'
set -eu

cd ~/truenas_pyjsonrpc/python

echo "=========================================="
echo "Provisioning PAM services + test user"
echo "=========================================="

# PAM service files the SCRAM tests use (verbatim from the pam_truenas test harness).
sudo tee /etc/pam.d/middleware <<'EOF'
#
# PAM configuration for the middleware service
#
auth	[success=1 default=ignore] pam_truenas.so debug allow_password_auth use_env_config
auth	[default=done] pam_truenas.so debug authfail
auth	required pam_truenas.so debug authsucc
auth	required	pam_permit.so

account sufficient pam_permit.so
session required pam_truenas.so debug session_utmp
session sufficient pam_permit.so
EOF

sudo tee /etc/pam.d/middleware-scram <<'EOF'
#
# PAM configuration for SCRAM authentication
#
auth	[success=1 default=ignore] pam_truenas.so debug use_env_config
auth	[default=done] pam_truenas.so debug authfail
auth	required pam_truenas.so debug authsucc
auth	required	pam_permit.so

account sufficient pam_permit.so
session required pam_truenas.so debug session_utmp
session sufficient pam_permit.so
EOF

# pwenc secret store (keyring encryption) and the user the tests provision an API key for.
sudo mkdir -p /data
sudo useradd -m -s /bin/bash bob || true

echo "=========================================="
echo "mypy (strict)"
echo "=========================================="
# The full optional stack is installed in the VM, so strict mypy is clean here.
python3 -m mypy truenas_pyjsonrpc truenas_pyjsonrpc_server truenas_pyjsonrpc_client codegen.py \
  2>&1 | tee ~/mypy-output.txt
MYPY_RC=${PIPESTATUS[0]}

echo "=========================================="
echo "pytest (full suite, incl. real pam_truenas)"
echo "=========================================="
# PAM auth + the kernel keyring need root, so run pytest under sudo.
sudo sh -c "cd /home/debian/truenas_pyjsonrpc/python && python3 -m pytest tests/ -v" \
  2>&1 | tee ~/test-output.txt
PYTEST_RC=${PIPESTATUS[0]}

RC=0
[ "$MYPY_RC" -eq 0 ] || RC=$MYPY_RC
[ "$PYTEST_RC" -eq 0 ] || RC=$PYTEST_RC
echo "$RC" > ~/test-exitcode.txt

echo "=========================================="
echo "mypy rc=$MYPY_RC  pytest rc=$PYTEST_RC  -> overall rc=$RC"
echo "=========================================="
exit $RC
REMOTE_SCRIPT

# Capture result and copy output back to the runner
TEST_EXIT_CODE=$?
scp debian@$VM_IP:~/test-output.txt /tmp/ || true
scp debian@$VM_IP:~/test-exitcode.txt /tmp/ || true
scp debian@$VM_IP:~/mypy-output.txt /tmp/ || true

if [ $TEST_EXIT_CODE -eq 0 ]; then
  echo "All checks passed!"
else
  echo "Checks failed with exit code: $TEST_EXIT_CODE"
  exit $TEST_EXIT_CODE
fi
