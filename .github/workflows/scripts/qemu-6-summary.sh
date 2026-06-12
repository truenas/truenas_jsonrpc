#!/usr/bin/env bash

######################################################################
# Display test summary
######################################################################

set -eu

echo "=========================================="
echo "Test Summary"
echo "=========================================="

if [ -f /tmp/test-exitcode.txt ]; then
  EXIT_CODE=$(cat /tmp/test-exitcode.txt)
  if [ "$EXIT_CODE" -eq 0 ]; then
    echo "Status: SUCCESS"
    echo "All checks (mypy + pytest) passed in the Debian Trixie QEMU VM"
  else
    echo "Status: FAILURE"
    echo "Checks failed with exit code: $EXIT_CODE"
  fi
else
  echo "Status: UNKNOWN"
  echo "Test exit code not found"
fi

if [ -f /tmp/test-output.txt ]; then
  echo ""
  echo "pytest summary:"
  echo "----------------------------------------"
  grep -E "(passed|failed|error|skipped)" /tmp/test-output.txt | tail -5 || true
fi

if [ -f /tmp/mypy-output.txt ]; then
  echo ""
  echo "mypy result:"
  echo "----------------------------------------"
  tail -3 /tmp/mypy-output.txt || true
fi

echo "=========================================="
