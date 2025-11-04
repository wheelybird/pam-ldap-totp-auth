#!/bin/bash
# Run all SSH TOTP authentication tests

set -e

echo "========================================"
echo "PAM LDAP TOTP - SSH Integration Tests"
echo "========================================"
echo ""

# Wait for SSH server to be ready
echo "Waiting for SSH server to start..."
sleep 5

# Test 1: Challenge-Response Mode
echo ""
echo "Test 1: Challenge-Response Mode (default)"
echo "----------------------------------------"
/test/test-challenge-mode.exp
TEST1_RESULT=$?

# Test 2: Append Mode (requires reconfiguration)
echo ""
echo "Test 2: Append Mode"
echo "----------------------------------------"
echo "NOTE: This test requires changing totp_mode to 'append' in config"
echo "Skipping append mode test (challenge mode is default)"
# /test/test-append-mode.exp
TEST2_RESULT=0

# Summary
echo ""
echo "========================================"
echo "Test Results Summary"
echo "========================================"
echo "Challenge-Response Mode: $([ $TEST1_RESULT -eq 0 ] && echo "PASS" || echo "FAIL")"
echo "Append Mode: SKIPPED (requires config change)"
echo "========================================"

if [ $TEST1_RESULT -eq 0 ]; then
    echo "✓ All configured tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi
