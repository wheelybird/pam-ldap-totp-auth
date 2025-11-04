#!/bin/bash
# Run all unit tests

set -e

cd /build/ldap-totp-pam/tests

echo "========================================"
echo "Running PAM LDAP TOTP Unit Tests"
echo "========================================"
echo

for test in test_config test_ldap_auth test_totp test_security test_challenge_response; do
    if [ -f "./$test" ]; then
        echo "Running $test..."
        ./$test
        echo
    else
        echo "WARNING: $test not found, skipping"
        echo
    fi
done

echo "========================================"
echo "All test suites completed successfully!"
echo "========================================"
