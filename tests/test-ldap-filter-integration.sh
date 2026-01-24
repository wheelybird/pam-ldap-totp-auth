#!/bin/bash
#
# Integration tests for ldap_filter functionality
# Tests LDAP filter combination logic with an actual LDAP server
#
# Prerequisites:
#   - LDAP server running (e.g., Docker OpenLDAP)
#   - Test users and groups configured
#   - memberOf overlay enabled
#
# Usage: ./test-ldap-filter-integration.sh

set -e

# Colours for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

# Configuration
LDAP_URI="${LDAP_URI:-ldap://localhost}"
LDAP_BASE="${LDAP_BASE:-dc=example,dc=com}"
LDAP_ADMIN_DN="${LDAP_ADMIN_DN:-cn=admin,dc=example,dc=com}"
LDAP_ADMIN_PW="${LDAP_ADMIN_PW:-password}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

echo "========================================="
echo "LDAP Filter Integration Tests"
echo "========================================="
echo ""
echo "Configuration:"
echo "  LDAP URI:   $LDAP_URI"
echo "  LDAP Base:  $LDAP_BASE"
echo "  Admin DN:   $LDAP_ADMIN_DN"
echo ""

# Check if LDAP server is reachable
echo "Checking LDAP server connectivity..."
if ! ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" -s base "(objectClass=*)" > /dev/null 2>&1; then
    echo -e "${RED}❌ FAIL: Cannot connect to LDAP server at $LDAP_URI${NC}"
    echo "   Please ensure LDAP server is running and credentials are correct."
    exit 1
fi
echo -e "${GREEN}✅ LDAP server is reachable${NC}"
echo ""

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    local description="$4"

    TESTS_RUN=$((TESTS_RUN + 1))

    echo "Test $TESTS_RUN: $test_name"
    if [ -n "$description" ]; then
        echo "  Description: $description"
    fi

    if eval "$test_command" > /dev/null 2>&1; then
        if [ "$expected_result" = "success" ]; then
            echo -e "  ${GREEN}✅ PASS${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "  ${RED}❌ FAIL (expected failure, got success)${NC}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        if [ "$expected_result" = "failure" ]; then
            echo -e "  ${GREEN}✅ PASS (failed as expected)${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "  ${RED}❌ FAIL (expected success, got failure)${NC}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
    echo ""
}

# Function to check if result has entries
has_entries() {
    local filter="$1"
    local result=$(ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" "$filter" uid 2>/dev/null)
    [[ -n "$result" && "$result" != *"No such object"* ]]
}

# Function to check if result has no entries
has_no_entries() {
    local filter="$1"
    local result=$(ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" "$filter" uid 2>/dev/null)
    [[ -z "$result" || "$result" == *"No such object"* ]]
}

echo "========================================="
echo "Basic Filter Tests"
echo "========================================="
echo ""

# Test 1: Simple username filter (no additional filter)
run_test \
    "Simple username filter" \
    "has_entries '(uid=vpnuser1)'" \
    "success" \
    "Basic filter without additional constraints"

# Test 2: Combined filter (username + memberOf)
run_test \
    "Combined filter (username + memberOf)" \
    "has_entries '(&(uid=vpnuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))'" \
    "success" \
    "User vpnuser1 should be in vpn-users group"

# Test 3: Combined filter (user not in group)
run_test \
    "Combined filter (user not in group)" \
    "has_no_entries '(&(uid=sshuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))'" \
    "success" \
    "User sshuser1 should NOT be in vpn-users group"

echo "========================================="
echo "OR Filter Tests"
echo "========================================="
echo ""

# Test 4: OR filter (multiple groups)
run_test \
    "OR filter (vpn-users OR ssh-users)" \
    "has_entries '(&(uid=vpnuser1)(|(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)(memberOf=cn=ssh-users,ou=groups,dc=example,dc=com)))'" \
    "success" \
    "User vpnuser1 is in vpn-users, should match OR filter"

# Test 5: OR filter (other group)
run_test \
    "OR filter (ssh user in ssh-users)" \
    "has_entries '(&(uid=sshuser1)(|(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)(memberOf=cn=ssh-users,ou=groups,dc=example,dc=com)))'" \
    "success" \
    "User sshuser1 is in ssh-users, should match OR filter"

echo "========================================="
echo "Complex Filter Tests"
echo "========================================="
echo ""

# Test 6: Nested AND filter
run_test \
    "Nested AND filter" \
    "has_entries '(&(&(uid=vpnuser1)(objectClass=inetOrgPerson))(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))'" \
    "success" \
    "User vpnuser1 with objectClass inetOrgPerson in vpn-users"

# Test 7: NOT filter
run_test \
    "NOT filter (not in ssh-users)" \
    "has_entries '(&(uid=vpnuser1)(!(memberOf=cn=ssh-users,ou=groups,dc=example,dc=com)))'" \
    "success" \
    "User vpnuser1 is NOT in ssh-users"

# Test 8: NOT filter (is in group)
run_test \
    "NOT filter (is in vpn-users)" \
    "has_no_entries '(&(uid=vpnuser1)(!(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)))'" \
    "success" \
    "User vpnuser1 IS in vpn-users, should not match NOT filter"

echo "========================================="
echo "Edge Cases"
echo "========================================="
echo ""

# Test 9: Wildcard in combined filter
run_test \
    "Wildcard in filter" \
    "has_entries '(&(uid=vpn*)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))'" \
    "success" \
    "Wildcard uid=vpn* should match vpnuser1 in vpn-users"

# Test 10: Non-existent group
run_test \
    "Non-existent group filter" \
    "has_no_entries '(&(uid=vpnuser1)(memberOf=cn=nonexistent,ou=groups,dc=example,dc=com))'" \
    "success" \
    "User should not be in non-existent group"

echo "========================================="
echo "memberOf Overlay Verification"
echo "========================================="
echo ""

# Test 11: Check if memberOf attribute exists
echo "Test: Checking for memberOf overlay support..."
MEMBEROF_CHECK=$(ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" "(uid=vpnuser1)" memberOf 2>/dev/null)
if echo "$MEMBEROF_CHECK" | grep -q "memberOf:"; then
    echo -e "${GREEN}✅ memberOf overlay is enabled and working${NC}"
    echo "   User vpnuser1 has memberOf attributes:"
    echo "$MEMBEROF_CHECK" | grep "memberOf:" | sed 's/^/     /'
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}⚠️  WARNING: memberOf overlay may not be enabled${NC}"
    echo "   Filter tests may fail if memberOf is not configured"
    echo "   See: https://www.openldap.org/doc/admin24/overlays.html#Reverse%20Group%20Membership%20Maintenance"
    TESTS_RUN=$((TESTS_RUN + 1))
fi
echo ""

echo "========================================="
echo "Filter Syntax Validation"
echo "========================================="
echo ""

# Test 12: Invalid filter (unbalanced parens)
echo "Test: Invalid filter syntax (should fail)..."
INVALID_FILTER_RESULT=$(ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" "(&(uid=vpnuser1)(memberOf=cn=vpn-users" uid 2>&1 || true)
if echo "$INVALID_FILTER_RESULT" | grep -q -i "bad search filter"; then
    echo -e "${GREEN}✅ Invalid filter correctly rejected by LDAP server${NC}"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}⚠️  LDAP server did not reject invalid filter (may depend on server implementation)${NC}"
    TESTS_RUN=$((TESTS_RUN + 1))
fi
echo ""

echo "========================================="
echo "Test Summary"
echo "========================================="
echo ""
echo "Tests run:    $TESTS_RUN"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
else
    echo -e "Tests failed: $TESTS_FAILED"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}All integration tests passed!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    exit 0
else
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED}Some tests failed!${NC}"
    echo -e "${RED}=========================================${NC}"
    exit 1
fi
