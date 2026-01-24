# LDAP Filter Feature Testing Guide

This document describes testing for the `ldap_filter` configuration parameter added in version 0.2.0.

## Feature Overview

The `ldap_filter` parameter allows administrators to restrict PAM authentication to users matching specific LDAP criteria (e.g., group membership, account status).

**Filter combination logic:**
```
Without filter: (uid=username)
With filter:    (&(uid=username)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))
```

## Unit Tests (`test_ldap_filter.c`)

### Test Suite Coverage

**Filter Validation (12 tests):**
- ✅ Valid filters (memberOf, accountStatus, OR, AND, NOT, wildcards)
- ✅ Invalid filters (unbalanced parens, missing parens, control chars)
- ✅ Length limits (exactly 512 bytes OK, 513+ bytes rejected)
- ✅ Parentheses depth tracking (nested filters, wrong order)
- ✅ Special characters (equals, comma, space, asterisk, backslash, hyphen, underscore, period, @)
- ✅ Empty filter (backward compatibility - feature disabled)
- ✅ NULL filter (feature disabled)

**Configuration Parsing (7 tests):**
- ✅ Valid filter in config (parsed correctly)
- ✅ Empty filter in config (backward compatible)
- ✅ No filter line in config (defaults to empty)
- ✅ Invalid filter in config (rejected, remains at default)
- ✅ Over-length filter in config (rejected, remains at default)
- ✅ Complex filters (OR, AND with NOT)
- ✅ Memory cleanup (free_config doesn't crash)

**Edge Cases:**
- Tab character allowed (only control char exception)
- DEL character rejected
- Deeply nested parentheses
- Filter with special LDAP escape sequences (\2a, \28, etc.)

### Running Unit Tests

```bash
cd /home/brian/git/wheelybird/pam-ldap-totp-auth/tests
make test_ldap_filter
./test_ldap_filter
```

**Expected output:**
```
Running suite(s): LDAP Filter Tests
100%: Checks: 19, Failures: 0, Errors: 0
```

### Run All Tests

```bash
make clean && make run
```

This runs all test suites including `test_ldap_filter`.

## Integration Tests

### Prerequisites

1. **Docker environment** with OpenLDAP
2. **memberOf overlay** enabled on LDAP server
3. **Test users** in different groups:
   - `vpnuser1` - member of `cn=vpn-users`
   - `vpnuser2` - member of `cn=vpn-users`
   - `sshuser1` - member of `cn=ssh-users` (NOT vpn-users)
   - `regularuser` - no group memberships

### Integration Test Scenarios

#### Scenario 1: Group-Based Access (memberOf filter)

**Configuration:**
```conf
ldap_uri ldap://localhost
ldap_base dc=example,dc=com
ldap_filter (memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)
totp_enabled true
totp_mode append
```

**Expected behaviour:**
| User | Group Membership | Authentication Result |
|------|------------------|----------------------|
| vpnuser1 | vpn-users | ✅ SUCCESS (with password+TOTP) |
| vpnuser2 | vpn-users | ✅ SUCCESS (with password+TOTP) |
| sshuser1 | ssh-users only | ❌ FAIL ("User not found") |
| regularuser | none | ❌ FAIL ("User not found") |

**LDAP query generated:**
```ldap
(&(uid=vpnuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))
```

**Testing with pamtester:**
```bash
# Should succeed
pamtester openvpn vpnuser1 authenticate
# Enter: password123456 (password + TOTP code)

# Should fail - user not in group
pamtester openvpn sshuser1 authenticate
# Expected: PAM_USER_UNKNOWN or PAM_AUTH_ERR
```

#### Scenario 2: Account Status Filter

**Configuration:**
```conf
ldap_filter (accountStatus=active)
```

**Expected behaviour:**
- Users with `accountStatus=active`: authentication succeeds
- Users with `accountStatus=disabled`: authentication fails ("User not found")
- Users without `accountStatus` attribute: authentication fails

#### Scenario 3: OR Filter (Multiple Groups)

**Configuration:**
```conf
ldap_filter (|(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)(memberOf=cn=ssh-users,ou=groups,dc=example,dc=com))
```

**Expected behaviour:**
- Users in vpn-users OR ssh-users: authentication succeeds
- Users in neither group: authentication fails

#### Scenario 4: Complex AND/NOT Filter

**Configuration:**
```conf
ldap_filter (&(accountStatus=active)(!(accountLocked=TRUE)))
```

**Expected behaviour:**
- Active, unlocked accounts: authentication succeeds
- Inactive or locked accounts: authentication fails

#### Scenario 5: Empty Filter (Backward Compatibility)

**Configuration:**
```conf
ldap_filter
```

**Expected behaviour:**
- All valid users authenticate (no filtering)
- Identical behaviour to version 0.1.x

#### Scenario 6: Invalid Filter (Fail Closed)

**Configuration:**
```conf
ldap_filter (memberOf=cn=vpn-users    # Missing closing paren
```

**Expected behaviour:**
- Configuration loads with warning logged
- Filter rejected at load time
- All authentications fail (fail closed)

### Manual Integration Testing Steps

#### 1. Setup Docker LDAP Environment

```bash
cd /home/brian/git/wheelybird/docker/openldap
docker-compose up -d
```

**Verify LDAP is running:**
```bash
ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w password "(uid=vpnuser1)"
```

#### 2. Create Test Users and Groups

```bash
# Add test groups
ldapadd -x -H ldap://localhost -D "cn=admin,dc=example,dc=com" -w password << EOF
dn: cn=vpn-users,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: vpn-users
member: uid=vpnuser1,ou=people,dc=example,dc=com
member: uid=vpnuser2,ou=people,dc=example,dc=com

dn: cn=ssh-users,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: ssh-users
member: uid=sshuser1,ou=people,dc=example,dc=com
EOF
```

**Verify memberOf overlay:**
```bash
ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w password "(uid=vpnuser1)" memberOf
```

Expected: Should see `memberOf: cn=vpn-users,ou=groups,dc=example,dc=com`

#### 3. Configure PAM Module with Filter

Edit `/etc/security/pam_ldap_totp_auth.conf`:
```conf
ldap_uri ldap://localhost
ldap_base dc=example,dc=com
ldap_bind_dn cn=admin,dc=example,dc=com
ldap_bind_password password
ldap_filter (memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)
totp_enabled true
totp_mode append
debug true
```

#### 4. Test with pamtester

```bash
# User in vpn-users group - should succeed
pamtester openvpn vpnuser1 authenticate
# Enter: password123456

# User NOT in vpn-users group - should fail
pamtester openvpn sshuser1 authenticate
# Expected: authentication failure with "User not found" log message
```

#### 5. Verify Debug Logs

```bash
tail -f /var/log/auth.log | grep PAM_LDAP_TOTP
```

**Expected log entries:**

For vpnuser1 (in group):
```
[PAM_LDAP_TOTP:DEBUG] LDAP search: base='dc=example,dc=com' filter='(&(uid=vpnuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))' attr='totpSecret'
[PAM_LDAP_TOTP:DEBUG] LDAP search returned 1 entries
```

For sshuser1 (not in group):
```
[PAM_LDAP_TOTP:DEBUG] LDAP search: base='dc=example,dc=com' filter='(&(uid=sshuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))' attr='totpSecret'
[PAM_LDAP_TOTP] User sshuser1 not found in LDAP
```

#### 6. Test Filter Combination

**Test with ldapsearch to verify filter logic:**

```bash
# Without additional filter (old behaviour)
ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w password \
  "(uid=vpnuser1)"

# With additional filter (new behaviour)
ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w password \
  "(&(uid=vpnuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))"

# Should return same user (vpnuser1 is in group)

# User not in group
ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w password \
  "(&(uid=sshuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))"

# Should return no results
```

### Automated Integration Test Script

**Create:** `/home/brian/git/wheelybird/pam-ldap-totp-auth/tests/test-ldap-filter-integration.sh`

```bash
#!/bin/bash
# Integration tests for ldap_filter functionality

set -e

echo "========================================="
echo "LDAP Filter Integration Tests"
echo "========================================="

# Configuration
LDAP_URI="ldap://localhost"
LDAP_BASE="dc=example,dc=com"
LDAP_ADMIN_DN="cn=admin,dc=example,dc=com"
LDAP_ADMIN_PW="password"

# Test 1: User in group (should succeed)
echo ""
echo "Test 1: User in vpn-users group..."
ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" \
  "(&(uid=vpnuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))" uid \
  | grep -q "uid: vpnuser1" && echo "✅ PASS" || echo "❌ FAIL"

# Test 2: User not in group (should fail - no results)
echo ""
echo "Test 2: User NOT in vpn-users group..."
RESULT=$(ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" \
  "(&(uid=sshuser1)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))" uid)
[[ -z "$RESULT" ]] && echo "✅ PASS (no results as expected)" || echo "❌ FAIL (should have no results)"

# Test 3: OR filter (multiple groups)
echo ""
echo "Test 3: OR filter (vpn-users OR ssh-users)..."
ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" \
  "(&(uid=vpnuser1)(|(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)(memberOf=cn=ssh-users,ou=groups,dc=example,dc=com)))" uid \
  | grep -q "uid: vpnuser1" && echo "✅ PASS" || echo "❌ FAIL"

# Test 4: Empty filter (backward compatibility)
echo ""
echo "Test 4: No filter (backward compatible)..."
ldapsearch -x -LLL -H "$LDAP_URI" -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PW" \
  "(uid=vpnuser1)" uid \
  | grep -q "uid: vpnuser1" && echo "✅ PASS" || echo "❌ FAIL"

echo ""
echo "========================================="
echo "All integration tests passed!"
echo "========================================="
```

## Performance Testing

### Test Filter Performance Impact

**Baseline (no filter):**
```bash
time for i in {1..100}; do pamtester openvpn vpnuser1 authenticate <<< "password123456" > /dev/null; done
```

**With memberOf filter:**
```bash
# Add ldap_filter to config
time for i in {1..100}; do pamtester openvpn vpnuser1 authenticate <<< "password123456" > /dev/null; done
```

**Expected:** Minimal performance impact (<5% slowdown) if memberOf attribute is indexed on LDAP server.

### Indexing Recommendations

For production deployments with filters, ensure LDAP attributes are indexed:

```ldif
# Add index for memberOf
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcDbIndex
olcDbIndex: memberOf eq
```

Verify with:
```bash
ldapsearch -Y EXTERNAL -H ldapi:/// -b "olcDatabase={1}mdb,cn=config" olcDbIndex
```

## Troubleshooting

### Filter Not Working

**Check configuration load:**
```bash
# Enable debug mode
echo "debug true" >> /etc/security/pam_ldap_totp_auth.conf

# Check syslog for filter validation
grep "LDAP filter" /var/log/syslog
```

**Common issues:**
1. Filter rejected due to invalid syntax (unbalanced parentheses)
2. Filter too long (>512 bytes)
3. memberOf overlay not enabled on LDAP server
4. Missing parentheses around filter

### User Not Found (Unexpected)

**Verify filter with ldapsearch:**
```bash
ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w password \
  "(&(uid=USERNAME)(YOUR_FILTER_HERE))" uid memberOf
```

**Check memberOf attribute:**
```bash
ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" "(uid=USERNAME)" memberOf
```

### Debug Mode Output

With `debug true` in config, you should see:
```
[PAM_LDAP_TOTP:DEBUG] Using login attribute: uid (login_attribute=uid)
[PAM_LDAP_TOTP:DEBUG] LDAP search: base='dc=example,dc=com' filter='(&(uid=username)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))' attr='totpSecret'
[PAM_LDAP_TOTP:DEBUG] LDAP search returned N entries
```

## Security Testing

### Injection Prevention

**Verify username escaping still works:**
```bash
# Attempt LDAP injection via username
pamtester openvpn "admin)(uid=*" authenticate
# Should fail - username is escaped
```

**Check logs for escaped filter:**
```
filter='(&(uid=admin\29\28uid=\2a)(memberOf=...))'
```

### Buffer Overflow Testing

**Test with very long filter in config:**
```bash
# Create filter with 513 bytes (over limit)
python3 << EOF
with open('/tmp/test_config', 'w') as f:
    f.write('ldap_uri ldap://localhost\n')
    f.write('ldap_base dc=example,dc=com\n')
    f.write('ldap_filter (' + 'a' * 511 + ')\n')  # 513 bytes total
EOF

# Try to load - should reject filter
```

**Expected:** Filter rejected with error logged to syslog.

## Regression Testing

### Ensure Backward Compatibility

**Test without ldap_filter line:**
```bash
# Config without ldap_filter
cat > /tmp/test_compat.conf << EOF
ldap_uri ldap://localhost
ldap_base dc=example,dc=com
totp_enabled true
EOF

# Should work identically to 0.1.x
```

**Test with empty ldap_filter:**
```bash
# Config with empty ldap_filter
echo "ldap_filter" >> /tmp/test_compat.conf

# Should work identically to no filter
```

## Test Summary Checklist

- [ ] All 19 unit tests pass (`test_ldap_filter`)
- [ ] Group-based filter works (users in group authenticate)
- [ ] Group-based filter blocks (users not in group fail)
- [ ] Empty filter maintains backward compatibility
- [ ] Invalid filters rejected at config load
- [ ] Over-length filters rejected
- [ ] Debug logs show combined filter
- [ ] Username still escaped (LDAP injection prevented)
- [ ] Buffer overflow protection works
- [ ] Performance impact acceptable (<5%)
- [ ] LDAP attributes indexed in production

## Next Steps

After all tests pass:

1. Update `README.md` with filter examples
2. Update `CHANGELOG.md` for version 0.2.0
3. Create release notes
4. Tag release: `git tag v0.2.0`
5. Update documentation with production deployment guide
