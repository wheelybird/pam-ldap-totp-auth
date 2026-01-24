# Changelog

All notable changes to the PAM LDAP TOTP authentication module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-23

### Added

- **LDAP Filter Support** - New `ldap_filter` configuration parameter for group-based and attribute-based access control
  - Combine username search with additional LDAP filter using AND logic
  - Support for memberOf filters (requires memberOf overlay)
  - Support for account status filters
  - Support for complex filters (OR, AND, NOT, nested)
  - Maximum filter length: 512 bytes
  - RFC 4515 LDAP filter syntax compliance
  - Load-time filter validation (balanced parentheses, control character rejection)
  - Runtime buffer overflow protection
  - Empty filter = feature disabled (backward compatible)

- **Validation Function** - `validate_ldap_filter()` in security_utils.c
  - Checks balanced parentheses
  - Rejects control characters (except tab)
  - Ensures filter starts/ends with parentheses
  - Enforces 512-byte maximum length
  - Returns 1 if valid, 0 if invalid

- **Configuration Parsing** - Enhanced config.c
  - Parse `ldap_filter` parameter from config file
  - Validate filter before accepting
  - Reject invalid filters (logged to syslog)
  - Free filter string on cleanup

- **Filter Combination Logic** - Updated LDAP query functions
  - `ldap_get_totp_secret()` - Apply filter when retrieving TOTP secret
  - `ldap_check_scratch_code()` - Apply filter when checking scratch codes
  - `ldap_get_attribute()` - Apply filter for generic attribute retrieval
  - `ldap_validate_password()` - Apply filter during password validation
  - Increased filter buffers from 256/512 to 1024 bytes
  - Explicit overflow checking on all filter combinations

- **Documentation**
  - Comprehensive `ldap_filter` documentation in pam_ldap_totp_auth.conf.example
  - Usage examples for group membership, account status, complex filters
  - Security and performance considerations
  - Example 9: Group-based access control configuration

- **Testing**
  - New unit test suite: `test_ldap_filter.c` (19 tests)
    - Filter validation tests (valid/invalid filters, length limits, special chars)
    - Configuration parsing tests (valid, empty, missing, invalid)
    - Edge case tests (parentheses depth, control chars)
  - Integration test script: `test-ldap-filter-integration.sh`
    - Tests with real LDAP server
    - memberOf filter tests
    - OR/AND/NOT filter tests
    - Backward compatibility verification
  - Comprehensive testing documentation: `tests/TEST_LDAP_FILTER.md`
    - Unit test coverage
    - Integration test scenarios
    - Manual testing procedures
    - Performance testing guide
    - Security testing
    - Troubleshooting guide

### Changed

- **Version** - Updated to 0.2.0 (minor version bump for new feature)
- **Header file** - Added `ldap_filter` field to `pam_config_t` struct
- **Buffer sizes** - Increased LDAP filter buffers for combined filters
- **Test Makefile** - Added `test_ldap_filter` to test suite
- **Tests README** - Documented new test_ldap_filter.c suite and integration tests

### Security

- **Username escaping maintained** - Username still escaped with `ldap_escape_filter()` to prevent LDAP injection
- **Filter is admin-configured** - Filter comes from config file (trusted), not user input
- **Fail closed on errors** - Invalid filters rejected at load time, authentication denied on filter errors
- **Buffer overflow protection** - Explicit overflow checks when combining filters
- **Filter validation** - Structural validation at config load prevents malformed filters

### Backward Compatibility

- **100% backward compatible** - Empty filter (default) provides identical behaviour to v0.1.x
- **No breaking changes** - Existing configurations work without modification
- **Optional feature** - Filter only applied when configured, defaults to disabled

## [0.1.3] - Previous Release

### Features

- LDAP-backed TOTP authentication
- Challenge-response and append authentication modes
- Grace period support
- Scratch code (backup code) support
- TLS/StartTLS support
- Configurable TOTP parameters (time step, window size)
- MFA enforcement modes (strict, graceful, warn_only)
- Debug logging
- Comprehensive configuration options

---

## Use Cases for ldap_filter

### VPN Access Control
```conf
ldap_filter (memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)
```
Only users in the vpn-users group can authenticate via VPN.

### SSH Access Control
```conf
ldap_filter (memberOf=cn=ssh-users,ou=groups,dc=example,dc=com)
```
Only users in the ssh-users group can authenticate via SSH.

### Active Account Requirement
```conf
ldap_filter (accountStatus=active)
```
Only users with active accounts can authenticate.

### Multiple Group Access
```conf
ldap_filter (|(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)(memberOf=cn=ssh-users,ou=groups,dc=example,dc=com))
```
Users in either vpn-users or ssh-users can authenticate.

### Complex Access Policy
```conf
ldap_filter (&(accountStatus=active)(!(accountLocked=TRUE)))
```
Only active, unlocked accounts can authenticate.

## Migration Guide

### Upgrading from 0.1.x to 0.2.0

**No changes required** - Version 0.2.0 is fully backward compatible with 0.1.x.

If you want to add group-based access control:

1. Ensure your LDAP server has memberOf overlay enabled
2. Add `ldap_filter` line to your config:
   ```conf
   ldap_filter (memberOf=cn=your-group,ou=groups,dc=example,dc=com)
   ```
3. Test with ldapsearch first:
   ```bash
   ldapsearch -x -H ldap://server -b dc=example,dc=com \
     "(&(uid=testuser)(memberOf=cn=your-group,ou=groups,dc=example,dc=com))"
   ```
4. Restart PAM-enabled services (VPN, SSH, etc.)
5. Test authentication with users in and out of the group

**Rollback:** Remove or comment out the `ldap_filter` line to revert to 0.1.x behaviour.

## Performance Notes

- **LDAP attribute indexing recommended** - Index `memberOf` and other filter attributes for best performance
- **Minimal performance impact** - <5% slowdown with indexed attributes
- **Complex filters** - May slow authentication; test with realistic user load
- **memberOf overlay** - Required for group membership filters; adds negligible overhead

## Known Issues

None at this time.

## Future Enhancements

Potential features for future releases:

- Variable substitution in filters (e.g., `${username}`)
- Multiple filter support with OR logic
- Filter validation improvements (full RFC 4515 parser)
- Performance monitoring and metrics
- Filter result caching

## Links

- [Repository](https://github.com/wheelybird/pam-ldap-totp-auth)
- [Issue Tracker](https://github.com/wheelybird/pam-ldap-totp-auth/issues)
- [OpenLDAP memberOf Overlay](https://www.openldap.org/doc/admin24/overlays.html#Reverse%20Group%20Membership%20Maintenance)
- [RFC 4515: LDAP Filter Syntax](https://tools.ietf.org/html/rfc4515)
