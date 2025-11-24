# PAM LDAP TOTP Test Suite

This directory contains unit tests for the PAM LDAP TOTP authentication module using the Check framework.

## Test Files

### test_config.c
Configuration parsing tests including:
- Basic LDAP configuration
- TOTP settings
- TLS/SSL configuration
- MFA enforcement modes
- **Grace period messaging configuration** (Tests 16-22)
  - Grace message parsing
  - Grace period attribute configuration
  - Show grace message toggle
  - Default values validation
  - Complete grace period configuration
  - Grace message with URLs
  - Empty grace message handling

### test_grace_period.c (NEW)
Grace period messaging functionality tests:
- Grace period calculation (date parsing and days elapsed)
- Custom LDAP attribute names
- Message formatting with days remaining
- Singular vs plural day handling
- Grace period enable/disable
- LDAP fallback to config defaults
- LDAP grace period value parsing
- Special characters in messages
- Long message handling

### test_ldap_auth.c
LDAP authentication tests

### test_totp.c
TOTP validation tests

### test_security.c
Security and input validation tests

### test_challenge_response.c
Challenge-response mode tests

## Running Tests

### Run all tests:
```bash
make test
```

Or from the tests directory:
```bash
cd tests
make run
```

### Run specific test:
```bash
cd tests
./test_grace_period
./test_config
```

### Build tests without running:
```bash
cd tests
make all
```

### Clean test artifacts:
```bash
cd tests
make clean
```

## Test Coverage for Grace Period Feature

### Configuration Tests (test_config.c)
- ✓ Parse `grace_message` setting
- ✓ Parse `grace_period_attribute` setting
- ✓ Parse `show_grace_message` boolean
- ✓ Verify default values:
  - `grace_message`: "Contact your administrator to set up MFA"
  - `show_grace_message`: true
  - `grace_period_attribute`: "mfaGracePeriodDays"
- ✓ Complete grace configuration with all options
- ✓ Grace message with URLs
- ✓ Empty grace message handling

### Grace Period Logic Tests (test_grace_period.c)
- ✓ Date calculation (LDAP GeneralizedTime → days elapsed)
- ✓ Days remaining calculation
- ✓ Custom LDAP attribute names
- ✓ Message formatting with proper plural/singular
- ✓ Grace period disabled state
- ✓ LDAP value fallback to config
- ✓ Invalid LDAP value handling
- ✓ Special characters in messages
- ✓ Long message handling (512 char limit)

## Test Results

Expected output when all tests pass:
```
=========================================
Running PAM LDAP TOTP Unit Tests
=========================================

Running test_config...
Running 'Configuration Parsing'...100%: Checks: 22, Failures: 0, Errors: 0

Running test_grace_period...
Running 'Grace Period Messaging'...100%: Checks: 9, Failures: 0, Errors: 0

Running test_ldap_auth...
[...]

=========================================
All test suites passed!
=========================================
```

## Dependencies

- Check framework (`libcheck`)
- PAM libraries (`libpam`)
- LDAP libraries (`libldap`, `liblber`)
- OATH library (`liboath`)

Install on Debian/Ubuntu:
```bash
sudo apt-get install check libpam0g-dev libldap2-dev liboath-dev
```

## Writing New Tests

### Test Template
```c
START_TEST(test_name)
{
  // Arrange
  const char *config = "ldap_uri ldap://localhost\n";
  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  // Act
  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  // Assert
  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.ldap_uri, "ldap://localhost");

  // Cleanup
  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST
```

### Adding Tests to Suite
```c
Suite *my_suite(void) {
  Suite *s = suite_create("My Suite");
  TCase *tc_core = tcase_create("Core");

  tcase_add_test(tc_core, test_name);
  suite_add_tcase(s, tc_core);

  return s;
}
```

## Continuous Integration

Tests are run automatically on:
- Every commit
- Pull requests
- Before installation

To integrate with CI/CD:
```bash
make clean && make test
if [ $? -eq 0 ]; then
  echo "Tests passed"
  make install
else
  echo "Tests failed"
  exit 1
fi
```
