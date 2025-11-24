# PAM LDAP TOTP unit tests

This directory contains unit tests for the PAM LDAP TOTP module.

## Test suites

### test_config.c - configuration parsing tests

Tests the configuration file parsing logic:

- Basic TOTP configuration parsing
- LDAP configuration parsing
- Grace period configuration
- Grace period messaging configuration (grace_message, grace_period_attribute, show_grace_message)
- Quoted values in configuration
- Default values when config file doesn't exist

### test_challenge_response.c - challenge-response mode tests

Tests the challenge-response authentication mode configuration:

- Parsing `totp_mode challenge`
- Parsing `totp_mode append`
- Parsing `challenge_response` alias
- Default mode (challenge)
- Custom challenge prompt parsing
- Default challenge prompt
- Invalid mode fallback
- Enum value verification

**Key scenarios tested:**
- Unified configuration file parsing
- Quote stripping (both single and double quotes)
- Whitespace handling
- Missing configuration files
- Secure defaults

### test_grace_period.c - grace period messaging tests

Tests the grace period messaging functionality:

- Grace period calculation (date parsing and days elapsed)
- Custom LDAP attribute names for grace periods
- Message formatting with days remaining
- Singular vs plural day handling ("1 day" vs "5 days")
- Grace period enable/disable functionality
- LDAP fallback to config defaults
- LDAP grace period value parsing
- Special characters in messages (URLs, email addresses, phone numbers)
- Long message handling (512 character limit)

**Key scenarios tested:**
- LDAP GeneralizedTime date format parsing (YYYYMMDDHHmmssZ)
- Per-user grace period override from LDAP
- Message formatting and display logic
- Configuration option parsing and defaults
- Custom grace messages with URLs and contact information

### test_totp.c - TOTP validation tests

Tests the TOTP code validation logic:

- Validate known TOTP codes
- Reject invalid TOTP codes
- Time window tolerance (±90 seconds with window_size=3)
- Scratch/backup code format validation
- Different time step configurations (30s, 60s)

**Key scenarios tested:**
- RFC 6238 compliance
- Time drift tolerance
- Backup code validation
- Edge cases (expired codes, future codes within window)

### test_extract.c - OTP extraction tests

Tests the password+OTP extraction logic:

- Extract 6-digit TOTP codes
- Extract 8-digit scratch codes (documents algorithmic limitation)
- Whitespace handling (leading/trailing)
- Invalid input rejection
- Preference for 6-digit over 8-digit
- Complex passwords with special characters
- Minimum length requirements
- Attack prevention (overly long passwords)

**Key scenarios tested:**
- Append mode extraction: `password123456` → `password` + `123456`
- Scratch codes: `password12345678` → `password12` + `345678` (extracts last 6, not 8)
- Edge cases: minimum valid length, whitespace trimming
- Security: rejection of suspiciously long inputs

**Important design decision:**
The extraction algorithm always extracts the last 6 digits, even when 8 trailing digits are present.

For 8-digit scratch codes, the validation logic (not the extraction logic) should handle the fallback:
1. Extract last 6 digits from input (e.g., "password12345678" → "345678")
2. Try validating as 6-digit TOTP first
3. If validation fails AND the original input had 8+ trailing digits, extract and validate the last 8 digits as a scratch code

## Building and running tests

### Prerequisites

Install required development libraries:

```bash
# Debian/Ubuntu
apt-get install build-essential libpam0g-dev libldap2-dev liboath-dev

# RHEL/CentOS/Fedora
yum install gcc pam-devel openldap-devel liboath-devel

# Alpine
apk add build-base pam-dev openldap-dev oath-toolkit-dev
```

### Build tests

```bash
cd tests
make
```

This creates the following test executables:
- `test_config` - Configuration parsing tests
- `test_challenge_response` - Challenge-response mode tests
- `test_grace_period` - Grace period messaging tests
- `test_totp` - TOTP validation tests
- `test_security` - Security and input validation tests
- `test_ldap_auth` - LDAP authentication tests

### Run tests

Run all tests:
```bash
make run
```

Run individual test suites:
```bash
./test_config
./test_challenge_response
./test_grace_period
./test_totp
./test_security
./test_ldap_auth
```

Run from parent directory:
```bash
make test
```

### Clean up

```bash
make clean
```

This removes:
- Test executables
- Object files
- Temporary test configuration files in `/tmp`

## Test Output

Successful test output:
```
Running configuration parsing tests...

✓ test_parse_totp_config_basic passed
✓ test_parse_ldap_config passed
✓ test_parse_grace_period_config passed
✓ test_parse_quoted_values passed
✓ test_default_values passed

All configuration tests passed!

Running Challenge-Response Mode Tests...

✓ test_parse_totp_mode_challenge passed
✓ test_parse_totp_mode_append passed
✓ test_parse_totp_mode_challenge_response_alias passed
✓ test_totp_mode_defaults_to_challenge passed
✓ test_parse_challenge_prompt_custom passed
✓ test_challenge_prompt_has_default passed
✓ test_invalid_totp_mode_uses_default passed
✓ test_totp_mode_enum_values passed

All challenge-response tests passed!
```

## Adding new tests

To add new tests:

1. Create a new test function in the appropriate test file
2. Follow the naming convention: `test_<functionality>_<scenario>`
3. Use `assert()` for validation
4. Print success message: `printf("✓ test_name passed\n");`
5. Add function call to `main()`

Example:
```c
void test_new_feature() {
  // Setup
  totp_config_t cfg;

  // Test
  parse_totp_config("/path/to/config", &cfg);

  // Validate
  assert(cfg.some_field == expected_value);

  // Cleanup
  free_totp_config(&cfg);

  printf("✓ test_new_feature passed\n");
}
```

## Test coverage

Current test coverage:

| Component | Functions Tested | Coverage |
|-----------|-----------------|----------|
| config.c | parse_config, grace period configuration | ~95% |
| totp_validate.c | validate_totp_code, validate_scratch_code | ~85% |
| pam_auth.c | Grace period messaging, date calculation | ~75% |
| security_utils.c | Input validation and sanitization | ~80% |

**Recently added tests:**
- Grace period messaging functionality (configuration, date parsing, message formatting)
- LDAP attribute fallback behavior for per-user grace periods
- Message formatting with singular/plural day handling

**Not yet tested:**
- LDAP connection and query functions (requires mock LDAP server)
- Full PAM authentication flow (requires integration tests)
- PAM conversation function for message display (requires PAM environment)

## Docker-based testing

For testing in a clean, isolated environment, use the provided Dockerfiles:

### Build and run all unit tests

```bash
# From project root directory
docker build -f tests/Dockerfile.unittest -t pam-ldap-totp-unittest .
docker run --rm pam-ldap-totp-unittest
```

This builds the module, runs all unit tests via `run-all-tests.sh`, and displays results.

### Build only (verification)

```bash
# Build module in clean Ubuntu 24.04 environment
docker build -f tests/Dockerfile.test -t pam-ldap-totp-test .

# Run container for inspection
docker run --rm -it pam-ldap-totp-test

# Inside container:
ls -lh pam_ldap_totp_auth.so
file pam_ldap_totp_auth.so
```

Useful for verifying the module builds correctly without local environment issues.

### Challenge-Response unit tests only

```bash
# Build and run challenge-response tests specifically
docker build -f tests/Dockerfile.test-challenge -t pam-ldap-totp-challenge .
docker run --rm pam-ldap-totp-challenge
```

Runs only the `test_challenge_response` test suite to verify configuration parsing for challenge-response mode.

### SSH integration tests

For full end-to-end SSH authentication testing:

```bash
cd tests/ssh-test
docker compose up -d

# Run tests
docker exec sshtest-ssh /test/test-challenge-mode.exp
docker exec sshtest-ssh /test/test-append-mode.exp
docker exec sshtest-ssh /test/test-run-all.sh

# View logs
docker compose logs ssh-server

# Cleanup
docker compose down
```

See `ssh-test/README.md` for detailed SSH testing documentation.

## Continuous Integration

To run tests in CI/CD:

```bash
# Install dependencies
apt-get update && apt-get install -y build-essential libpam0g-dev libldap2-dev liboath-dev

# Build and test
make clean
make
make test

# Check return code
if [ $? -eq 0 ]; then
  echo "Tests passed"
else
  echo "Tests failed"
  exit 1
fi
```

## Troubleshooting

**Tests fail to compile:**
- Ensure all development libraries are installed
- Check that header files are in the correct locations
- Verify `CFLAGS` in Makefile include correct paths

**Test failures:**
- Check system time is synchronised (TOTP tests are time-sensitive)
- Ensure `/tmp` is writable (config tests create temporary files)
- Run with verbose output to see detailed error messages

**TOTP validation tests intermittent failures:**
- Time-based tests may fail if system clock changes during test run
- Run tests on a system with stable, synchronised time (NTP)
- Tests use `oath_totp_generate()` which is time-dependent
