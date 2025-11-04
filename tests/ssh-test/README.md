# SSH Integration Tests for PAM LDAP TOTP

This directory contains a complete integration test environment for testing the PAM LDAP TOTP module with SSH authentication.

## Overview

The test environment includes:
- **OpenLDAP server** with TOTP schema
- **SSH server** with PAM LDAP TOTP module installed
- **Automated tests** using expect scripts
- **Test user** with known TOTP secret

**Test data location:** All test data (LDAP database, config, logs) is stored in `/tmp/pam-ldap-totp-test/` to keep the repository clean.

## Quick Start

```bash
# Start the test environment
cd tests/ssh-test
docker-compose up -d

# Wait for services to initialize
sleep 10

# Run the tests
docker exec sshtest-ssh /test/test-run-all.sh

# Stop the environment
docker-compose down
```

## Test Credentials

### Test User
- **Username**: testuser
- **Password**: testpass
- **TOTP Secret**: JBSWY3DPEHPK3PXP
- **Backup Codes**: 12345678, 87654321, 11111111

### LDAP Admin
- **Username**: cn=admin,dc=example,dc=com
- **Password**: password

## Test Modes

### Challenge-Response Mode (Default)

The PAM module is configured in challenge-response mode by default. This mode:
- Prompts for password first
- Then prompts for TOTP code separately
- Works with SSH, sudo, login, and other PAM-enabled services
- **Does NOT work with OpenVPN**

**Test Command:**
```bash
docker exec sshtest-ssh /test/test-challenge-mode.exp
```

### Append Mode

To test append mode (password+TOTP concatenated):

1. Edit `pam_ldap_totp_auth.conf` to set `totp_mode append`
2. Rebuild the SSH container: `docker-compose up -d --build`
3. Run the append mode test:
```bash
docker exec sshtest-ssh /test/test-append-mode.exp
```

## Manual Testing

### Generate Current TOTP Code

```bash
# Inside the container
docker exec sshtest-ssh oathtool --totp --base32 JBSWY3DPEHPK3PXP

# Outside the container (if oathtool installed)
oathtool --totp --base32 JBSWY3DPEHPK3PXP
```

### Manual SSH Connection

```bash
# Challenge-response mode
ssh -p 10022 testuser@localhost
Password: testpass
TOTP code: [enter current code from oathtool]

# Append mode
ssh -p 10022 testuser@localhost
Password: testpass123456  [password + current TOTP code]
```

## Architecture

```
┌─────────────────────┐
│  OpenLDAP Server    │
│  - TOTP Schema      │
│  - Test User        │
│  - Port: 10389      │
└──────────┬──────────┘
           │
           │ LDAP queries
           │
┌──────────▼──────────┐
│   SSH Server        │
│  - PAM LDAP TOTP    │
│  - nslcd            │
│  - Port: 10022      │
└─────────────────────┘
```

## Files

### Configuration
- `nslcd.conf` - LDAP client configuration
- `pam_ldap_totp_auth.conf` - PAM module configuration
- `pam-sshd` - PAM configuration for SSH
- `sshd_config` - SSH server configuration

### LDAP Initialization
- `ldap-init/01-totp-schema.ldif` - TOTP schema definition
- `ldap-init/02-test-user.ldif` - Test user with TOTP enabled

### Test Scripts
- `test-challenge-mode.exp` - Test challenge-response mode
- `test-append-mode.exp` - Test append mode
- `test-run-all.sh` - Run all tests

## Troubleshooting

### SSH Server Won't Start

Check logs:
```bash
docker logs sshtest-ssh
```

Common issues:
- Host key generation failed
- PAM module not installed correctly
- Configuration syntax errors

### LDAP Connection Failed

Verify LDAP server is running:
```bash
docker logs sshtest-openldap

# Test LDAP connection
docker exec sshtest-ssh ldapsearch -x -H ldap://openldap:389 \
  -D "cn=admin,dc=example,dc=com" -w password \
  -b "dc=example,dc=com" "(uid=testuser)"
```

### Authentication Failed

Enable debug logging:
1. Edit `pam_ldap_totp_auth.conf` and set `debug true`
2. Rebuild container: `docker-compose up -d --build`
3. Check auth logs: `docker exec sshtest-ssh tail -f /var/log/auth.log`

### TOTP Code Not Accepted

Ensure system time is synchronized:
```bash
# Check container time
docker exec sshtest-ssh date

# Generate code and verify
docker exec sshtest-ssh oathtool --totp --base32 JBSWY3DPEHPK3PXP
```

TOTP has a ±90 second window by default (`window_size 3`).

### Challenge-Response Not Working

Verify SSH configuration:
```bash
docker exec sshtest-ssh grep -E "ChallengeResponse|KbdInteractive|UsePAM" /etc/ssh/sshd_config
```

Should show:
```
UsePAM yes
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
```

## Expected Test Output

### Successful Challenge-Response Test

```
=========================================
Testing SSH Challenge-Response Mode
=========================================
Password: testpass
TOTP Code: 123456

✓ Challenge-response authentication SUCCEEDED
```

### Successful Append Mode Test

```
=========================================
Testing SSH Append Mode
=========================================
Password: testpass
TOTP Code: 123456
Combined: testpass123456

✓ Append mode authentication SUCCEEDED
```

## Cleanup

Test data is stored in `/tmp/pam-ldap-totp-test/` to avoid cluttering the repository.

```bash
# Stop containers
docker-compose down

# Remove all test data including LDAP database and test results
# This resets the test environment completely
sudo rm -rf /tmp/pam-ldap-totp-test/

# Alternative: Remove volumes only (preserves container images)
docker-compose down -v
```

**Note:** The `/tmp/pam-ldap-totp-test/` directory contains:
- `ldap-data/` - LDAP database files
- `ldap-config/` - LDAP configuration
- `test-results/` - Test output logs

## Security Notes

This is a **test environment only**. Do not use in production:

- Uses weak passwords
- LDAP connection without TLS
- Known TOTP secret
- Permissive SSH configuration
- Debug logging enabled

## Next Steps

After successful SSH testing:
- Test with sudo authentication
- Test with login (console)
- Test grace period enforcement
- Test backup code usage
- Performance testing with concurrent connections
