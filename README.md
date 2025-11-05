# pam-ldap-totp-auth: A PAM LDAP TOTP Authentication Module

A complete PAM (Pluggable Authentication Modules) module that provides **unified password and TOTP authentication** against LDAP directories. This single module validates both user passwords (via LDAP bind) and optionally validates TOTP (Time-based One-Time Password) codes for two-factor authentication. Works with any PAM-enabled service including OpenVPN, SSH, sudo, login, and more.

## Key features

- **Unified authentication** - Single PAM module handles both password AND TOTP validation
- **LDAP password validation** - Authenticates passwords via secure LDAP bind
- **Optional TOTP 2FA** - Add two-factor authentication with TOTP codes stored in LDAP
- **Universal compatibility** - Works with any PAM-enabled service (SSH, sudo, login, OpenVPN, etc.)
- **Centralised storage** - TOTP secrets stored securely in your LDAP directory
- **Two authentication modes**:
  - **Challenge-response mode** (default) - Separate password and OTP prompts for SSH/sudo/login
  - **Append mode** - Password+OTP concatenated for OpenVPN compatibility
- **RFC 6238 compliant** - Standard TOTP implementation with SHA1
- **Backup codes** - Emergency access with scratch codes (single-use)
- **Clock drift tolerance** - Configurable time window for TOTP validation
- **Grace period support** - Allow users time to enroll in MFA


### Authentication flow

1. **Username validation** - Verifies username format
2. **Password authentication** - Validates password against LDAP using secure LDAP bind
3. **TOTP validation (optional)** - If enabled and user has TOTP configured:
   - Validates TOTP code from user input against secret stored in LDAP
   - Checks backup/scratch codes if TOTP validation fails
   - Enforces grace period policies for new users

### Password-only mode

TOTP validation is optional. You can use this module for LDAP password authentication only:

```conf
# /etc/security/pam_ldap_totp_auth.conf
totp_enabled false
ldap_uri ldap://ldap.example.com
ldap_base dc=example,dc=com
```

With `totp_enabled false`, the module performs only password validation via LDAP bind.

### Password + TOTP mode

Enable two-factor authentication by setting `totp_enabled true` (the default):

```conf
# /etc/security/pam_ldap_totp_auth.conf
totp_enabled true
totp_mode challenge
ldap_uri ldap://ldap.example.com
ldap_base dc=example,dc=com
```

Users will be prompted for both their password and TOTP code (or password+code together in append mode).

## Requirements

### LDAP schema (recommended)

It is **strongly recommended** that you install the LDAP TOTP schema in your LDAP directory:

**LDAP TOTP schema**: https://github.com/wheelybird/ldap-totp-schema

This schema adds standardised LDAP attributes (`totpSecret`, `totpStatus`, `totpScratchCode`, etc.) for storing TOTP secrets and managing MFA policies, along with secure ACL examples.

**Alternative TOTP attribute configuration**: The PAM module is configurable and can use any LDAP attribute you specify via the `totp_attribute` setting. However, if you use custom attributes, you are responsible for implementing appropriate LDAP access controls to protect the TOTP secrets. The official schema provides battle-tested ACLs and attribute definitions.

### System dependencies

**Build dependencies:**
```bash
# Debian/Ubuntu
apt-get install build-essential libpam0g-dev libldap2-dev liboath-dev

# RHEL/CentOS/Fedora
yum install gcc pam-devel openldap-devel liboath-devel

# Alpine
apk add build-base pam-dev openldap-dev oath-toolkit-dev
```

**Runtime dependencies:**
- PAM library (`libpam`)
- OpenLDAP client library (`libldap`)
- OATH Toolkit library (`liboath`)

### LDAP Configuration

**Configuration File: `/etc/security/pam_ldap_totp_auth.conf`**

See `pam_ldap_totp_auth.conf.example` for all available settings

**LDAP settings supported:**
- `ldap_uri` - LDAP server URI (e.g., `ldap://ldap.example.com` or `ldaps://ldap.example.com:636`)
- `ldap_base` - LDAP base DN (e.g., `dc=example,dc=com`)
- `ldap_bind_dn` - Bind DN for LDAP authentication (optional, anonymous bind if not set)
- `ldap_bind_password` - Bind password (optional)
- `tls_mode` - TLS/SSL settings (`on`, `starttls`, or `off`)
- `tls_verify_cert` - Certificate validation (`true`/`false`)
- `tls_ca_cert_file` - Path to CA certificate file
- `login_attribute` - LDAP attribute for user login (default: `uid`)

**Login attribute configuration:**

The `login_attribute` setting determines which LDAP attribute is used when searching for users.

Example configuration:
```conf
# Search for users by email address instead of uid
login_attribute mail
```

The module will search for users using `(mail=username)` instead of `(uid=username)`. This is useful for environments where users authenticate with email addresses.  See "Multiple match handling" below for how this handles multiple matches for that attribute.

## Building

```bash
make
```

This will compile `pam_ldap_totp_auth.so` in the current directory.

## Installation

```bash
sudo make install
```

This installs the module to `/lib/security/pam_ldap_totp_auth.so` (or `/lib64/security/` on 64-bit systems).

## Configuration

**Important:** This is a **unified authentication module** that handles both password validation (via LDAP bind) and optional TOTP validation. You only need this single module - do not combine it with `pam_ldap.so` or other LDAP password modules, as that would cause duplicate password prompts.

### 1. PAM module configuration

Create `/etc/security/pam_ldap_totp_auth.conf`:

```bash
sudo cp pam_ldap_totp_auth.conf.example /etc/security/pam_ldap_totp_auth.conf
sudo chmod 600 /etc/security/pam_ldap_totp_auth.conf
```

Edit the configuration file to match your setup. Key settings:

```conf
# Authentication mode (IMPORTANT: Read compatibility notes below)
totp_mode challenge   # challenge (SSH/sudo/login) or append (OpenVPN)

# Custom prompt for challenge mode
challenge_prompt TOTP code:

# LDAP attribute containing TOTP secret
totp_attribute totpSecret

# LDAP attribute mappings (customisable for your schema)
scratch_attribute totpScratchCode
status_attribute totpStatus
enrolled_date_attribute totpEnrolledDate

# TOTP validation settings
time_step 30
window_size 3

# MFA enforcement
grace_period_days 7
enforcement_mode graceful  # Options: graceful (default), warn_only, strict

# Multiple match handling (default: false, matches pam_ldap behavior)
require_unique_match false

# Debug (disable in production)
debug false
```

**⚠️ Authentication mode compatibility:**
- **Challenge mode** (default): Works with SSH, sudo, login - **This doesn't work with OpenVPN**
- **Append mode**: Works with all services including OpenVPN

**MFA enforcement modes:**

The `enforcement_mode` option controls how strictly MFA is enforced and how password-only authentication is handled:

- `enforcement_mode graceful` (default) - Allow password-only authentication for users without TOTP configured. Users with `totpStatus=pending` get a grace period. **Recommended for mixed environments.**
- `enforcement_mode warn_only` - Allow password-only authentication but log security warnings to syslog. **Useful for MFA rollout testing.**
- `enforcement_mode strict` - Require TOTP for ALL users. Users without TOTP configured are denied access. **Use only when all users have MFA.**

**Password-only authentication behavior:**
- `graceful` and `warn_only` modes: Users without the `totpUser` objectClass can authenticate with password alone
- `strict` mode: All users must have TOTP configured; password-only authentication is rejected

**Multiple match handling:**

The `require_unique_match` option controls behavior when multiple LDAP entries match the login attribute:

- `require_unique_match false` (default) - Uses the first matching entry, consistent with `pam_ldap.so` behavior
- `require_unique_match true` - Fails authentication if multiple entries match, logging a warning

**Recommendation:** Leave this at the default (`false`) unless you have strict security requirements. If enabled, administrators must ensure LDAP filters and login attributes produce unique matches (e.g., by using unique email addresses).

**Attribute mapping:**
All LDAP attributes used by the module are configurable, allowing integration with custom LDAP schemas:
- `totp_attribute` - LDAP attribute storing the TOTP secret (default: `totpSecret`)
- `scratch_attribute` - LDAP attribute for backup/scratch codes (default: `totpScratchCode`)
- `status_attribute` - LDAP attribute for enrollment status (default: `totpStatus`)
- `enrolled_date_attribute` - LDAP attribute for enrollment date (default: `totpEnrolledDate`)

If you use the recommended [LDAP TOTP schema](https://github.com/wheelybird/ldap-totp-schema), the defaults will work out of the box.

See `pam_ldap_totp_auth.conf.example` for all available options.

### 2. Service PAM configuration

Choose the appropriate example for your service and install it to `/etc/pam.d/`:

**OpenVPN:**
```bash
sudo cp examples/openvpn/openvpn /etc/pam.d/openvpn
```

**SSH:**
```bash
sudo cp examples/ssh/sshd /etc/pam.d/sshd
```

**sudo:**
```bash
sudo cp examples/sudo/sudo /etc/pam.d/sudo
```

### 3. Service-specific configuration

**For SSH:**

Edit `/etc/ssh/sshd_config`:
```
UsePAM yes
PasswordAuthentication yes
```

Then restart SSH:
```bash
sudo systemctl restart sshd
```

**For OpenVPN:**

Configure OpenVPN server to use PAM authentication. See the [OpenVPN documentation](https://github.com/wheelybird/openvpn-server-ldap-otp) for details.

## Authentication modes

This module **always validates both password (via LDAP bind) and TOTP code** when TOTP is enabled. The mode determines **how** users provide these credentials.

### Challenge-response mode (Default, Recommended)

**Best for:** SSH, sudo, login: most PAM-enabled services except OpenVPN.

**What it does:** Validates password against LDAP, then validates TOTP code. Users see separate prompts:

```
Password: [user enters password]
TOTP code: [user enters 123456]
[Module validates password via LDAP bind, then validates TOTP code]
[Authenticated]
```

**Configuration:**
```conf
totp_mode challenge
challenge_prompt TOTP code:
```

**Advantages:**
- Better user experience with clear separate prompts
- More intuitive for end users
- Standard PAM authentication flow

**⚠️ OpenVPN incompatibility:**

OpenVPN **does not support** PAM challenge-response (conversation function). If you use challenge mode with OpenVPN, authentication will fail with:
```
Failed to get TOTP code: PAM conversation unavailable
Challenge-response mode requires PAM conversation support
For OpenVPN, use totp_mode append in configuration
```

For OpenVPN deployments, use **Append mode** (see below).

### Append mode (OpenVPN Compatible)

**Best for:** OpenVPN, or any service where challenge-response is unavailable

**What it does:** Extracts password and TOTP code from a single concatenated input, then validates password via LDAP bind and validates TOTP code.

User enters password and TOTP code concatenated together:

```
Password: [user enters mypassword123456]
[Module extracts: password="mypassword", otp="123456"]
[Module validates password via LDAP bind, then validates TOTP code]
[Authenticated]
```

**Example:** If password is `mypassword` and TOTP code is `123456`, user enters: `mypassword123456`

**Configuration:**
```conf
totp_mode append
```

**Use cases:**
- **OpenVPN** (all clients support this)
- SSH (works, but challenge mode provides better UX)
- sudo (works, but challenge mode provides better UX)
- Any PAM-enabled service

**Scratch code support (both modes):**

8-digit scratch/backup codes are supported as follows:

**In challenge mode:**
1. User is prompted: `TOTP code:`
2. User enters 8-digit scratch code: `12345678`
3. Module validates as scratch code
4. Authentication succeeds if code is valid
5. The scratch code is removed from LDAP

**In append mode:**
1. User enters password + 8-digit scratch code: `mypassword12345678`
2. Module extracts last 6 digits as OTP: `345678`
3. Module attempts TOTP validation with `345678`
4. If validation fails AND the original input had 8+ trailing digits, module extracts last 8 digits (`12345678`) and validates as scratch code
5. Authentication succeeds if scratch code is valid
6. The scratch code is removed from LDAP

## Usage examples

### Enable MFA for LDAP user

```bash
# 1. Generate TOTP secret (Base32, 160-bit)
SECRET=$(openssl rand -base64 20 | base32 | tr -d '=' | head -c 32)

# 2. Add to LDAP user entry
ldapmodify -x -D "cn=admin,dc=example,dc=com" -w password <<EOF
dn: uid=jdoe,ou=people,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: totpUser
-
add: totpSecret
totpSecret: $SECRET
-
add: totpStatus
totpStatus: active
-
add: totpEnrolledDate
totpEnrolledDate: $(date -u +"%Y%m%d%H%M%SZ")
EOF

# 3. Generate QR code for user
echo "otpauth://totp/Example:jdoe?secret=$SECRET&issuer=Example" | qrencode -t UTF8
```

### Test authentication

**Challenge mode (SSH/sudo/login):**
```bash
# Test with SSH
ssh jdoe@server
# Password: mypassword
# TOTP code: 123456

# Test with pamtester (requires mock conversation function)
pamtester sshd jdoe authenticate
```

**Append mode (OpenVPN):**
```bash
# Generate current TOTP code
CODE=$(oathtool --totp --base32 "JBSWY3DPEHPK3PXP")

# Test with pamtester
pamtester openvpn jdoe authenticate
# Enter: password$CODE (e.g., mypassword123456)
```

## Troubleshooting

### Check module installation

```bash
ls -l /lib/security/pam_ldap_totp_auth.so
# Should show the module file
```

### Enable debug logging

Edit `/etc/security/pam_ldap_totp_auth.conf`:
```conf
debug true
```

Check logs:
```bash
# Debian/Ubuntu
tail -f /var/log/auth.log

# RHEL/CentOS
tail -f /var/log/secure

# systemd
journalctl -f -u sshd
```

### Common issues

**"LDAP connection failed"**
- Check `/etc/security/pam_ldap_totp_auth.conf` configuration
- Verify `ldap_uri` and `ldap_base` settings
- Verify LDAP server is reachable
- Test with: `ldapsearch -x -H ldap://server -b "dc=example,dc=com"`

**"TOTP secret not found"**
- Verify user has `totpUser` objectClass
- Check `totpSecret` attribute exists
- Verify PAM module can read the attribute (check LDAP ACLs)

**"TOTP validation failed" (code is correct)**
- Check system time synchronization: `timedatectl status`
- Install NTP: `apt-get install ntp` or `yum install chrony`
- Increase `window_size` in config (temporarily for testing)

**"Permission denied" when accessing `/etc/security/pam_ldap_totp_auth.conf`**
```bash
sudo chmod 600 /etc/security/pam_ldap_totp_auth.conf
sudo chown root:root /etc/security/pam_ldap_totp_auth.conf
```

**"PAM conversation unavailable" or "Failed to get TOTP code"**

This error occurs when using challenge-response mode with a service that doesn't support PAM conversation (like OpenVPN).

**Solution:**
1. For OpenVPN: Change to append mode in `/etc/security/pam_ldap_totp_auth.conf`:
   ```conf
   totp_mode append
   ```
2. For SSH/sudo/login: Challenge mode should work - check PAM configuration
3. Verify the service supports PAM conversation function

**Error message in logs:**
```
Failed to get TOTP code: PAM conversation unavailable
Challenge-response mode requires PAM conversation support
For OpenVPN, use totp_mode append in configuration
```

### Test TOTP code generation

```bash
# Install oathtool
apt-get install oathtool  # Debian/Ubuntu
yum install oathtool      # RHEL/CentOS

# Generate code from secret
oathtool --totp --base32 "JBSWY3DPEHPK3PXP"
```

## Security considerations

### LDAP ACLs

See the [LDAP TOTP schema](https://github.com/wheelybird/ldap-totp-schema) for complete ACL examples.  The module needs read access to all the TOTP attributes except for the attribute storing the scratch codes - it needs write access to this in order to remove scratch codes that have been used.

### Time synchronisation

TOTP relies on accurate system time:
- Install and enable NTP/chrony
- Ensure all servers are time-synchronized
- Monitor for clock drift

### Backup codes

Always generate backup codes for emergency access:
```bash
for i in {1..10}; do
  printf "TOTP-SCRATCH:%08d\n" $((RANDOM * RANDOM % 100000000))
done
```

Store with `totpScratchCode` attribute in LDAP.

### Configuration file permissions

```bash
# PAM module config should only be readable by root
chmod 600 /etc/security/pam_ldap_totp_auth.conf
chown root:root /etc/security/pam_ldap_totp_auth.conf
```

## Integration examples

### OpenVPN

See [openvpn-server-ldap-otp](https://github.com/wheelybird/openvpn-server-ldap-otp) for a complete OpenVPN container with LDAP TOTP support.

### SSH Two-Factor authentication

Complete SSH MFA setup:

1. Install PAM module (see above)
2. Configure `/etc/pam.d/sshd` (use example)
3. Configure `/etc/ssh/sshd_config`:
   ```
   UsePAM yes
   PasswordAuthentication yes
   ```
4. Restart SSH: `systemctl restart sshd`
5. Enroll users in LDAP (add `totpSecret`)
6. Test: `ssh username@server` (enter password + TOTP code concatenated)

### Self-service MFA enrollment

Use [LDAP User Manager](https://github.com/wheelybird/ldap-user-manager) to provide a web interface where users can:
- Enroll in MFA themselves
- Scan QR codes with authenticator apps
- View and save backup codes
- Manage their MFA status

## Technical details

### TOTP parameters

- **Algorithm**: SHA1 (RFC 6238 standard)
- **Digits**: 6
- **Time Step**: 30 seconds (configurable)
- **Window Size**: 3 steps (±90 seconds tolerance, configurable)

### Validation window

With `window_size=3`, the module accepts codes from:
- 3 steps before current time (-90 seconds)
- Current time window
- 3 steps after current time (+90 seconds)

This provides a total window of 210 seconds (7 time steps).

### Grace period

The `grace_period_days` setting allows users time to set up MFA:
- Check if user is in group with `mfaRequired=TRUE`
- If `totpStatus=pending`, allow grace period
- Calculate: `days_elapsed = (current_date - totpEnrolledDate) / 86400`
- If `days_elapsed > grace_period_days`, enforce MFA

## Development

### Building from source

```bash
git clone https://github.com/wheelybird/pam-ldap-totp-auth.git
cd pam-ldap-totp-auth
make
```

### Running unit tests

The project includes unit tests for configuration parsing, TOTP validation, and OTP extraction logic.

```bash
# Run all tests
make test

# Or run tests directly
cd tests
make run

# Run individual test suites
./tests/test_config   # Configuration parsing tests
./tests/test_totp     # TOTP validation tests
./tests/test_extract  # OTP extraction tests
```

See [tests/README.md](tests/README.md) for detailed test documentation.

### Integration Testing with pamtester

```bash
# Install pamtester
sudo apt-get install pamtester

# Test authentication
pamtester <service> <username> authenticate
```

### Debugging

Enable debug logging in `/etc/security/pam_ldap_totp_auth.conf`:
```conf
debug true
```

Then check logs:
```bash
# Debian/Ubuntu
tail -f /var/log/auth.log

# RHEL/CentOS
tail -f /var/log/secure

# systemd
journalctl -f -u sshd
```

## Related projects

- **LDAP TOTP Schema**: https://github.com/wheelybird/ldap-totp-schema - LDAP schema definitions
- **LDAP User Manager**: https://github.com/wheelybird/ldap-user-manager - Web UI for MFA enrolment
- **OpenVPN LDAP OTP**: https://github.com/wheelybird/openvpn-server-ldap-otp - OpenVPN with LDAP TOTP

## Standards & references

- **RFC 6238** - TOTP: Time-Based One-Time Password Algorithm
- **RFC 4226** - HOTP: HMAC-Based One-Time Password Algorithm
- **Linux-PAM Documentation**: http://www.linux-pam.org/
- **OATH Toolkit**: https://www.nongnu.org/oath-toolkit/

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.

## Support

- **Issues**: https://github.com/wheelybird/pam-ldap-totp-auth/issues
- **Discussions**: https://github.com/wheelybird/pam-ldap-totp-auth/discussions
