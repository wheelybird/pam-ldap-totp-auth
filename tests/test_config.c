/*
 * test_config.c
 *
 * Unit tests for configuration parsing
 * Tests config.c with Check framework
 *
 * Standalone configuration format:
 * - Friendly keywords (ldap_uri, ldap_base, totp_enabled)
 * - Unquoted values (whitespace-separated)
 * - Single unified config file
 * - OWASP input validation
 */

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../include/pam_ldap_totp.h"

/* Test helper: create temporary config file */
static char *create_temp_config(const char *content) {
  static char template[] = "/tmp/pam_ldap_totp_test_XXXXXX";
  char *filename = strdup(template);
  int fd = mkstemp(filename);
  if (fd == -1) {
    free(filename);
    return NULL;
  }

  write(fd, content, strlen(content));
  close(fd);
  return filename;
}

/* Test 1: Basic LDAP configuration parsing */
START_TEST(test_parse_basic_ldap_config)
{
  const char *config =
    "ldap_uri ldap://ldap.example.com\n"
    "ldap_base dc=example,dc=com\n"
    "login_attribute uid\n"
    "totp_enabled true\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.ldap_uri, "ldap://ldap.example.com");
  ck_assert_str_eq(cfg.ldap_base, "dc=example,dc=com");
  ck_assert_str_eq(cfg.login_attribute, "uid");
  ck_assert_int_eq(cfg.totp_enabled, 1);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 2: LDAP authentication with bind credentials */
START_TEST(test_parse_ldap_bind_credentials)
{
  const char *config =
    "ldap_uri ldaps://ldap.example.com:636\n"
    "ldap_base dc=example,dc=com\n"
    "ldap_bind_dn cn=pam-auth,ou=services,dc=example,dc=com\n"
    "ldap_bind_password SecurePassword123\n"
    "tls_verify_cert true\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.ldap_uri, "ldaps://ldap.example.com:636");
  ck_assert_str_eq(cfg.ldap_bind_dn, "cn=pam-auth,ou=services,dc=example,dc=com");
  ck_assert_str_eq(cfg.ldap_bind_password, "SecurePassword123");
  ck_assert_int_eq(cfg.tls_verify_cert, 1);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 3: TOTP enabled configuration */
START_TEST(test_parse_totp_enabled)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "totp_enabled true\n"
    "totp_mode append\n"
    "totp_attribute totpSecret\n"
    "time_step 30\n"
    "window_size 3\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_int_eq(cfg.totp_enabled, 1);
  ck_assert_int_eq(cfg.totp_mode, TOTP_MODE_APPEND);
  ck_assert_str_eq(cfg.totp_attribute, "totpSecret");
  ck_assert_int_eq(cfg.time_step, 30);
  ck_assert_int_eq(cfg.window_size, 3);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 4: TOTP disabled configuration */
START_TEST(test_parse_totp_disabled)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "totp_enabled false\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_int_eq(cfg.totp_enabled, 0);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 5: TLS configuration options */
START_TEST(test_parse_tls_config)
{
  const char *config =
    "ldap_uri ldap://ldap.example.com\n"
    "ldap_base dc=example,dc=com\n"
    "tls_mode starttls\n"
    "tls_verify_cert true\n"
    "tls_ca_cert_file /etc/ssl/certs/ca-certificates.crt\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.tls_mode, "starttls");
  ck_assert_int_eq(cfg.tls_verify_cert, 1);
  ck_assert_str_eq(cfg.tls_ca_cert_file, "/etc/ssl/certs/ca-certificates.crt");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 6: MFA enforcement settings */
START_TEST(test_parse_mfa_enforcement)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_period_days 7\n"
    "enforcement_mode graceful\n"
    "require_unique_match true\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_int_eq(cfg.grace_period_days, 7);
  ck_assert_str_eq(cfg.enforcement_mode, "graceful");
  ck_assert_int_eq(cfg.require_unique_match, 1);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 7: Enforcement mode - graceful (allows password-only) */
START_TEST(test_enforcement_mode_graceful)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "enforcement_mode graceful\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.enforcement_mode, "graceful");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 8: Enforcement mode - warn_only (allows password-only with warning) */
START_TEST(test_enforcement_mode_warn_only)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "enforcement_mode warn_only\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.enforcement_mode, "warn_only");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 9: Enforcement mode - strict (requires TOTP) */
START_TEST(test_enforcement_mode_strict)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "enforcement_mode strict\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.enforcement_mode, "strict");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 10: Empty values are treated as empty strings */
START_TEST(test_parse_empty_values)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "ldap_bind_dn\n"
    "ldap_bind_password\n"
    "totp_prefix\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  /* Empty values should be empty strings, not NULL */
  ck_assert_ptr_nonnull(cfg.ldap_bind_dn);
  ck_assert_str_eq(cfg.ldap_bind_dn, "");
  ck_assert_ptr_nonnull(cfg.ldap_bind_password);
  ck_assert_str_eq(cfg.ldap_bind_password, "");
  ck_assert_ptr_nonnull(cfg.totp_prefix);
  ck_assert_str_eq(cfg.totp_prefix, "");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 11: Comments and blank lines are ignored */
START_TEST(test_parse_comments_and_blanks)
{
  const char *config =
    "# This is a comment\n"
    "ldap_uri ldap://localhost\n"
    "\n"
    "  # Indented comment\n"
    "ldap_base dc=example,dc=com\n"
    "\n"
    "totp_enabled true\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.ldap_uri, "ldap://localhost");
  ck_assert_str_eq(cfg.ldap_base, "dc=example,dc=com");
  ck_assert_int_eq(cfg.totp_enabled, 1);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 12: Default values when config file missing */
START_TEST(test_default_values)
{
  pam_config_t cfg;
  int result = parse_config("/nonexistent/file", &cfg);

  /* Should fail when required settings missing */
  ck_assert_int_eq(result, -1);
}
END_TEST

/* Test 13: Required settings validation */
START_TEST(test_required_settings)
{
  /* Missing ldap_base (required) */
  const char *config = "ldap_uri ldap://localhost\n";
  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  /* Should fail validation */
  ck_assert_int_eq(result, -1);

  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 14: OWASP - Invalid characters in keyword */
START_TEST(test_security_invalid_keyword)
{
  /* Keywords must be alphanumeric + underscore only */
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "invalid-keyword value\n"  /* Hyphen not allowed */
    "totp_enabled true\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  /* Should parse successfully but skip invalid line */
  ck_assert_int_eq(result, 0);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 15: Boolean value parsing */
START_TEST(test_parse_boolean_values)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "totp_enabled yes\n"
    "tls_verify_cert 1\n"
    "require_unique_match on\n"
    "debug false\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_int_eq(cfg.totp_enabled, 1);   /* yes */
  ck_assert_int_eq(cfg.tls_verify_cert, 1); /* 1 */
  ck_assert_int_eq(cfg.require_unique_match, 1); /* on */
  ck_assert_int_eq(cfg.debug, 0);          /* false */

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 16: Grace message parsing */
START_TEST(test_parse_grace_message)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_message Please visit https://auth.example.com/manage_mfa\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.grace_message);
  ck_assert_str_eq(cfg.grace_message, "Please visit https://auth.example.com/manage_mfa");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 17: Grace period attribute parsing */
START_TEST(test_parse_grace_period_attribute)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_period_attribute customGracePeriodDays\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.grace_period_attribute);
  ck_assert_str_eq(cfg.grace_period_attribute, "customGracePeriodDays");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 18: Show grace message parsing */
START_TEST(test_parse_show_grace_message)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "show_grace_message false\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_int_eq(cfg.show_grace_message, 0);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 19: Grace period defaults */
START_TEST(test_grace_period_defaults)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);

  /* Check defaults */
  ck_assert_ptr_nonnull(cfg.grace_message);
  ck_assert_str_eq(cfg.grace_message, "Contact your administrator to set up MFA");
  ck_assert_int_eq(cfg.show_grace_message, 1); /* Enabled by default */
  ck_assert_ptr_nonnull(cfg.grace_period_attribute);
  ck_assert_str_eq(cfg.grace_period_attribute, "mfaGracePeriodDays");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 20: Complete grace period configuration */
START_TEST(test_parse_complete_grace_config)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_period_days 14\n"
    "grace_period_attribute mfaGracePeriodDays\n"
    "grace_message Contact IT helpdesk at ext. 5555 for MFA setup\n"
    "show_grace_message true\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_int_eq(cfg.grace_period_days, 14);
  ck_assert_str_eq(cfg.grace_period_attribute, "mfaGracePeriodDays");
  ck_assert_str_eq(cfg.grace_message, "Contact IT helpdesk at ext. 5555 for MFA setup");
  ck_assert_int_eq(cfg.show_grace_message, 1);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 21: Grace message with URL */
START_TEST(test_grace_message_with_url)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_message Please visit https://auth.example.com/manage_mfa to complete enrollment\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.grace_message, "Please visit https://auth.example.com/manage_mfa to complete enrollment");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 22: Empty grace message (should use empty string, not default) */
START_TEST(test_empty_grace_message)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_message\n";  /* Empty value */

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.grace_message);
  ck_assert_str_eq(cfg.grace_message, "");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test Suite Setup */
Suite *config_suite(void) {
  Suite *s;
  TCase *tc_core, *tc_security;

  s = suite_create("Configuration Parsing");

  /* Core test case */
  tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_parse_basic_ldap_config);
  tcase_add_test(tc_core, test_parse_ldap_bind_credentials);
  tcase_add_test(tc_core, test_parse_totp_enabled);
  tcase_add_test(tc_core, test_parse_totp_disabled);
  tcase_add_test(tc_core, test_parse_tls_config);
  tcase_add_test(tc_core, test_parse_mfa_enforcement);
  tcase_add_test(tc_core, test_enforcement_mode_graceful);
  tcase_add_test(tc_core, test_enforcement_mode_warn_only);
  tcase_add_test(tc_core, test_enforcement_mode_strict);
  tcase_add_test(tc_core, test_parse_empty_values);
  tcase_add_test(tc_core, test_parse_comments_and_blanks);
  tcase_add_test(tc_core, test_default_values);
  tcase_add_test(tc_core, test_required_settings);
  tcase_add_test(tc_core, test_parse_boolean_values);
  tcase_add_test(tc_core, test_parse_grace_message);
  tcase_add_test(tc_core, test_parse_grace_period_attribute);
  tcase_add_test(tc_core, test_parse_show_grace_message);
  tcase_add_test(tc_core, test_grace_period_defaults);
  tcase_add_test(tc_core, test_parse_complete_grace_config);
  tcase_add_test(tc_core, test_grace_message_with_url);
  tcase_add_test(tc_core, test_empty_grace_message);
  suite_add_tcase(s, tc_core);

  /* Security test case */
  tc_security = tcase_create("Security");
  tcase_add_test(tc_security, test_security_invalid_keyword);
  suite_add_tcase(s, tc_security);

  return s;
}

int main(void) {
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = config_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
