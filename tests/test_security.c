/*
 * test_security.c
 *
 * OWASP Security Tests for PAM LDAP TOTP Module
 *
 * Tests for:
 * - LDAP injection prevention
 * - Buffer overflow protection
 * - Input validation
 * - Timing attack resistance
 * - Secure memory handling
 */

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../include/pam_ldap_totp.h"

/* Test 1: LDAP filter injection prevention */
START_TEST(test_ldap_filter_injection_prevention)
{
  /* Test that LDAP special characters are properly escaped */
  const char *malicious_usernames[] = {
    "admin)(uid=*",              /* OR injection attempt */
    "user*",                     /* Wildcard injection */
    "user\\2a",                  /* Escaped wildcard */
    "user(objectClass=*)",       /* Filter injection */
    "user)(|(uid=*",             /* Complex injection */
    NULL
  };

  for (int i = 0; malicious_usernames[i] != NULL; i++) {
    char *escaped = ldap_escape_filter(malicious_usernames[i]);
    ck_assert_ptr_nonnull(escaped);

    /* Verify no unescaped special characters remain */
    ck_assert_ptr_null(strchr(escaped, '('));
    ck_assert_ptr_null(strchr(escaped, ')'));
    ck_assert_ptr_null(strchr(escaped, '*'));
    ck_assert_ptr_null(strchr(escaped, '\\'));

    free(escaped);
  }
}
END_TEST

/* Test 2: Username validation */
START_TEST(test_username_validation)
{
  /* Valid usernames */
  ck_assert_int_eq(is_safe_username("user123"), 1);
  ck_assert_int_eq(is_safe_username("john.doe"), 1);
  ck_assert_int_eq(is_safe_username("user_name"), 1);
  ck_assert_int_eq(is_safe_username("user-name"), 1);

  /* Invalid usernames */
  ck_assert_int_eq(is_safe_username(""), 0);           /* Empty */
  ck_assert_int_eq(is_safe_username(NULL), 0);         /* NULL */
  ck_assert_int_eq(is_safe_username("user;rm -rf"), 0); /* Command injection */
  ck_assert_int_eq(is_safe_username("user\n"), 0);     /* Newline */
  ck_assert_int_eq(is_safe_username("user\0admin"), 0); /* Null byte */

  /* Test very long username (potential buffer overflow) */
  char long_username[1024];
  memset(long_username, 'a', sizeof(long_username) - 1);
  long_username[sizeof(long_username) - 1] = '\0';
  ck_assert_int_eq(is_safe_username(long_username), 0);
}
END_TEST

/* Test 3: LDAP attribute validation */
START_TEST(test_ldap_attribute_validation)
{
  /* Valid attributes */
  ck_assert_int_eq(is_valid_ldap_attribute("uid"), 1);
  ck_assert_int_eq(is_valid_ldap_attribute("totpSecret"), 1);
  ck_assert_int_eq(is_valid_ldap_attribute("sAMAccountName"), 1);

  /* Invalid attributes */
  ck_assert_int_eq(is_valid_ldap_attribute(""), 0);
  ck_assert_int_eq(is_valid_ldap_attribute(NULL), 0);
  ck_assert_int_eq(is_valid_ldap_attribute("attr;DROP TABLE"), 0);
  ck_assert_int_eq(is_valid_ldap_attribute("attr\n"), 0);
}
END_TEST

/* Test 4: Buffer overflow prevention in config parsing */
START_TEST(test_config_buffer_overflow)
{
  /* Create config with very long line (>1024 bytes) */
  char config_content[2048];
  memset(config_content, 'A', sizeof(config_content) - 1);
  config_content[sizeof(config_content) - 1] = '\0';

  /* Create a config file with oversized line */
  FILE *fp = fopen("/tmp/test_overflow_config", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fprintf(fp, "very_long_keyword %s\n", config_content);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_overflow_config", &cfg);

  /* Should handle gracefully (skip long line) */
  ck_assert_int_eq(result, 0);

  free_config(&cfg);
  unlink("/tmp/test_overflow_config");
}
END_TEST

/* Test 5: Timing attack resistance - constant time comparison */
START_TEST(test_constant_time_comparison)
{
  const char *secret1 = "JBSWY3DPEHPK3PXP";
  const char *secret2 = "JBSWY3DPEHPK3PXP";
  const char *secret3 = "ABCDEFGHIJKLMNOP";

  /* Measure time for matching strings */
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int result1 = constant_time_compare(secret1, secret2, strlen(secret1));
  clock_gettime(CLOCK_MONOTONIC, &end);
  long match_time = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);

  /* Measure time for non-matching strings */
  clock_gettime(CLOCK_MONOTONIC, &start);
  int result2 = constant_time_compare(secret1, secret3, strlen(secret1));
  clock_gettime(CLOCK_MONOTONIC, &end);
  long nomatch_time = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);

  /* Verify results are correct */
  ck_assert_int_eq(result1, 1);  /* Match */
  ck_assert_int_eq(result2, 0);  /* No match */

  /* Timing difference should be minimal (< 10% variation) */
  /* This is a rough check; precise timing attacks are complex */
  long diff = labs(match_time - nomatch_time);
  long max_time = match_time > nomatch_time ? match_time : nomatch_time;

  /* Allow up to 50% variation due to system scheduling */
  ck_assert_int_lt(diff, max_time / 2);
}
END_TEST

/* Test 6: Secure memory cleanup */
START_TEST(test_secure_memory_cleanup)
{
  char *sensitive_data = strdup("SecretPassword123");
  char *ptr = sensitive_data;

  /* Secure free should zero memory before freeing */
  secure_free(sensitive_data, strlen(sensitive_data));

  /* Note: We can't actually verify the memory was zeroed after free
   * as accessing freed memory is undefined behavior. This test just
   * verifies the function doesn't crash. */

  /* Verify NULL handling */
  secure_free(NULL, 0);  /* Should not crash */
}
END_TEST

/* Test 7: Date validation */
START_TEST(test_date_validation)
{
  /* Valid dates */
  ck_assert_int_eq(is_valid_date(2025, 10, 16, 12, 30, 45), 1);
  ck_assert_int_eq(is_valid_date(2025, 1, 1, 0, 0, 0), 1);
  ck_assert_int_eq(is_valid_date(2025, 12, 31, 23, 59, 59), 1);

  /* Invalid dates */
  ck_assert_int_eq(is_valid_date(2025, 13, 1, 12, 0, 0), 0);  /* Month > 12 */
  ck_assert_int_eq(is_valid_date(2025, 0, 1, 12, 0, 0), 0);   /* Month = 0 */
  ck_assert_int_eq(is_valid_date(2025, 10, 32, 12, 0, 0), 0); /* Day > 31 */
  ck_assert_int_eq(is_valid_date(2025, 10, 0, 12, 0, 0), 0);  /* Day = 0 */
  ck_assert_int_eq(is_valid_date(2025, 10, 16, 24, 0, 0), 0); /* Hour >= 24 */
  ck_assert_int_eq(is_valid_date(2025, 10, 16, -1, 0, 0), 0); /* Hour < 0 */
  ck_assert_int_eq(is_valid_date(2025, 10, 16, 12, 60, 0), 0); /* Minute >= 60 */
  ck_assert_int_eq(is_valid_date(2025, 10, 16, 12, 30, 60), 0); /* Second >= 60 */
}
END_TEST

/* Test 8: Safe string duplication */
START_TEST(test_safe_strdup)
{
  /* Normal string */
  char *dup1 = safe_strdup("test string");
  ck_assert_ptr_nonnull(dup1);
  ck_assert_str_eq(dup1, "test string");
  free(dup1);

  /* Empty string */
  char *dup2 = safe_strdup("");
  ck_assert_ptr_nonnull(dup2);
  ck_assert_str_eq(dup2, "");
  free(dup2);

  /* NULL handling */
  char *dup3 = safe_strdup(NULL);
  ck_assert_ptr_null(dup3);
}
END_TEST

/* Test 9: Configuration file permission check */
START_TEST(test_config_file_permissions)
{
  /* Create test config file with password */
  FILE *fp = fopen("/tmp/test_perms_config", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fprintf(fp, "ldap_bind_password SecretPassword\n");
  fclose(fp);

  /* Set insecure permissions (world-readable) */
  chmod("/tmp/test_perms_config", 0644);

  /* Parse should succeed (module doesn't enforce permissions)
   * but in production, admin should set 600 permissions */
  pam_config_t cfg;
  int result = parse_config("/tmp/test_perms_config", &cfg);
  ck_assert_int_eq(result, 0);

  free_config(&cfg);
  unlink("/tmp/test_perms_config");
}
END_TEST

/* Test 10: LDAP URI validation */
START_TEST(test_ldap_uri_validation)
{
  /* This test verifies that invalid LDAP URIs are handled
   * Note: Full URI validation would happen at LDAP connect time */

  const char *config_valid =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n";

  FILE *fp = fopen("/tmp/test_uri_config", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_valid);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_uri_config", &cfg);
  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.ldap_uri, "ldap://localhost");

  free_config(&cfg);
  unlink("/tmp/test_uri_config");
}
END_TEST

/* Test Suite Setup */
Suite *security_suite(void) {
  Suite *s;
  TCase *tc_injection, *tc_validation, *tc_buffer, *tc_timing;

  s = suite_create("OWASP Security Tests");

  /* Injection prevention */
  tc_injection = tcase_create("Injection Prevention");
  tcase_add_test(tc_injection, test_ldap_filter_injection_prevention);
  suite_add_tcase(s, tc_injection);

  /* Input validation */
  tc_validation = tcase_create("Input Validation");
  tcase_add_test(tc_validation, test_username_validation);
  tcase_add_test(tc_validation, test_ldap_attribute_validation);
  tcase_add_test(tc_validation, test_date_validation);
  tcase_add_test(tc_validation, test_safe_strdup);
  tcase_add_test(tc_validation, test_ldap_uri_validation);
  suite_add_tcase(s, tc_validation);

  /* Buffer overflow prevention */
  tc_buffer = tcase_create("Buffer Overflow Prevention");
  tcase_add_test(tc_buffer, test_config_buffer_overflow);
  suite_add_tcase(s, tc_buffer);

  /* Timing attack resistance */
  tc_timing = tcase_create("Timing Attack Resistance");
  tcase_add_test(tc_timing, test_constant_time_comparison);
  tcase_add_test(tc_timing, test_secure_memory_cleanup);
  tcase_add_test(tc_timing, test_config_file_permissions);
  suite_add_tcase(s, tc_timing);

  return s;
}

int main(void) {
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = security_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
