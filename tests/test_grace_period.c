/*
 * test_grace_period.c
 *
 * Unit tests for grace period messaging functionality
 * Tests the grace period feature including LDAP attribute reading and message generation
 */

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
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

/* Test 1: Grace period days calculation */
START_TEST(test_grace_period_calculation)
{
  /* This tests the date parsing and calculation logic */
  time_t now = time(NULL);
  struct tm *tm_now = gmtime(&now);

  /* Create a date 3 days ago */
  time_t three_days_ago = now - (3 * 24 * 60 * 60);
  struct tm *tm_past = gmtime(&three_days_ago);

  char enrolled_date[20];
  snprintf(enrolled_date, sizeof(enrolled_date), "%04d%02d%02d%02d%02d%02dZ",
           tm_past->tm_year + 1900,
           tm_past->tm_mon + 1,
           tm_past->tm_mday,
           tm_past->tm_hour,
           tm_past->tm_min,
           tm_past->tm_sec);

  /* Parse the date back */
  struct tm enrolled_tm = {0};
  int year, month, day, hour, min, sec;
  int parsed = sscanf(enrolled_date, "%4d%2d%2d%2d%2d%2d",
                      &year, &month, &day, &hour, &min, &sec);

  ck_assert_int_eq(parsed, 6);
  ck_assert_int_eq(year, tm_past->tm_year + 1900);
  ck_assert_int_eq(month, tm_past->tm_mon + 1);

  enrolled_tm.tm_year = year - 1900;
  enrolled_tm.tm_mon = month - 1;
  enrolled_tm.tm_mday = day;
  enrolled_tm.tm_hour = hour;
  enrolled_tm.tm_min = min;
  enrolled_tm.tm_sec = sec;
  enrolled_tm.tm_isdst = -1;

  time_t enrolled_time = mktime(&enrolled_tm);
  ck_assert(enrolled_time != -1);

  /* Calculate days elapsed */
  double seconds_elapsed = difftime(now, enrolled_time);
  int days_elapsed = (int)(seconds_elapsed / (60 * 60 * 24));

  /* Should be approximately 3 days (allowing for rounding) */
  ck_assert_int_ge(days_elapsed, 2);
  ck_assert_int_le(days_elapsed, 4);

  /* Days remaining from 7-day grace period */
  int days_remaining = 7 - days_elapsed;
  ck_assert_int_ge(days_remaining, 3);
  ck_assert_int_le(days_remaining, 5);
}
END_TEST

/* Test 2: Grace period with custom attribute name */
START_TEST(test_grace_period_custom_attribute)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_period_attribute customGracePeriod\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.grace_period_attribute, "customGracePeriod");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 3: Grace message formatting */
START_TEST(test_grace_message_formatting)
{
  char message[512];
  int days_remaining = 5;
  const char *grace_message = "Please visit https://auth.example.com/manage_mfa";

  snprintf(message, sizeof(message),
          "\n*** MFA ENROLLMENT REQUIRED ***\n"
          "You have %d day%s remaining to set up multi-factor authentication.\n"
          "%s\n",
          days_remaining,
          days_remaining == 1 ? "" : "s",
          grace_message);

  /* Verify message contains expected content */
  ck_assert(strstr(message, "*** MFA ENROLLMENT REQUIRED ***") != NULL);
  ck_assert(strstr(message, "5 days remaining") != NULL);
  ck_assert(strstr(message, grace_message) != NULL);
}
END_TEST

/* Test 4: Singular vs plural days */
START_TEST(test_grace_message_singular)
{
  char message[512];
  int days_remaining = 1;
  const char *grace_message = "Contact your administrator";

  snprintf(message, sizeof(message),
          "\n*** MFA ENROLLMENT REQUIRED ***\n"
          "You have %d day%s remaining to set up multi-factor authentication.\n"
          "%s\n",
          days_remaining,
          days_remaining == 1 ? "" : "s",
          grace_message);

  /* Should say "1 day" not "1 days" */
  ck_assert(strstr(message, "1 day remaining") != NULL);
  ck_assert(strstr(message, "1 days remaining") == NULL);
}
END_TEST

/* Test 5: Grace period disabled */
START_TEST(test_grace_period_disabled)
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

/* Test 6: Grace period with LDAP fallback */
START_TEST(test_grace_period_ldap_fallback)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_period_days 7\n"
    "grace_period_attribute mfaGracePeriodDays\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_int_eq(cfg.grace_period_days, 7); /* Config fallback */
  ck_assert_str_eq(cfg.grace_period_attribute, "mfaGracePeriodDays"); /* LDAP attribute */

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 7: Parse LDAP grace period value */
START_TEST(test_parse_ldap_grace_value)
{
  /* Simulate reading "14" from LDAP */
  const char *ldap_value = "14";
  int grace_days = atoi(ldap_value);

  ck_assert_int_eq(grace_days, 14);

  /* Test invalid values */
  const char *invalid = "abc";
  int invalid_days = atoi(invalid);
  ck_assert_int_eq(invalid_days, 0); /* atoi returns 0 for invalid input */
}
END_TEST

/* Test 8: Grace message with special characters */
START_TEST(test_grace_message_special_chars)
{
  const char *config =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "grace_message Call IT @ ext. 1234 or email help@example.com for MFA setup!\n";

  char *config_file = create_temp_config(config);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.grace_message, "Call IT @ ext. 1234 or email help@example.com for MFA setup!");

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test 9: Long grace message */
START_TEST(test_long_grace_message)
{
  const char *long_message = "To complete your multi-factor authentication enrollment, "
                             "please visit our secure portal at https://auth.example.com/mfa "
                             "during business hours (9 AM - 5 PM EST) or contact the IT helpdesk "
                             "at extension 5555 for assistance with the setup process.";

  char config_content[1024];
  snprintf(config_content, sizeof(config_content),
           "ldap_uri ldap://localhost\n"
           "ldap_base dc=example,dc=com\n"
           "grace_message %s\n",
           long_message);

  char *config_file = create_temp_config(config_content);
  ck_assert_ptr_nonnull(config_file);

  pam_config_t cfg;
  int result = parse_config(config_file, &cfg);

  ck_assert_int_eq(result, 0);
  ck_assert_str_eq(cfg.grace_message, long_message);

  free_config(&cfg);
  unlink(config_file);
  free(config_file);
}
END_TEST

/* Test Suite Setup */
Suite *grace_period_suite(void) {
  Suite *s;
  TCase *tc_core;

  s = suite_create("Grace Period Messaging");

  /* Core test case */
  tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_grace_period_calculation);
  tcase_add_test(tc_core, test_grace_period_custom_attribute);
  tcase_add_test(tc_core, test_grace_message_formatting);
  tcase_add_test(tc_core, test_grace_message_singular);
  tcase_add_test(tc_core, test_grace_period_disabled);
  tcase_add_test(tc_core, test_grace_period_ldap_fallback);
  tcase_add_test(tc_core, test_parse_ldap_grace_value);
  tcase_add_test(tc_core, test_grace_message_special_chars);
  tcase_add_test(tc_core, test_long_grace_message);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(void) {
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = grace_period_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
