/*
 * test_ldap_filter.c
 *
 * Unit tests for LDAP filter functionality
 *
 * Tests for:
 * - LDAP filter validation (syntax, structure, length)
 * - Configuration parsing (ldap_filter parameter)
 * - Filter combination logic (username + additional filter)
 * - Buffer overflow protection
 * - Backward compatibility (empty filter)
 */

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../include/pam_ldap_totp.h"

/* Test 1: Valid LDAP filter validation */
START_TEST(test_ldap_filter_valid_filters)
{
  /* Simple memberOf filter */
  ck_assert_int_eq(validate_ldap_filter("(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)"), 1);

  /* Account status filter */
  ck_assert_int_eq(validate_ldap_filter("(accountStatus=active)"), 1);

  /* OR filter with multiple conditions */
  ck_assert_int_eq(validate_ldap_filter("(|(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)(memberOf=cn=ssh-users,ou=groups,dc=example,dc=com))"), 1);

  /* AND filter with multiple conditions */
  ck_assert_int_eq(validate_ldap_filter("(&(accountStatus=active)(!(accountLocked=TRUE)))"), 1);

  /* Complex nested filter */
  ck_assert_int_eq(validate_ldap_filter("(&(objectClass=person)(|(memberOf=cn=admin,ou=groups,dc=example,dc=com)(memberOf=cn=vpn,ou=groups,dc=example,dc=com)))"), 1);

  /* Empty filter (feature disabled - valid) */
  ck_assert_int_eq(validate_ldap_filter(""), 1);
  ck_assert_int_eq(validate_ldap_filter(NULL), 1);

  /* Filter with wildcard */
  ck_assert_int_eq(validate_ldap_filter("(cn=vpn*)"), 1);

  /* Filter with equals in value (escaped) */
  ck_assert_int_eq(validate_ldap_filter("(description=test=value)"), 1);
}
END_TEST

/* Test 2: Invalid LDAP filter validation */
START_TEST(test_ldap_filter_invalid_filters)
{
  /* Missing opening parenthesis */
  ck_assert_int_eq(validate_ldap_filter("memberOf=cn=vpn-users)"), 0);

  /* Missing closing parenthesis */
  ck_assert_int_eq(validate_ldap_filter("(memberOf=cn=vpn-users"), 0);

  /* Unbalanced parentheses - too many opening */
  ck_assert_int_eq(validate_ldap_filter("((memberOf=cn=vpn-users)"), 0);

  /* Unbalanced parentheses - too many closing */
  ck_assert_int_eq(validate_ldap_filter("(memberOf=cn=vpn-users))"), 0);

  /* No parentheses at all */
  ck_assert_int_eq(validate_ldap_filter("memberOf=cn=vpn-users"), 0);

  /* Doesn't start with parenthesis */
  ck_assert_int_eq(validate_ldap_filter("test(memberOf=cn=vpn)"), 0);

  /* Doesn't end with parenthesis */
  ck_assert_int_eq(validate_ldap_filter("(memberOf=cn=vpn)test"), 0);

  /* Control character (newline) */
  ck_assert_int_eq(validate_ldap_filter("(memberOf=cn\n=vpn)"), 0);

  /* Control character (carriage return) */
  ck_assert_int_eq(validate_ldap_filter("(memberOf=cn\r=vpn)"), 0);

  /* DEL character */
  char filter_with_del[32];
  snprintf(filter_with_del, sizeof(filter_with_del), "(test=%c)", 0x7F);
  ck_assert_int_eq(validate_ldap_filter(filter_with_del), 0);

  /* Tab character is allowed (only control char exception) */
  ck_assert_int_eq(validate_ldap_filter("(description=test\tvalue)"), 1);
}
END_TEST

/* Test 3: LDAP filter length limits */
START_TEST(test_ldap_filter_length_limits)
{
  /* Exactly at limit (512 bytes) - valid */
  char filter_at_limit[513];
  memset(filter_at_limit, 'a', 510);  /* 510 'a' chars */
  filter_at_limit[0] = '(';
  filter_at_limit[510] = ')';
  filter_at_limit[511] = '\0';
  ck_assert_int_eq(validate_ldap_filter(filter_at_limit), 1);

  /* Over limit (513 bytes) - invalid */
  char filter_over_limit[600];
  memset(filter_over_limit, 'a', 513);
  filter_over_limit[0] = '(';
  filter_over_limit[512] = ')';
  filter_over_limit[513] = '\0';
  ck_assert_int_eq(validate_ldap_filter(filter_over_limit), 0);

  /* Way over limit - invalid */
  char *filter_huge = malloc(2000);
  ck_assert_ptr_nonnull(filter_huge);
  memset(filter_huge, 'a', 1999);
  filter_huge[0] = '(';
  filter_huge[1998] = ')';
  filter_huge[1999] = '\0';
  ck_assert_int_eq(validate_ldap_filter(filter_huge), 0);
  free(filter_huge);
}
END_TEST

/* Test 4: Configuration parsing with ldap_filter */
START_TEST(test_config_parsing_ldap_filter)
{
  /* Test 1: Valid filter in config */
  const char *config_with_filter =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "ldap_filter (memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)\n";

  FILE *fp = fopen("/tmp/test_ldap_filter_config1", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_with_filter);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_ldap_filter_config1", &cfg);
  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.ldap_filter);
  ck_assert_str_eq(cfg.ldap_filter, "(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)");

  free_config(&cfg);
  unlink("/tmp/test_ldap_filter_config1");
}
END_TEST

/* Test 5: Configuration parsing with empty ldap_filter */
START_TEST(test_config_parsing_empty_filter)
{
  /* Test: Empty filter (backward compatibility) */
  const char *config_empty_filter =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "ldap_filter\n";

  FILE *fp = fopen("/tmp/test_ldap_filter_config2", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_empty_filter);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_ldap_filter_config2", &cfg);
  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.ldap_filter);
  ck_assert_str_eq(cfg.ldap_filter, "");  /* Should be empty string */

  free_config(&cfg);
  unlink("/tmp/test_ldap_filter_config2");
}
END_TEST

/* Test 6: Configuration parsing without ldap_filter (default) */
START_TEST(test_config_parsing_no_filter)
{
  /* Test: No ldap_filter line (should default to empty) */
  const char *config_no_filter =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n";

  FILE *fp = fopen("/tmp/test_ldap_filter_config3", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_no_filter);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_ldap_filter_config3", &cfg);
  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.ldap_filter);
  ck_assert_str_eq(cfg.ldap_filter, "");  /* Should default to empty */

  free_config(&cfg);
  unlink("/tmp/test_ldap_filter_config3");
}
END_TEST

/* Test 7: Configuration parsing with invalid ldap_filter */
START_TEST(test_config_parsing_invalid_filter)
{
  /* Test: Invalid filter (unbalanced parens) - should be rejected */
  const char *config_invalid_filter =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "ldap_filter (memberOf=cn=vpn-users\n";  /* Missing closing paren */

  FILE *fp = fopen("/tmp/test_ldap_filter_config4", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_invalid_filter);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_ldap_filter_config4", &cfg);
  /* Parse should succeed, but invalid filter should be ignored/rejected */
  ck_assert_int_eq(result, 0);
  /* Invalid filter should not be set - should remain at default empty */
  ck_assert_ptr_nonnull(cfg.ldap_filter);
  ck_assert_str_eq(cfg.ldap_filter, "");

  free_config(&cfg);
  unlink("/tmp/test_ldap_filter_config4");
}
END_TEST

/* Test 8: Configuration parsing with too-long filter */
START_TEST(test_config_parsing_overlength_filter)
{
  /* Test: Filter exceeding 512 byte limit */
  char long_filter[600];
  memset(long_filter, 'a', 513);
  long_filter[0] = '(';
  long_filter[512] = ')';
  long_filter[513] = '\0';

  char config_content[700];
  snprintf(config_content, sizeof(config_content),
           "ldap_uri ldap://localhost\n"
           "ldap_base dc=example,dc=com\n"
           "ldap_filter %s\n", long_filter);

  FILE *fp = fopen("/tmp/test_ldap_filter_config5", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_content);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_ldap_filter_config5", &cfg);
  ck_assert_int_eq(result, 0);
  /* Over-length filter should be rejected, remain at default */
  ck_assert_ptr_nonnull(cfg.ldap_filter);
  ck_assert_str_eq(cfg.ldap_filter, "");

  free_config(&cfg);
  unlink("/tmp/test_ldap_filter_config5");
}
END_TEST

/* Test 9: Complex valid filters */
START_TEST(test_config_parsing_complex_filters)
{
  /* Test: OR filter */
  const char *config_or_filter =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "ldap_filter (|(memberOf=cn=vpn,ou=groups,dc=example,dc=com)(memberOf=cn=ssh,ou=groups,dc=example,dc=com))\n";

  FILE *fp = fopen("/tmp/test_ldap_filter_config6", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_or_filter);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_ldap_filter_config6", &cfg);
  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.ldap_filter);
  ck_assert_str_eq(cfg.ldap_filter, "(|(memberOf=cn=vpn,ou=groups,dc=example,dc=com)(memberOf=cn=ssh,ou=groups,dc=example,dc=com))");

  free_config(&cfg);
  unlink("/tmp/test_ldap_filter_config6");

  /* Test: AND with NOT filter */
  const char *config_and_not_filter =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "ldap_filter (&(accountStatus=active)(!(accountLocked=TRUE)))\n";

  fp = fopen("/tmp/test_ldap_filter_config7", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_and_not_filter);
  fclose(fp);

  result = parse_config("/tmp/test_ldap_filter_config7", &cfg);
  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.ldap_filter);
  ck_assert_str_eq(cfg.ldap_filter, "(&(accountStatus=active)(!(accountLocked=TRUE)))");

  free_config(&cfg);
  unlink("/tmp/test_ldap_filter_config7");
}
END_TEST

/* Test 10: Memory cleanup (free_config) */
START_TEST(test_config_free_ldap_filter)
{
  const char *config_with_filter =
    "ldap_uri ldap://localhost\n"
    "ldap_base dc=example,dc=com\n"
    "ldap_filter (memberOf=cn=test,ou=groups,dc=example,dc=com)\n";

  FILE *fp = fopen("/tmp/test_ldap_filter_config8", "w");
  ck_assert_ptr_nonnull(fp);
  fprintf(fp, "%s", config_with_filter);
  fclose(fp);

  pam_config_t cfg;
  int result = parse_config("/tmp/test_ldap_filter_config8", &cfg);
  ck_assert_int_eq(result, 0);
  ck_assert_ptr_nonnull(cfg.ldap_filter);

  /* Free should not crash */
  free_config(&cfg);

  /* After free, pointers should be NULL (config zeroed) */
  ck_assert_ptr_null(cfg.ldap_filter);

  unlink("/tmp/test_ldap_filter_config8");
}
END_TEST

/* Test 11: Parentheses depth tracking */
START_TEST(test_ldap_filter_parentheses_depth)
{
  /* Deeply nested valid filter */
  ck_assert_int_eq(validate_ldap_filter("(((((test=value)))))"), 1);

  /* Unbalanced - one extra opening */
  ck_assert_int_eq(validate_ldap_filter("((((((test=value)))))"), 0);

  /* Unbalanced - one extra closing */
  ck_assert_int_eq(validate_ldap_filter("(((((test=value))))))"), 0);

  /* Wrong order - closing before opening completes */
  ck_assert_int_eq(validate_ldap_filter("((test=value)))"), 0);
}
END_TEST

/* Test 12: Special characters in filter values */
START_TEST(test_ldap_filter_special_chars)
{
  /* Filter with equals sign in value */
  ck_assert_int_eq(validate_ldap_filter("(description=a=b)"), 1);

  /* Filter with comma in value */
  ck_assert_int_eq(validate_ldap_filter("(cn=Last, First)"), 1);

  /* Filter with space in value */
  ck_assert_int_eq(validate_ldap_filter("(cn=John Doe)"), 1);

  /* Filter with asterisk wildcard */
  ck_assert_int_eq(validate_ldap_filter("(cn=vpn*)"), 1);

  /* Filter with backslash (LDAP escape) */
  ck_assert_int_eq(validate_ldap_filter("(cn=test\\2a)"), 1);

  /* Filter with hyphen in value */
  ck_assert_int_eq(validate_ldap_filter("(cn=test-user)"), 1);

  /* Filter with underscore in value */
  ck_assert_int_eq(validate_ldap_filter("(cn=test_user)"), 1);

  /* Filter with period in value */
  ck_assert_int_eq(validate_ldap_filter("(cn=user.name)"), 1);

  /* Filter with at-sign in value */
  ck_assert_int_eq(validate_ldap_filter("(mail=user@example.com)"), 1);
}
END_TEST

/* Test user search filter construction (#4: multiple login attributes) */
START_TEST(test_build_user_filter)
{
  pam_config_t cfg;
  char buf[1024];
  memset(&cfg, 0, sizeof(cfg));

  /* Unset login_attribute falls back to uid */
  ck_assert_int_eq(build_user_filter(buf, sizeof(buf), "alice", &cfg), 1);
  ck_assert_str_eq(buf, "(uid=alice)");

  cfg.login_attribute = "mail";
  ck_assert_int_eq(build_user_filter(buf, sizeof(buf), "a@example.com", &cfg), 1);
  ck_assert_str_eq(buf, "(mail=a@example.com)");

  cfg.login_attribute = "uid,mail";
  ck_assert_int_eq(build_user_filter(buf, sizeof(buf), "alice", &cfg), 1);
  ck_assert_str_eq(buf, "(|(uid=alice)(mail=alice))");

  cfg.login_attribute = " uid , mail ,cn";
  ck_assert_int_eq(build_user_filter(buf, sizeof(buf), "alice", &cfg), 1);
  ck_assert_str_eq(buf, "(|(uid=alice)(mail=alice)(cn=alice))");

  cfg.ldap_filter = "(memberOf=cn=vpn,dc=example,dc=com)";
  ck_assert_int_eq(build_user_filter(buf, sizeof(buf), "alice", &cfg), 1);
  ck_assert_str_eq(buf, "(&(|(uid=alice)(mail=alice)(cn=alice))(memberOf=cn=vpn,dc=example,dc=com))");

  cfg.login_attribute = "uid";
  ck_assert_int_eq(build_user_filter(buf, sizeof(buf), "alice", &cfg), 1);
  ck_assert_str_eq(buf, "(&(uid=alice)(memberOf=cn=vpn,dc=example,dc=com))");
}
END_TEST

START_TEST(test_build_user_filter_escapes_username)
{
  pam_config_t cfg;
  char buf[1024];
  memset(&cfg, 0, sizeof(cfg));

  cfg.login_attribute = "uid,mail";
  ck_assert_int_eq(build_user_filter(buf, sizeof(buf), "*)(uid=*", &cfg), 1);
  ck_assert_str_eq(buf, "(|(uid=\\2a\\29\\28uid=\\2a)(mail=\\2a\\29\\28uid=\\2a))");
}
END_TEST

START_TEST(test_build_user_filter_rejects_bad_input)
{
  pam_config_t cfg;
  char buf[1024];
  char small[16];
  memset(&cfg, 0, sizeof(cfg));

  const char *bad[] = { "uid,(cn=*)", "uid,", ",", "uid mail", "uid,ma=il", NULL };
  for (int i = 0; bad[i]; i++) {
    cfg.login_attribute = (char *)bad[i];
    ck_assert_msg(build_user_filter(buf, sizeof(buf), "alice", &cfg) == 0,
                  "login_attribute '%s' should be rejected", bad[i]);
  }

  cfg.login_attribute = "uid,mail";
  ck_assert_int_eq(build_user_filter(small, sizeof(small), "alice", &cfg), 0);
}
END_TEST

START_TEST(test_require_unique_user_match)
{
  pam_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));

  cfg.login_attribute = "uid";
  ck_assert_int_eq(require_unique_user_match(&cfg), 0);
  cfg.require_unique_match = 1;
  ck_assert_int_eq(require_unique_user_match(&cfg), 1);

  /* Several attributes always require a unique match */
  cfg.require_unique_match = 0;
  cfg.login_attribute = "uid,mail";
  ck_assert_int_eq(require_unique_user_match(&cfg) != 0, 1);
}
END_TEST

/* Test Suite Setup */
Suite *ldap_filter_suite(void) {
  Suite *s;
  TCase *tc_validation, *tc_config, *tc_user_filter, *tc_edge_cases;

  s = suite_create("LDAP Filter Tests");

  /* Filter validation tests */
  tc_validation = tcase_create("Filter Validation");
  tcase_add_test(tc_validation, test_ldap_filter_valid_filters);
  tcase_add_test(tc_validation, test_ldap_filter_invalid_filters);
  tcase_add_test(tc_validation, test_ldap_filter_length_limits);
  tcase_add_test(tc_validation, test_ldap_filter_parentheses_depth);
  tcase_add_test(tc_validation, test_ldap_filter_special_chars);
  suite_add_tcase(s, tc_validation);

  /* Configuration parsing tests */
  tc_config = tcase_create("Configuration Parsing");
  tcase_add_test(tc_config, test_config_parsing_ldap_filter);
  tcase_add_test(tc_config, test_config_parsing_empty_filter);
  tcase_add_test(tc_config, test_config_parsing_no_filter);
  tcase_add_test(tc_config, test_config_parsing_invalid_filter);
  tcase_add_test(tc_config, test_config_parsing_overlength_filter);
  tcase_add_test(tc_config, test_config_parsing_complex_filters);
  tcase_add_test(tc_config, test_config_free_ldap_filter);
  suite_add_tcase(s, tc_config);

  /* User search filter construction */
  tc_user_filter = tcase_create("User Search Filter");
  tcase_add_test(tc_user_filter, test_build_user_filter);
  tcase_add_test(tc_user_filter, test_build_user_filter_escapes_username);
  tcase_add_test(tc_user_filter, test_build_user_filter_rejects_bad_input);
  tcase_add_test(tc_user_filter, test_require_unique_user_match);
  suite_add_tcase(s, tc_user_filter);

  /* Edge cases */
  tc_edge_cases = tcase_create("Edge Cases");
  /* Can add more edge case tests here if needed */
  suite_add_tcase(s, tc_edge_cases);

  return s;
}

int main(void) {
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = ldap_filter_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
