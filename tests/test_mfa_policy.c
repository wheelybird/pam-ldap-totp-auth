/*
 * test_mfa_policy.c
 *
 * Enforcement decisions for users without a TOTP secret (issue #8)
 */

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "../include/mfa_policy.h"

/* 2026-11-26 12:00:00 UTC */
static const time_t NOW = 1795694400;

static void gt_days_ago(char *buf, size_t len, int days) {
  time_t t = NOW - (time_t)days * 86400;
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(buf, len, "%Y%m%d%H%M%SZ", &tm);
}

START_TEST(test_days_elapsed)
{
  char d[20];
  gt_days_ago(d, sizeof(d), 0);
  ck_assert_int_eq(mfa_days_elapsed(d, NOW), 0);
  gt_days_ago(d, sizeof(d), 3);
  ck_assert_int_eq(mfa_days_elapsed(d, NOW), 3);
  ck_assert_int_eq(mfa_days_elapsed("20261126120000Z", NOW), 0);
  ck_assert_int_eq(mfa_days_elapsed("20261119115959Z", NOW), 7);
}
END_TEST

START_TEST(test_days_elapsed_invalid)
{
  ck_assert_int_eq(mfa_days_elapsed(NULL, NOW), -1);
  ck_assert_int_eq(mfa_days_elapsed("", NOW), -1);
  ck_assert_int_eq(mfa_days_elapsed("2026", NOW), -1);
  ck_assert_int_eq(mfa_days_elapsed("2026112X120000Z", NOW), -1);
  ck_assert_int_eq(mfa_days_elapsed("20261326120000Z", NOW), -1);
  /* Future dates would otherwise grant an open-ended grace period */
  ck_assert_int_eq(mfa_days_elapsed("20991231000000Z", NOW), -1);
}
END_TEST

START_TEST(test_effective_grace_days)
{
  ck_assert_int_eq(mfa_effective_grace_days(NULL, 7), 7);
  ck_assert_int_eq(mfa_effective_grace_days("", 7), 7);
  ck_assert_int_eq(mfa_effective_grace_days("14", 7), 14);
  ck_assert_int_eq(mfa_effective_grace_days("0", 7), 7);
  ck_assert_int_eq(mfa_effective_grace_days("-3", 7), 7);
  ck_assert_int_eq(mfa_effective_grace_days("14days", 7), 7);
}
END_TEST

/* The bypass in #8: no status, none or disabled used to pass under graceful */
START_TEST(test_graceful_denies_not_pending)
{
  ck_assert_int_eq(mfa_decide_without_secret(NULL, NULL, 7, "graceful", NOW, NULL),
                   MFA_DENY_NOT_ENROLLED);
  ck_assert_int_eq(mfa_decide_without_secret("none", NULL, 7, "graceful", NOW, NULL),
                   MFA_DENY_NOT_ENROLLED);
  ck_assert_int_eq(mfa_decide_without_secret("disabled", NULL, 7, "graceful", NOW, NULL),
                   MFA_DENY_NOT_ENROLLED);
  ck_assert_int_eq(mfa_decide_without_secret("active", NULL, 7, "graceful", NOW, NULL),
                   MFA_DENY_NOT_ENROLLED);
}
END_TEST

START_TEST(test_graceful_pending_within_grace)
{
  char d[20];
  int remaining = -1;
  gt_days_ago(d, sizeof(d), 2);
  ck_assert_int_eq(mfa_decide_without_secret("pending", d, 7, "graceful", NOW, &remaining),
                   MFA_ALLOW_GRACE);
  ck_assert_int_eq(remaining, 5);
}
END_TEST

START_TEST(test_graceful_pending_expired)
{
  char d[20];
  gt_days_ago(d, sizeof(d), 7);
  ck_assert_int_eq(mfa_decide_without_secret("pending", d, 7, "graceful", NOW, NULL),
                   MFA_DENY_GRACE_EXPIRED);
  gt_days_ago(d, sizeof(d), 30);
  ck_assert_int_eq(mfa_decide_without_secret("pending", d, 7, "graceful", NOW, NULL),
                   MFA_DENY_GRACE_EXPIRED);
}
END_TEST

START_TEST(test_graceful_pending_per_user_grace)
{
  char d[20];
  gt_days_ago(d, sizeof(d), 10);
  int days = mfa_effective_grace_days("14", 7);
  ck_assert_int_eq(mfa_decide_without_secret("pending", d, days, "graceful", NOW, NULL),
                   MFA_ALLOW_GRACE);
}
END_TEST

START_TEST(test_graceful_pending_bad_date_fails_closed)
{
  ck_assert_int_eq(mfa_decide_without_secret("pending", NULL, 7, "graceful", NOW, NULL),
                   MFA_DENY_GRACE_INVALID);
  ck_assert_int_eq(mfa_decide_without_secret("pending", "garbage", 7, "graceful", NOW, NULL),
                   MFA_DENY_GRACE_INVALID);
}
END_TEST

START_TEST(test_strict_denies_everyone)
{
  char d[20];
  gt_days_ago(d, sizeof(d), 1);
  ck_assert_int_eq(mfa_decide_without_secret("pending", d, 7, "strict", NOW, NULL),
                   MFA_DENY_STRICT);
  ck_assert_int_eq(mfa_decide_without_secret(NULL, NULL, 7, "strict", NOW, NULL),
                   MFA_DENY_NOT_ENROLLED);
}
END_TEST

START_TEST(test_unknown_mode_is_strict)
{
  char d[20];
  gt_days_ago(d, sizeof(d), 1);
  ck_assert_int_eq(mfa_decide_without_secret("pending", d, 7, "lenient", NOW, NULL),
                   MFA_DENY_STRICT);
  ck_assert_int_eq(mfa_decide_without_secret("pending", d, 7, NULL, NOW, NULL),
                   MFA_DENY_STRICT);
}
END_TEST

START_TEST(test_warn_only_allows)
{
  ck_assert_int_eq(mfa_decide_without_secret(NULL, NULL, 7, "warn_only", NOW, NULL),
                   MFA_ALLOW_WARN_ONLY);
  ck_assert_int_eq(mfa_decide_without_secret("pending", "garbage", 7, "warn_only", NOW, NULL),
                   MFA_ALLOW_WARN_ONLY);
}
END_TEST

START_TEST(test_decision_allows)
{
  ck_assert(mfa_decision_allows(MFA_ALLOW_GRACE));
  ck_assert(mfa_decision_allows(MFA_ALLOW_WARN_ONLY));
  ck_assert(!mfa_decision_allows(MFA_DENY_NOT_ENROLLED));
  ck_assert(!mfa_decision_allows(MFA_DENY_GRACE_EXPIRED));
  ck_assert(!mfa_decision_allows(MFA_DENY_GRACE_INVALID));
  ck_assert(!mfa_decision_allows(MFA_DENY_STRICT));
}
END_TEST

static Suite *mfa_policy_suite(void) {
  Suite *s = suite_create("MFA policy");
  TCase *tc = tcase_create("Core");

  tcase_add_test(tc, test_days_elapsed);
  tcase_add_test(tc, test_days_elapsed_invalid);
  tcase_add_test(tc, test_effective_grace_days);
  tcase_add_test(tc, test_graceful_denies_not_pending);
  tcase_add_test(tc, test_graceful_pending_within_grace);
  tcase_add_test(tc, test_graceful_pending_expired);
  tcase_add_test(tc, test_graceful_pending_per_user_grace);
  tcase_add_test(tc, test_graceful_pending_bad_date_fails_closed);
  tcase_add_test(tc, test_strict_denies_everyone);
  tcase_add_test(tc, test_unknown_mode_is_strict);
  tcase_add_test(tc, test_warn_only_allows);
  tcase_add_test(tc, test_decision_allows);
  suite_add_tcase(s, tc);
  return s;
}

int main(void) {
  SRunner *sr = srunner_create(mfa_policy_suite());
  srunner_run_all(sr, CK_NORMAL);
  int failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
