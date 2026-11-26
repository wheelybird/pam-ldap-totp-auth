/*
 * mfa_policy.c
 *
 * Enforcement decision for users without a TOTP secret.
 *
 *   strict    - deny everyone without a secret, including pending users
 *   graceful  - allow pending users within their grace period, deny everyone else
 *   warn_only - allow everyone (logged by the caller)
 *
 * Unknown modes are treated as strict.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/mfa_policy.h"

/* Days from 1970-01-01 to a civil date (proleptic Gregorian), avoiding timegm/TZ */
static long days_from_civil(int y, int m, int d) {
  y -= m <= 2;
  long era = (y >= 0 ? y : y - 399) / 400;
  long yoe = y - era * 400;
  long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

int mfa_days_elapsed(const char *generalized_time, time_t now) {
  int year, month, day, hour, min, sec;

  if (!generalized_time || strlen(generalized_time) < 14) {
    return -1;
  }
  for (int i = 0; i < 14; i++) {
    if (!isdigit((unsigned char)generalized_time[i])) {
      return -1;
    }
  }
  if (sscanf(generalized_time, "%4d%2d%2d%2d%2d%2d",
             &year, &month, &day, &hour, &min, &sec) != 6) {
    return -1;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 ||
      hour > 23 || min > 59 || sec > 60) {
    return -1;
  }

  long long then = (long long)days_from_civil(year, month, day) * 86400LL +
                   hour * 3600LL + min * 60LL + sec;
  long long elapsed = (long long)now - then;

  /* A date in the future would grant an open-ended grace period */
  if (elapsed < 0) {
    return -1;
  }
  return (int)(elapsed / 86400LL);
}

int mfa_effective_grace_days(const char *user_value, int default_days) {
  if (user_value && *user_value) {
    char *end = NULL;
    long v = strtol(user_value, &end, 10);
    if (end && *end == '\0' && v > 0 && v < 100000) {
      return (int)v;
    }
  }
  return default_days;
}

mfa_decision_e mfa_decide_without_secret(const char *status,
                                         const char *enrolled_date,
                                         int grace_days,
                                         const char *enforcement_mode,
                                         time_t now,
                                         int *days_remaining) {
  if (days_remaining) {
    *days_remaining = 0;
  }

  if (enforcement_mode && strcmp(enforcement_mode, "warn_only") == 0) {
    return MFA_ALLOW_WARN_ONLY;
  }

  int graceful = enforcement_mode && strcmp(enforcement_mode, "graceful") == 0;

  if (!status || strcmp(status, "pending") != 0) {
    return MFA_DENY_NOT_ENROLLED;
  }
  if (!graceful) {
    return MFA_DENY_STRICT;
  }

  int elapsed = mfa_days_elapsed(enrolled_date, now);
  if (elapsed < 0) {
    return MFA_DENY_GRACE_INVALID;
  }
  if (elapsed >= grace_days) {
    return MFA_DENY_GRACE_EXPIRED;
  }

  if (days_remaining) {
    *days_remaining = grace_days - elapsed;
  }
  return MFA_ALLOW_GRACE;
}

int mfa_decision_allows(mfa_decision_e decision) {
  return decision == MFA_ALLOW_GRACE || decision == MFA_ALLOW_WARN_ONLY;
}
