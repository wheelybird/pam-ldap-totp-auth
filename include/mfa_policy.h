/*
 * mfa_policy.h
 *
 * Decides whether a user without a TOTP secret may authenticate.
 * Pure logic with no LDAP or PAM calls, so it can be unit tested.
 */

#ifndef MFA_POLICY_H
#define MFA_POLICY_H

#include <time.h>

typedef enum {
  MFA_ALLOW_GRACE = 0,       /* pending and within grace period */
  MFA_ALLOW_WARN_ONLY,       /* enforcement_mode warn_only */
  MFA_DENY_NOT_ENROLLED,     /* no secret and not pending */
  MFA_DENY_GRACE_EXPIRED,
  MFA_DENY_GRACE_INVALID,    /* pending but enrolment date missing or unparseable */
  MFA_DENY_STRICT            /* pending, but strict mode allows no grace period */
} mfa_decision_e;

/* Whole days since an LDAP GeneralizedTime (UTC), or -1 if it can't be parsed */
int mfa_days_elapsed(const char *generalized_time, time_t now);

/* Per-user grace days from LDAP if it is a positive integer, otherwise the default */
int mfa_effective_grace_days(const char *user_value, int default_days);

mfa_decision_e mfa_decide_without_secret(const char *status,
                                         const char *enrolled_date,
                                         int grace_days,
                                         const char *enforcement_mode,
                                         time_t now,
                                         int *days_remaining);

int mfa_decision_allows(mfa_decision_e decision);

#endif /* MFA_POLICY_H */
