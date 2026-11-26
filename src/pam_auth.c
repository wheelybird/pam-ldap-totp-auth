/*
 * pam_auth.c
 *
 * Unified LDAP + TOTP authentication
 * Single module that handles both password and TOTP validation
 */

#include "pam_ldap_totp.h"
#include "mfa_policy.h"
#include <security/pam_modules.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>

/*
 * Send an informational message to the user (no response expected)
 * Uses PAM_TEXT_INFO message type which displays to user without prompting
 *
 * Returns: PAM_SUCCESS or PAM_CONV_ERR
 */
static int send_info_message(pam_handle_t *pamh, const char *message) {
  struct pam_conv *conv;
  struct pam_message msg;
  const struct pam_message *msgp;
  struct pam_response *resp = NULL;
  int retval;

  /* Get conversation function */
  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (retval != PAM_SUCCESS || !conv || !conv->conv) {
    return PAM_CONV_ERR;
  }

  /* Setup informational message */
  msg.msg_style = PAM_TEXT_INFO;
  msg.msg = message;
  msgp = &msg;

  /* Call conversation function */
  retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);

  /* Free response if allocated (shouldn't be for TEXT_INFO, but be safe) */
  if (resp) {
    if (resp[0].resp) {
      free(resp[0].resp);
    }
    free(resp);
  }

  return retval;
}

/*
 * Prompt user for input using PAM conversation
 *
 * More portable than pam_prompt() - uses direct PAM conversation API
 *
 * Returns: PAM_SUCCESS on success, PAM_CONV_ERR on failure
 *          response is allocated and must be freed by caller
 */
static int converse(pam_handle_t *pamh, int style, const char *prompt, char **response) {
  struct pam_conv *conv;
  struct pam_message msg;
  const struct pam_message *msgp;
  struct pam_response *resp;
  int retval;

  /* Get conversation function */
  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (retval != PAM_SUCCESS || !conv || !conv->conv) {
    return PAM_CONV_ERR;
  }

  /* Setup message */
  msg.msg_style = style;
  msg.msg = prompt;
  msgp = &msg;

  /* Call conversation function */
  resp = NULL;
  retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);

  if (retval != PAM_SUCCESS || !resp || !resp[0].resp) {
    if (resp) {
      free(resp);
    }
    return PAM_CONV_ERR;
  }

  /* Extract response */
  *response = resp[0].resp;
  free(resp);

  return PAM_SUCCESS;
}

/*
 * Prompt user for multiple inputs in one conversation call
 * This is required for SSH keyboard-interactive which expects all prompts at once
 *
 * Returns: PAM_SUCCESS on success, PAM_CONV_ERR on failure
 *          responses are allocated and must be freed by caller
 */
static int converse_multi(pam_handle_t *pamh, const char *prompt1, const char *prompt2,
                         char **response1, char **response2) {
  struct pam_conv *conv;
  struct pam_message msgs[2];
  const struct pam_message *msgps[2];
  struct pam_response *resp = NULL;
  int retval;

  /* Get conversation function */
  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (retval != PAM_SUCCESS || !conv || !conv->conv) {
    return PAM_CONV_ERR;
  }

  /* Setup messages */
  msgs[0].msg_style = PAM_PROMPT_ECHO_OFF;
  msgs[0].msg = prompt1;
  msgps[0] = &msgs[0];

  msgs[1].msg_style = PAM_PROMPT_ECHO_OFF;
  msgs[1].msg = prompt2;
  msgps[1] = &msgs[1];

  /* Call conversation function with 2 messages */
  retval = conv->conv(2, msgps, &resp, conv->appdata_ptr);

  if (retval != PAM_SUCCESS || !resp) {
    if (resp) {
      free(resp);
    }
    return PAM_CONV_ERR;
  }

  if (!resp[0].resp || !resp[1].resp) {
    if (resp[0].resp) free(resp[0].resp);
    if (resp[1].resp) free(resp[1].resp);
    free(resp);
    return PAM_CONV_ERR;
  }

  /* Extract responses */
  *response1 = resp[0].resp;
  *response2 = resp[1].resp;
  free(resp);

  return PAM_SUCCESS;
}

/*
 * Decide whether a user with no TOTP secret may authenticate (see mfa_policy.c).
 * Every outcome is logged to syslog so password-only logins are auditable.
 */
static int handle_missing_secret(pam_handle_t *pamh, LDAP *ld,
                                 const char *username, pam_config_t *config) {
  char *status = ldap_get_attribute(pamh, ld, username, config->status_attribute, config);
  char *enrolled_date = NULL;
  char *user_grace = NULL;

  if (status && strcmp(status, "pending") == 0) {
    enrolled_date = ldap_get_attribute(pamh, ld, username, config->enrolled_date_attribute, config);
    if (config->grace_period_attribute && *config->grace_period_attribute) {
      user_grace = ldap_get_attribute(pamh, ld, username, config->grace_period_attribute, config);
    }
  }

  int grace_days = mfa_effective_grace_days(user_grace, config->grace_period_days);
  int days_remaining = 0;
  mfa_decision_e decision = mfa_decide_without_secret(status, enrolled_date, grace_days,
                                                      config->enforcement_mode,
                                                      time(NULL), &days_remaining);

  switch (decision) {
    case MFA_ALLOW_GRACE:
      pam_syslog(pamh, LOG_NOTICE,
                 "User '%s' authenticated without MFA: grace period, %d of %d day%s remaining",
                 username, days_remaining, grace_days, grace_days == 1 ? "" : "s");
      if (config->show_grace_message && config->grace_message) {
        char message[512];
        snprintf(message, sizeof(message),
                 "\n*** MFA ENROLMENT REQUIRED ***\n"
                 "You have %d day%s remaining to set up multi-factor authentication.\n"
                 "%s\n",
                 days_remaining, days_remaining == 1 ? "" : "s", config->grace_message);
        send_info_message(pamh, message);
      }
      break;
    case MFA_ALLOW_WARN_ONLY:
      pam_syslog(pamh, LOG_NOTICE,
                 "Warning: user '%s' authenticated without MFA (password-only, enforcement_mode=warn_only)",
                 username);
      break;
    case MFA_DENY_GRACE_EXPIRED:
      pam_syslog(pamh, LOG_NOTICE, "Grace period expired - TOTP setup required for user '%s'",
                 username);
      break;
    case MFA_DENY_GRACE_INVALID:
      pam_syslog(pamh, LOG_NOTICE,
                 "User '%s' is pending but %s is missing or invalid - denying access",
                 username, config->enrolled_date_attribute);
      break;
    case MFA_DENY_STRICT:
      pam_syslog(pamh, LOG_NOTICE,
                 "User '%s' is pending but enforcement_mode=strict allows no grace period",
                 username);
      break;
    case MFA_DENY_NOT_ENROLLED:
    default:
      pam_syslog(pamh, LOG_NOTICE, "TOTP required but not configured for user '%s'", username);
      break;
  }

  if (status) free(status);
  if (enrolled_date) free(enrolled_date);
  if (user_grace) free(user_grace);

  return mfa_decision_allows(decision) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

/*
 * Extract OTP from password input
 *
 * Extracts the last 6 or 8 digits as OTP code, remaining as password.
 * Supports both 6-digit TOTP codes and 8-digit scratch codes.
 *
 * OWASP Security: Does not log actual password or complete OTP code.
 * Debug mode shows only first 2 and last 2 digits of OTP for verification.
 */
/*
 * Extract OTP from password (append mode)
 *
 * Strategy: Always extract 6 digits for TOTP first.
 * If TOTP validation fails, caller can check if 8+ digits exist and re-extract.
 *
 * otp_len parameter: 6 for TOTP (default), 8 for scratch code (retry)
 */
static int extract_otp_from_password(const char *full_password, char **password, char **otp, int otp_len, pam_config_t *config) {
  size_t len = strlen(full_password);

  /* Minimum length: at least 1 char password + otp_len digits */
  if (len < (size_t)(otp_len + 1)) {
    DEBUG_LOG(config, "OTP extraction failed: input too short (min %d chars required)", otp_len + 1);
    return 0;
  }

  /* Validate that last otp_len characters are digits */
  for (int i = len - otp_len; i < (int)len; i++) {
    if (!isdigit((unsigned char)full_password[i])) {
      DEBUG_LOG(config, "OTP extraction failed: non-digit character in OTP position");
      return 0;
    }
  }

  /* Allocate and extract password and OTP */
  size_t pwd_len = len - otp_len;
  *password = (char *)malloc(pwd_len + 1);
  *otp = (char *)malloc(otp_len + 1);

  if (!*password || !*otp) {
    if (*password) free(*password);
    if (*otp) free(*otp);
    return 0;
  }

  memcpy(*password, full_password, pwd_len);
  (*password)[pwd_len] = '\0';

  memcpy(*otp, full_password + pwd_len, otp_len);
  (*otp)[otp_len] = '\0';

  /* Debug: Show redacted OTP for verification (first 2 + last 2 digits only) */
  if (config->debug) {
    if (otp_len == 6) {
      DEBUG_LOG(config, "Extracted 6-digit TOTP: %c%c**%c%c (password_len=%zu)",
                (*otp)[0], (*otp)[1], (*otp)[4], (*otp)[5], pwd_len);
    } else if (otp_len == 8) {
      DEBUG_LOG(config, "Extracted 8-digit scratch code: %c%c****%c%c (password_len=%zu)",
                (*otp)[0], (*otp)[1], (*otp)[6], (*otp)[7], pwd_len);
    }
  }

  return 1;
}

/*
 * Check if input has at least N trailing digits
 */
static int has_trailing_digits(const char *str, int count) {
  size_t len = strlen(str);
  if (len < (size_t)count) {
    return 0;
  }

  for (int i = len - count; i < (int)len; i++) {
    if (!isdigit((unsigned char)str[i])) {
      return 0;
    }
  }
  return 1;
}

/*
 * Challenge-response authentication function
 *
 * Prompts user separately for password and TOTP code using PAM conversation.
 * This provides better UX but requires PAM conversation support (SSH, sudo, login).
 * NOT compatible with OpenVPN which doesn't support PAM conversation.
 *
 * Flow:
 *   1. Password obtained via pam_get_authtok() (already done by caller)
 *   2. Validate password with LDAP bind
 *   3. Prompt for TOTP code using pam_prompt()
 *   4. Validate TOTP code
 *
 * Returns: PAM_SUCCESS or PAM_AUTH_ERR or PAM_AUTHINFO_UNAVAIL
 */
static int authenticate_challenge_response(pam_handle_t *pamh,
                                           const char *username,
                                           const char *password,
                                           pam_config_t *config) {
  int retval = PAM_AUTH_ERR;
  LDAP *ld = NULL;
  char *secret = NULL;
  char *otp_response = NULL;
  char *password_response = NULL;
  const char *password_to_use = password;

  INFO_LOG("Challenge-response authentication for user '%s'", username);

  /* Prompt for BOTH password and TOTP in one conversation call
   * This is required for SSH keyboard-interactive which expects all prompts together */
  if (!password) {
    DEBUG_LOG(config, "Prompting for password AND TOTP via PAM conversation");

    retval = converse_multi(pamh, "Password:", config->challenge_prompt,
                           &password_response, &otp_response);

    if (retval != PAM_SUCCESS || !password_response || !otp_response) {
      pam_syslog(pamh, LOG_ERR, "Failed to get password/TOTP: PAM conversation unavailable");
      if (password_response) SECURE_FREE_STRING(password_response);
      if (otp_response) SECURE_FREE_STRING(otp_response);
      return PAM_AUTHINFO_UNAVAIL;
    }
    password_to_use = password_response;
  } else {
    /* Password provided, only prompt for TOTP */
    DEBUG_LOG(config, "Password provided, prompting for TOTP only");
    retval = converse(pamh, PAM_PROMPT_ECHO_OFF, config->challenge_prompt, &otp_response);

    if (retval != PAM_SUCCESS || !otp_response) {
      pam_syslog(pamh, LOG_ERR, "Failed to get TOTP: PAM conversation unavailable");
      return PAM_AUTHINFO_UNAVAIL;
    }
  }

  /* Connect to LDAP */
  ld = pam_ldap_connect(pamh, config);
  if (!ld) {
    INFO_LOG("LDAP connection failed for user '%s'", username);
    pam_syslog(pamh, LOG_ERR, "Failed to connect to LDAP");
    if (password_response) {
      SECURE_FREE_STRING(password_response);
    }
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* Validate password via LDAP bind */
  DEBUG_LOG(config, "Validating password via LDAP bind");
  retval = ldap_validate_password(pamh, ld, username, password_to_use, config);

  if (retval != PAM_SUCCESS) {
    INFO_LOG("Password authentication failed for user '%s'", username);
    if (password_response) {
      SECURE_FREE_STRING(password_response);
    }
    pam_ldap_disconnect(ld);
    return PAM_AUTH_ERR;
  }

  INFO_LOG("Password authentication successful for user '%s'", username);

  /* Check if TOTP is required for this user */
  if (!config->totp_enabled) {
    DEBUG_LOG(config, "TOTP disabled - skipping OTP validation");
    if (password_response) {
      SECURE_FREE_STRING(password_response);
    }
    pam_ldap_disconnect(ld);
    return PAM_SUCCESS;
  }

  /* Get TOTP secret from LDAP */
  DEBUG_LOG(config, "Fetching TOTP secret for user: %s", username);
  secret = ldap_get_totp_secret(pamh, ld, username, config);

  if (!secret) {
    retval = handle_missing_secret(pamh, ld, username, config);
    if (otp_response) SECURE_FREE_STRING(otp_response);
    if (password_response) SECURE_FREE_STRING(password_response);
    pam_ldap_disconnect(ld);
    return retval;
  }

  /* TOTP response already collected above via converse_multi() or converse() */
  /* Validate TOTP code */
  DEBUG_LOG(config, "Validating TOTP code");

  if (validate_totp_code(pamh, secret, otp_response, config)) {
    INFO_LOG("TOTP authentication successful for user '%s'", username);
    retval = PAM_SUCCESS;
  } else {
    /* Try scratch code */
    DEBUG_LOG(config, "TOTP failed, trying scratch code");
    if (ldap_check_scratch_code(pamh, ld, username, otp_response, config)) {
      INFO_LOG("Scratch code authentication successful for user '%s'", username);
      retval = PAM_SUCCESS;
    } else {
      INFO_LOG("TOTP and scratch code authentication failed for user '%s'", username);
      pam_syslog(pamh, LOG_NOTICE, "Invalid TOTP code for user '%s'", username);
      retval = PAM_AUTH_ERR;
    }
  }

  /* Cleanup */
  SECURE_FREE_STRING(secret);
  if (otp_response) {
    memset(otp_response, 0, strlen(otp_response));
    free(otp_response);
  }
  if (password_response) {
    SECURE_FREE_STRING(password_response);
  }
  pam_ldap_disconnect(ld);

  return retval;
}

/*
 * Unified authentication function (Append Mode)
 *
 * When totp_enabled=true:
 *   - User enters: password123456 (password + 6-digit OTP)
 *   - Validates both password (via LDAP bind) and OTP (via TOTP)
 *   - Both must succeed
 *
 * When totp_enabled=false:
 *   - User enters: password (no OTP)
 *   - Validates only password (via LDAP bind)
 *   - OTP validation skipped
 *
 * OWASP Security:
 *   - No password logging
 *   - Secure memory cleanup
 *   - Input validation
 *   - Timing-attack resistant
 *
 * Returns: PAM_SUCCESS or PAM_AUTH_ERR
 */
static int authenticate_unified(pam_handle_t *pamh,
                                const char *username,
                                const char *input,
                                pam_config_t *config) {
  char *password = NULL;
  char *otp = NULL;
  int retval = PAM_AUTH_ERR;
  LDAP *ld = NULL;
  char *secret = NULL;
  char *input_copy = NULL;

  INFO_LOG("Authenticating user '%s' (TOTP %s)", username,
           config->totp_enabled ? "enabled" : "disabled");

  /* Save copy of input */
  input_copy = strdup(input);
  if (!input_copy) {
    pam_syslog(pamh, LOG_ERR, "Memory allocation failed");
    return PAM_AUTH_ERR;
  }

  /* Connect to LDAP */
  ld = pam_ldap_connect(pamh, config);
  if (!ld) {
    INFO_LOG("LDAP connection failed for user '%s'", username);
    pam_syslog(pamh, LOG_ERR, "Failed to connect to LDAP");
    SECURE_FREE_STRING(input_copy);
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* Branch based on TOTP enabled/disabled */
  if (config->totp_enabled) {
    /*
     * TOTP ENABLED: Try to extract OTP from input
     * If extraction fails, input may be plain password (grace period user)
     */
    DEBUG_LOG(config, "TOTP enabled - attempting OTP extraction from input");

    /* Always extract 6 digits first (TOTP) */
    int otp_extracted = extract_otp_from_password(input_copy, &password, &otp, 6, config);
    int using_8_digit_code = 0;  /* Track if we switched to 8-digit extraction */

    if (!otp_extracted) {
      /* OTP extraction failed - could be plain password for grace period user */
      DEBUG_LOG(config, "OTP extraction failed - treating input as plain password");
      password = strdup(input);
      otp = NULL;

      if (!password) {
        pam_syslog(pamh, LOG_ERR, "Memory allocation failed");
        SECURE_FREE_STRING(input_copy);
        pam_ldap_disconnect(ld);
        return PAM_AUTH_ERR;
      }
    }

    /* Validate password via LDAP bind */
    DEBUG_LOG(config, "Validating password via LDAP bind (with 6-digit OTP extraction)");
    retval = ldap_validate_password(pamh, ld, username, password, config);

    if (retval != PAM_SUCCESS) {
      /* Password validation failed with 6-digit extraction */
      /* Check if we can try 8-digit extraction for scratch code */
      DEBUG_LOG(config, "Password validation failed with 6-digit extraction");

      if (has_trailing_digits(input_copy, 8)) {
        DEBUG_LOG(config, "Input has 8+ trailing digits, trying 8-digit extraction");

        /* Free the 6-digit extraction results */
        SECURE_FREE_STRING(password);
        SECURE_FREE_STRING(otp);

        /* Re-extract with 8 digits */
        if (!extract_otp_from_password(input_copy, &password, &otp, 8, config)) {
          DEBUG_LOG(config, "Failed to re-extract with 8 digits");
          SECURE_FREE_STRING(input_copy);
          pam_ldap_disconnect(ld);
          return PAM_AUTH_ERR;
        }

        /* Try password validation again with 8-digit extraction */
        DEBUG_LOG(config, "Validating password via LDAP bind (with 8-digit scratch code extraction)");
        retval = ldap_validate_password(pamh, ld, username, password, config);

        if (retval != PAM_SUCCESS) {
          INFO_LOG("Password authentication failed for user '%s' (tried both 6 and 8 digit extraction)", username);
          SECURE_FREE_STRING(password);
          SECURE_FREE_STRING(otp);
          SECURE_FREE_STRING(input_copy);
          pam_ldap_disconnect(ld);
          return PAM_AUTH_ERR;
        }

        INFO_LOG("Password authentication successful for user '%s' (8-digit extraction)", username);
        /* Continue with scratch code validation below - OTP now contains 8 digits */
        using_8_digit_code = 1;
      } else {
        /* No 8 digits available */
        INFO_LOG("Password authentication failed for user '%s'", username);
        SECURE_FREE_STRING(password);
        SECURE_FREE_STRING(otp);
        SECURE_FREE_STRING(input_copy);
        pam_ldap_disconnect(ld);
        return PAM_AUTH_ERR;
      }
    } else {
      INFO_LOG("Password authentication successful for user '%s' (6-digit extraction)", username);
    }

    /* Get TOTP secret from LDAP */
    DEBUG_LOG(config, "Fetching TOTP secret for user: %s", username);
    secret = ldap_get_totp_secret(pamh, ld, username, config);

    if (!secret) {
      retval = handle_missing_secret(pamh, ld, username, config);
      SECURE_FREE_STRING(password);
      SECURE_FREE_STRING(otp);
      SECURE_FREE_STRING(input_copy);
      pam_ldap_disconnect(ld);
      return retval;
    }

    /* User has TOTP secret - OTP code is required */
    if (!otp) {
      /* Secret exists but no OTP was provided in input */
      INFO_LOG("TOTP required but no OTP provided for user '%s'", username);
      pam_syslog(pamh, LOG_NOTICE, "Missing TOTP code for user '%s'", username);
      SECURE_FREE_STRING(secret);
      SECURE_FREE_STRING(password);
      SECURE_FREE_STRING(input_copy);
      pam_ldap_disconnect(ld);
      return PAM_AUTH_ERR;
    }

    /* Validate TOTP or scratch code based on what was extracted */
    if (using_8_digit_code) {
      /* We already extracted 8 digits due to password validation failure */
      /* Skip TOTP validation and go straight to scratch code */
      DEBUG_LOG(config, "Using 8-digit code - validating as scratch code");

      if (ldap_check_scratch_code(pamh, ld, username, otp, config)) {
        INFO_LOG("Scratch code authentication successful for user '%s'", username);
        retval = PAM_SUCCESS;
      } else {
        INFO_LOG("Scratch code validation failed for user '%s'", username);
        pam_syslog(pamh, LOG_NOTICE, "Invalid scratch code for user '%s'", username);
        retval = PAM_AUTH_ERR;
      }
    } else if (validate_totp_code(pamh, secret, otp, config)) {
      /* 6-digit TOTP validation successful */
      INFO_LOG("TOTP authentication successful for user '%s'", username);
      retval = PAM_SUCCESS;
    } else {
      /* TOTP failed - check if input has 8+ digits for scratch code */
      DEBUG_LOG(config, "TOTP validation failed (6 digits)");

      if (has_trailing_digits(input_copy, 8)) {
        /* Re-extract with 8 digits for scratch code */
        DEBUG_LOG(config, "Input has 8+ trailing digits, re-extracting for scratch code");

        char *password_8 = NULL;
        char *otp_8 = NULL;

        if (extract_otp_from_password(input_copy, &password_8, &otp_8, 8, config)) {
          /* Validate password with 8-digit extraction */
          DEBUG_LOG(config, "Validating password with 8-digit OTP extraction");
          int pwd_result = ldap_validate_password(pamh, ld, username, password_8, config);

          if (pwd_result == PAM_SUCCESS) {
            /* Password valid, try scratch code */
            DEBUG_LOG(config, "Password valid, checking 8-digit scratch code");
            if (ldap_check_scratch_code(pamh, ld, username, otp_8, config)) {
              INFO_LOG("Scratch code authentication successful for user '%s'", username);
              retval = PAM_SUCCESS;
            } else {
              INFO_LOG("Scratch code validation failed for user '%s'", username);
              retval = PAM_AUTH_ERR;
            }
          } else {
            DEBUG_LOG(config, "Password validation failed with 8-digit extraction");
            retval = PAM_AUTH_ERR;
          }

          SECURE_FREE_STRING(password_8);
          SECURE_FREE_STRING(otp_8);
        } else {
          DEBUG_LOG(config, "Failed to re-extract with 8 digits");
          retval = PAM_AUTH_ERR;
        }
      } else {
        /* No 8 digits available - authentication failed */
        INFO_LOG("TOTP validation failed and no scratch code available for user '%s'", username);
        pam_syslog(pamh, LOG_NOTICE, "Invalid TOTP code for user '%s'", username);
        retval = PAM_AUTH_ERR;
      }
    }

    SECURE_FREE_STRING(secret);
    SECURE_FREE_STRING(password);
    SECURE_FREE_STRING(otp);

  } else {
    /*
     * TOTP DISABLED: Only validate password
     */
    DEBUG_LOG(config, "TOTP disabled - validating password only");

    /* input contains only password (no OTP) */
    retval = ldap_validate_password(pamh, ld, username, input, config);

    if (retval == PAM_SUCCESS) {
      INFO_LOG("Password authentication successful for user '%s'", username);
    } else {
      INFO_LOG("Password authentication failed for user '%s'", username);
    }
  }

  /* Cleanup */
  SECURE_FREE_STRING(input_copy);
  pam_ldap_disconnect(ld);

  return retval;
}

/*
 * Main PAM authentication entry point
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  const char *username;
  const char *password = NULL;
  int retval;
  pam_config_t config;

  /* Get username */
  retval = pam_get_user(pamh, &username, NULL);
  if (retval != PAM_SUCCESS || !username) {
    pam_syslog(pamh, LOG_ERR, "Failed to get username");
    return PAM_USER_UNKNOWN;
  }

  /* OWASP: Validate username */
  if (!is_safe_username(username)) {
    pam_syslog(pamh, LOG_ERR, "Invalid username format");
    return PAM_USER_UNKNOWN;
  }

  INFO_LOG("PAM LDAP TOTP v%s loaded for user '%s'", PAM_LDAP_TOTP_VERSION, username);

  /* Parse configuration first to determine authentication mode */
  if (parse_config(PAM_CONFIG_FILE, &config) != 0) {
    pam_syslog(pamh, LOG_ERR, "Failed to parse config file: %s", PAM_CONFIG_FILE);
    return PAM_AUTHINFO_UNAVAIL;
  }

  if (config.debug) {
    syslog(LOG_DEBUG, "Config loaded: TOTP %s, Mode %s, LDAP %s",
           config.totp_enabled ? "enabled" : "disabled",
           config.totp_mode == TOTP_MODE_CHALLENGE ? "challenge" : "append",
           config.ldap_uri ? config.ldap_uri : "(not set)");
  }

  /* Get password only in append mode - challenge mode prompts separately */
  if (config.totp_mode == TOTP_MODE_APPEND) {
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (retval != PAM_SUCCESS || !password) {
      pam_syslog(pamh, LOG_ERR, "Failed to get password");
      free_config(&config);
      return PAM_AUTH_ERR;
    }
  }

  /* Authenticate based on mode */
  if (config.totp_mode == TOTP_MODE_CHALLENGE) {
    DEBUG_LOG(&config, "Using challenge-response mode");
    /* In challenge mode, password is NULL - function will prompt */
    retval = authenticate_challenge_response(pamh, username, NULL, &config);
  } else {
    DEBUG_LOG(&config, "Using append mode");
    retval = authenticate_unified(pamh, username, password, &config);
  }

  /* OWASP: Secure cleanup */
  free_config(&config);

  return retval;
}

/* PAM credential management (required) */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
  return PAM_SUCCESS;
}

/* PAM account management (required) */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
  return PAM_SUCCESS;
}
