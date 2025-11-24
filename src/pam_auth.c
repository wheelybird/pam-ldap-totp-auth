/*
 * pam_auth.c
 *
 * Unified LDAP + TOTP authentication
 * Single module that handles both password and TOTP validation
 */

#include "pam_ldap_totp.h"
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
 * Check if grace period has expired
 *
 * Parses LDAP GeneralizedTime format (YYYYMMDDHHmmssZ) and calculates
 * days elapsed since enrollment.
 *
 * Returns:
 *   1 if within grace period (allow access)
 *   0 if grace period expired (deny access)
 *  -1 on error (no date, invalid format)
 */
static int check_grace_period(const char *enrolled_date, int grace_days, pam_config_t *config) {
  if (!enrolled_date || strlen(enrolled_date) < 14) {
    DEBUG_LOG(config, "Grace period check: invalid or missing enrollment date");
    return -1;
  }

  /* Parse LDAP GeneralizedTime: YYYYMMDDHHmmssZ */
  struct tm enrolled_tm = {0};
  int year, month, day, hour, min, sec;

  if (sscanf(enrolled_date, "%4d%2d%2d%2d%2d%2d",
             &year, &month, &day, &hour, &min, &sec) != 6) {
    DEBUG_LOG(config, "Grace period check: failed to parse date format");
    return -1;
  }

  enrolled_tm.tm_year = year - 1900;
  enrolled_tm.tm_mon = month - 1;
  enrolled_tm.tm_mday = day;
  enrolled_tm.tm_hour = hour;
  enrolled_tm.tm_min = min;
  enrolled_tm.tm_sec = sec;
  enrolled_tm.tm_isdst = -1;

  time_t enrolled_time = mktime(&enrolled_tm);
  if (enrolled_time == -1) {
    DEBUG_LOG(config, "Grace period check: mktime failed");
    return -1;
  }

  time_t current_time = time(NULL);
  double seconds_elapsed = difftime(current_time, enrolled_time);
  int days_elapsed = (int)(seconds_elapsed / (60 * 60 * 24));

  DEBUG_LOG(config, "Grace period: %d days elapsed, %d days allowed",
            days_elapsed, grace_days);

  if (days_elapsed < grace_days) {
    INFO_LOG("Grace period active: %d of %d days used", days_elapsed, grace_days);
    return 1;  /* Within grace period */
  } else {
    INFO_LOG("Grace period expired: %d days elapsed (limit: %d)",
             days_elapsed, grace_days);
    return 0;  /* Grace period expired */
  }
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
    /* Check for grace period */
    char *status = ldap_get_attribute(pamh, ld, username, config->status_attribute, config);
    if (status && strcmp(status, "pending") == 0) {
      char *enrolled_date = ldap_get_attribute(pamh, ld, username,
                                                config->enrolled_date_attribute, config);
      if (enrolled_date) {
        int grace_status = check_grace_period(enrolled_date, config->grace_period_days, config);

        if (grace_status == 1) {
          /* Within grace period - calculate days remaining and show message */
          INFO_LOG("User '%s' in grace period - TOTP not required yet", username);

          /* Calculate days remaining for message */
          if (config->show_grace_message) {
            /* Get user-specific grace period from LDAP (if available) */
            int grace_period_days = config->grace_period_days; /* Default from config */
            char *user_grace_period = ldap_get_attribute(pamh, ld, username,
                                                         config->grace_period_attribute, config);
            if (user_grace_period && strlen(user_grace_period) > 0) {
              int ldap_grace_days = atoi(user_grace_period);
              if (ldap_grace_days > 0) {
                grace_period_days = ldap_grace_days;
                DEBUG_LOG(config, "Using LDAP grace period: %d days", grace_period_days);
              }
              free(user_grace_period);
            }

            struct tm enrolled_tm = {0};
            int year, month, day, hour, min, sec;

            if (sscanf(enrolled_date, "%4d%2d%2d%2d%2d%2d",
                       &year, &month, &day, &hour, &min, &sec) == 6) {
              enrolled_tm.tm_year = year - 1900;
              enrolled_tm.tm_mon = month - 1;
              enrolled_tm.tm_mday = day;
              enrolled_tm.tm_hour = hour;
              enrolled_tm.tm_min = min;
              enrolled_tm.tm_sec = sec;
              enrolled_tm.tm_isdst = -1;

              time_t enrolled_time = mktime(&enrolled_tm);
              if (enrolled_time != -1) {
                time_t current_time = time(NULL);
                double seconds_elapsed = difftime(current_time, enrolled_time);
                int days_elapsed = (int)(seconds_elapsed / (60 * 60 * 24));
                int days_remaining = grace_period_days - days_elapsed;

                /* Send informational message to user */
                if (days_remaining > 0 && config->grace_message) {
                  char message[512];
                  snprintf(message, sizeof(message),
                          "\n*** MFA ENROLLMENT REQUIRED ***\n"
                          "You have %d day%s remaining to set up multi-factor authentication.\n"
                          "%s\n",
                          days_remaining,
                          days_remaining == 1 ? "" : "s",
                          config->grace_message);

                  send_info_message(pamh, message);
                }
              }
            }
          }

          free(enrolled_date);
          free(status);

          if (password_response) {
            SECURE_FREE_STRING(password_response);
          }
          pam_ldap_disconnect(ld);
          return PAM_SUCCESS;
        } else if (grace_status == 0) {
          INFO_LOG("Grace period expired for user '%s'", username);
          free(enrolled_date);
          free(status);
          if (password_response) {
            SECURE_FREE_STRING(password_response);
          }
          pam_ldap_disconnect(ld);
          return PAM_AUTH_ERR;
        }
        free(enrolled_date);
      }
      free(status);
    } else if (status) {
      free(status);
    }

    INFO_LOG("TOTP secret not found for user '%s'", username);
    pam_syslog(pamh, LOG_NOTICE, "TOTP not configured for user '%s'", username);
    if (password_response) {
      SECURE_FREE_STRING(password_response);
    }
    pam_ldap_disconnect(ld);
    return PAM_AUTH_ERR;
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
      /* No TOTP secret configured - check grace period */
      INFO_LOG("No TOTP secret found for user '%s'", username);
      DEBUG_LOG(config, "Checking grace period status");

      /* Check if user is in grace period */
      char *totp_status = ldap_get_attribute(pamh, ld, username,
                                             config->status_attribute, config);

      if (totp_status && strcmp(totp_status, "pending") == 0) {
        /* User has pending status - check if grace period is still valid */
        char *enrolled_date = ldap_get_attribute(pamh, ld, username,
                                                 config->enrolled_date_attribute, config);

        int grace_result = check_grace_period(enrolled_date, config->grace_period_days, config);

        if (grace_result == 1) {
          /* Within grace period - allow access */
          INFO_LOG("User '%s' within grace period, allowing access", username);

          /* Calculate days remaining for message (append mode - message won't display but log it) */
          if (config->show_grace_message && enrolled_date) {
            /* Get user-specific grace period from LDAP (if available) */
            int grace_period_days = config->grace_period_days; /* Default from config */
            char *user_grace_period = ldap_get_attribute(pamh, ld, username,
                                                         config->grace_period_attribute, config);
            if (user_grace_period && strlen(user_grace_period) > 0) {
              int ldap_grace_days = atoi(user_grace_period);
              if (ldap_grace_days > 0) {
                grace_period_days = ldap_grace_days;
                DEBUG_LOG(config, "Using LDAP grace period: %d days", grace_period_days);
              }
              free(user_grace_period);
            }

            struct tm enrolled_tm = {0};
            int year, month, day, hour, min, sec;

            if (sscanf(enrolled_date, "%4d%2d%2d%2d%2d%2d",
                       &year, &month, &day, &hour, &min, &sec) == 6) {
              enrolled_tm.tm_year = year - 1900;
              enrolled_tm.tm_mon = month - 1;
              enrolled_tm.tm_mday = day;
              enrolled_tm.tm_hour = hour;
              enrolled_tm.tm_min = min;
              enrolled_tm.tm_sec = sec;
              enrolled_tm.tm_isdst = -1;

              time_t enrolled_time = mktime(&enrolled_tm);
              if (enrolled_time != -1) {
                time_t current_time = time(NULL);
                double seconds_elapsed = difftime(current_time, enrolled_time);
                int days_elapsed = (int)(seconds_elapsed / (60 * 60 * 24));
                int days_remaining = grace_period_days - days_elapsed;

                /* Send informational message (note: won't display in append mode like OpenVPN) */
                if (days_remaining > 0 && config->grace_message) {
                  char message[512];
                  snprintf(message, sizeof(message),
                          "\n*** MFA ENROLLMENT REQUIRED ***\n"
                          "You have %d day%s remaining to set up multi-factor authentication.\n"
                          "%s\n",
                          days_remaining,
                          days_remaining == 1 ? "" : "s",
                          config->grace_message);

                  send_info_message(pamh, message);
                }
              }
            }
          }

          if (enrolled_date) free(enrolled_date);
          if (totp_status) free(totp_status);
          SECURE_FREE_STRING(password);
          SECURE_FREE_STRING(otp);
          SECURE_FREE_STRING(input_copy);
          pam_ldap_disconnect(ld);
          return PAM_SUCCESS;
        } else if (grace_result == 0) {
          /* Grace period expired */
          INFO_LOG("Grace period expired for user '%s'", username);
          pam_syslog(pamh, LOG_NOTICE,
                     "Grace period expired - TOTP setup required for user '%s'", username);
          if (enrolled_date) free(enrolled_date);
          if (totp_status) free(totp_status);
          SECURE_FREE_STRING(password);
          SECURE_FREE_STRING(otp);
          SECURE_FREE_STRING(input_copy);
          pam_ldap_disconnect(ld);
          return PAM_AUTH_ERR;
        } else {
          /* Error checking grace period - allow access (fail open for usability) */
          DEBUG_LOG(config, "Grace period check error - allowing access");
          INFO_LOG("User '%s' in pending status (grace period check failed), allowing access",
                   username);
          if (enrolled_date) free(enrolled_date);
          if (totp_status) free(totp_status);
          SECURE_FREE_STRING(password);
          SECURE_FREE_STRING(otp);
          SECURE_FREE_STRING(input_copy);
          pam_ldap_disconnect(ld);
          return PAM_SUCCESS;
        }
      }

      if (totp_status) free(totp_status);

      /* No secret and not in grace period - check enforcement mode */
      if (config->enforcement_mode &&
          (strcmp(config->enforcement_mode, "graceful") == 0 ||
           strcmp(config->enforcement_mode, "warn_only") == 0)) {
        /* MFA is optional - allow password-only authentication */
        INFO_LOG("No TOTP configured for user '%s', allowing password-only auth (enforcement_mode=%s)",
                 username, config->enforcement_mode);
        if (strcmp(config->enforcement_mode, "warn_only") == 0) {
          pam_syslog(pamh, LOG_NOTICE,
                     "Warning: User '%s' authenticated without MFA (password-only)", username);
        }
        SECURE_FREE_STRING(password);
        SECURE_FREE_STRING(otp);
        SECURE_FREE_STRING(input_copy);
        pam_ldap_disconnect(ld);
        return PAM_SUCCESS;
      }

      /* Strict mode - TOTP required but not configured */
      pam_syslog(pamh, LOG_NOTICE, "TOTP required but not configured for user '%s'",
                 username);
      SECURE_FREE_STRING(password);
      SECURE_FREE_STRING(otp);
      SECURE_FREE_STRING(input_copy);
      pam_ldap_disconnect(ld);
      return PAM_AUTH_ERR;
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
