/*
 * totp_validate.c
 *
 * TOTP code validation using liboath
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <liboath/oath.h>
#include "../include/pam_ldap_totp.h"

/* Validate TOTP code against secret */
int validate_totp_code(pam_handle_t *pamh, const char *secret, const char *code,
                        totp_config_t *config) {
  int rc;
  time_t now;
  uint64_t time_step_value;
  char otp[7];
  int window;
  char *decoded_secret = NULL;
  size_t decoded_len = 0;

  if (!secret || !code) {
    return 0;
  }

  /* Ensure code is 6 digits */
  if (strlen(code) != 6) {
    if (config->debug) {
      pam_syslog(pamh, LOG_DEBUG, "OTP code must be 6 digits");
    }
    return 0;
  }

  /* Initialize OATH library */
  rc = oath_init();
  if (rc != OATH_OK) {
    pam_syslog(pamh, LOG_ERR, "oath_init failed: %s", oath_strerror(rc));
    return 0;
  }

  /* Decode Base32 secret */
  rc = oath_base32_decode(secret, strlen(secret), &decoded_secret, &decoded_len);
  if (rc != OATH_OK) {
    pam_syslog(pamh, LOG_ERR, "Base32 decode failed: %s", oath_strerror(rc));
    oath_done();
    return 0;
  }

  /* Get current time step */
  now = time(NULL);
  time_step_value = now / config->time_step;

  /* Try multiple time windows (handle clock drift) */
  for (window = -config->window_size; window <= config->window_size; window++) {
    uint64_t moving_factor = time_step_value + window;

    /* Generate OTP for this time window */
    rc = oath_totp_generate(decoded_secret, decoded_len,
                             moving_factor * config->time_step,
                             config->time_step, 0, /* SHA1 */
                             6, /* 6 digits */
                             otp);

    if (rc == OATH_OK) {
      /* Use constant-time comparison to prevent timing attacks */
      if (constant_time_compare(otp, code, 6)) {
        if (config->debug) {
          pam_syslog(pamh, LOG_DEBUG, "TOTP code validated successfully (window: %d)", window);
        }
        secure_free(decoded_secret, decoded_len);
        oath_done();
        return 1;
      }
    }
    else if (config->debug) {
      pam_syslog(pamh, LOG_DEBUG, "oath_totp_generate failed: %s", oath_strerror(rc));
    }
  }

  if (config->debug) {
    pam_syslog(pamh, LOG_DEBUG, "TOTP code validation failed");
  }

  secure_free(decoded_secret, decoded_len);
  oath_done();
  return 0;
}

/* Validate scratch/backup code (8 digits) */
int validate_scratch_code(const char *code) {
  /* Check if code is 8 digits */
  if (!code || strlen(code) != 8) {
    return 0;
  }

  /* Check all digits */
  for (int i = 0; i < 8; i++) {
    if (code[i] < '0' || code[i] > '9') {
      return 0;
    }
  }

  return 1; /* Format is valid, actual validation happens in ldap_query.c */
}
