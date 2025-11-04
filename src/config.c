/*
 * config.c
 *
 * Standalone configuration parsing for PAM LDAP TOTP module
 * Single unified config file with friendly keywords
 */

#include "pam_ldap_totp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>

/* Trim leading/trailing whitespace */
static char *trim_whitespace(char *str) {
  char *end;

  /* Trim leading space */
  while (isspace((unsigned char)*str)) str++;

  if (*str == 0) /* All spaces */
    return str;

  /* Trim trailing space */
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) end--;

  /* Write new null terminator */
  end[1] = '\0';

  return str;
}

/* Parse TLS mode string to internal representation */
static int parse_tls_mode(const char *mode_str) {
  if (!mode_str || strcmp(mode_str, "none") == 0) {
    return 0; /* No TLS */
  } else if (strcmp(mode_str, "starttls") == 0) {
    return 1; /* StartTLS */
  } else if (strcmp(mode_str, "ldaps") == 0) {
    return 2; /* LDAPS */
  }
  return 1; /* Default: StartTLS */
}

/* Parse boolean value (true/false, 1/0, yes/no) */
static int parse_boolean(const char *value) {
  if (!value) return 0;

  if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
      strcmp(value, "yes") == 0 || strcmp(value, "on") == 0) {
    return 1;
  }
  return 0;
}

/* Parse TOTP mode string to internal representation */
static totp_mode_e parse_totp_mode(const char *mode_str) {
  if (!mode_str) {
    return TOTP_MODE_CHALLENGE; /* Default */
  }

  if (strcmp(mode_str, "challenge") == 0 || strcmp(mode_str, "challenge_response") == 0) {
    return TOTP_MODE_CHALLENGE;
  } else if (strcmp(mode_str, "append") == 0) {
    return TOTP_MODE_APPEND;
  }

  syslog(LOG_WARNING, "Unknown totp_mode value '%s', using default (challenge)", mode_str);
  return TOTP_MODE_CHALLENGE; /* Default on invalid value */
}

/* Initialize config with secure defaults following OWASP guidelines */
static void init_config_defaults(pam_config_t *config) {
  memset(config, 0, sizeof(pam_config_t));

  /* LDAP defaults */
  config->ldap_uri = NULL;           /* Must be configured */
  config->ldap_base = NULL;          /* Must be configured */
  config->ldap_bind_dn = NULL;       /* Optional - anonymous bind */
  config->ldap_bind_password = NULL; /* Optional */
  config->login_attribute = strdup("uid");
  config->tls_mode = strdup("starttls"); /* Secure by default */
  config->tls_verify_cert = 1;       /* Verify certificates by default */
  config->tls_ca_cert_file = strdup("/etc/ssl/certs/ca-certificates.crt");

  /* TOTP defaults */
  config->totp_enabled = 1;          /* TOTP enabled by default */
  config->totp_mode = TOTP_MODE_CHALLENGE; /* Challenge-response by default */
  config->challenge_prompt = strdup("TOTP code:");
  config->totp_attribute = strdup("totpSecret");
  config->scratch_attribute = strdup("totpScratchCode");
  config->status_attribute = strdup("totpStatus");
  config->enrolled_date_attribute = strdup("totpEnrolledDate");
  config->totp_prefix = strdup("");
  config->scratch_prefix = strdup("TOTP-SCRATCH:");
  config->time_step = 30;
  config->window_size = 3;

  /* MFA enforcement defaults */
  config->grace_period_days = 7;
  config->enforcement_mode = strdup("graceful");
  config->require_unique_match = 0;  /* Match pam_ldap behaviour */

  /* Debug */
  config->debug = 0;
}

/* Parse single configuration line - OWASP: Input validation */
static void parse_config_line(char *line, pam_config_t *config) {
  char *key, *value;
  char *trimmed = trim_whitespace(line);

  /* Skip empty lines and comments */
  if (*trimmed == '\0' || *trimmed == '#') {
    return;
  }

  /* Split on first whitespace */
  key = trimmed;
  value = key;
  while (*value && !isspace((unsigned char)*value)) value++;

  if (*value) {
    *value = '\0';
    value++;
    value = trim_whitespace(value);
  }

  /* Empty value = empty string (not NULL) */
  if (*value == '\0') {
    value = "";
  }

  /* OWASP: Validate key is alphanumeric + underscore only */
  for (const char *p = key; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '_') {
      syslog(LOG_WARNING, "Invalid config key (non-alphanumeric): %s", key);
      return;
    }
  }

  /* Parse LDAP settings */
  if (strcmp(key, "ldap_uri") == 0) {
    if (config->ldap_uri) free(config->ldap_uri);
    config->ldap_uri = strdup(value);
  }
  else if (strcmp(key, "ldap_base") == 0) {
    if (config->ldap_base) free(config->ldap_base);
    config->ldap_base = strdup(value);
  }
  else if (strcmp(key, "ldap_bind_dn") == 0) {
    if (config->ldap_bind_dn) free(config->ldap_bind_dn);
    config->ldap_bind_dn = strdup(value);
  }
  else if (strcmp(key, "ldap_bind_password") == 0) {
    if (config->ldap_bind_password) free(config->ldap_bind_password);
    config->ldap_bind_password = strdup(value);
  }
  else if (strcmp(key, "login_attribute") == 0) {
    if (config->login_attribute) free(config->login_attribute);
    config->login_attribute = strdup(value);
  }
  else if (strcmp(key, "tls_mode") == 0) {
    if (config->tls_mode) free(config->tls_mode);
    config->tls_mode = strdup(value);
  }
  else if (strcmp(key, "tls_verify_cert") == 0) {
    config->tls_verify_cert = parse_boolean(value);
  }
  else if (strcmp(key, "tls_ca_cert_file") == 0) {
    if (config->tls_ca_cert_file) free(config->tls_ca_cert_file);
    config->tls_ca_cert_file = strdup(value);
  }

  /* Parse TOTP settings */
  else if (strcmp(key, "totp_enabled") == 0) {
    config->totp_enabled = parse_boolean(value);
  }
  else if (strcmp(key, "totp_mode") == 0) {
    config->totp_mode = parse_totp_mode(value);
  }
  else if (strcmp(key, "challenge_prompt") == 0) {
    if (config->challenge_prompt) free(config->challenge_prompt);
    config->challenge_prompt = strdup(value);
  }
  else if (strcmp(key, "totp_attribute") == 0) {
    if (config->totp_attribute) free(config->totp_attribute);
    config->totp_attribute = strdup(value);
  }
  else if (strcmp(key, "scratch_attribute") == 0) {
    if (config->scratch_attribute) free(config->scratch_attribute);
    config->scratch_attribute = strdup(value);
  }
  else if (strcmp(key, "status_attribute") == 0) {
    if (config->status_attribute) free(config->status_attribute);
    config->status_attribute = strdup(value);
  }
  else if (strcmp(key, "enrolled_date_attribute") == 0) {
    if (config->enrolled_date_attribute) free(config->enrolled_date_attribute);
    config->enrolled_date_attribute = strdup(value);
  }
  else if (strcmp(key, "totp_prefix") == 0) {
    if (config->totp_prefix) free(config->totp_prefix);
    config->totp_prefix = strdup(value);
  }
  else if (strcmp(key, "scratch_prefix") == 0) {
    if (config->scratch_prefix) free(config->scratch_prefix);
    config->scratch_prefix = strdup(value);
  }
  else if (strcmp(key, "time_step") == 0) {
    config->time_step = atoi(value);
  }
  else if (strcmp(key, "window_size") == 0) {
    config->window_size = atoi(value);
  }

  /* Parse MFA enforcement settings */
  else if (strcmp(key, "grace_period_days") == 0) {
    config->grace_period_days = atoi(value);
  }
  else if (strcmp(key, "enforcement_mode") == 0) {
    if (config->enforcement_mode) free(config->enforcement_mode);
    config->enforcement_mode = strdup(value);
  }
  else if (strcmp(key, "require_unique_match") == 0) {
    config->require_unique_match = parse_boolean(value);
  }

  /* Parse debug settings */
  else if (strcmp(key, "debug") == 0) {
    config->debug = parse_boolean(value);
  }
  else {
    syslog(LOG_WARNING, "Unknown config keyword: %s", key);
  }
}

/* Parse configuration file */
int parse_config(const char *config_file, pam_config_t *config) {
  FILE *fp;
  char line[1024]; /* OWASP: Fixed buffer size with bounds checking */

  if (!config_file || !config) {
    return -1;
  }

  /* Initialize with defaults */
  init_config_defaults(config);

  /* Open config file */
  fp = fopen(config_file, "r");
  if (!fp) {
    syslog(LOG_ERR, "Failed to open config file: %s", config_file);
    return -1;
  }

  syslog(LOG_DEBUG, "Parsing config file: %s", config_file);

  /* Parse each line */
  while (fgets(line, sizeof(line), fp)) {
    /* OWASP: Check for buffer overflow */
    if (strlen(line) >= sizeof(line) - 1 && line[sizeof(line) - 2] != '\n') {
      syslog(LOG_WARNING, "Config line too long, skipping");
      /* Skip rest of long line */
      int c;
      while ((c = fgetc(fp)) != '\n' && c != EOF);
      continue;
    }

    parse_config_line(line, config);
  }

  fclose(fp);

  /* Validate required settings */
  if (!config->ldap_uri || !config->ldap_base) {
    syslog(LOG_ERR, "Required LDAP settings missing (ldap_uri and ldap_base required)");
    free_config(config);
    return -1;
  }

  syslog(LOG_DEBUG, "Config parsed successfully");
  return 0;
}

/* Free configuration structure - OWASP: Secure cleanup of sensitive data */
void free_config(pam_config_t *config) {
  if (!config) return;

  /* Free LDAP settings */
  if (config->ldap_uri) free(config->ldap_uri);
  if (config->ldap_base) free(config->ldap_base);
  if (config->ldap_bind_dn) free(config->ldap_bind_dn);

  /* OWASP: Securely clear password before freeing */
  if (config->ldap_bind_password) {
    memset(config->ldap_bind_password, 0, strlen(config->ldap_bind_password));
    free(config->ldap_bind_password);
  }

  if (config->login_attribute) free(config->login_attribute);
  if (config->tls_mode) free(config->tls_mode);
  if (config->tls_ca_cert_file) free(config->tls_ca_cert_file);

  /* Free TOTP settings */
  if (config->totp_attribute) free(config->totp_attribute);
  if (config->scratch_attribute) free(config->scratch_attribute);
  if (config->status_attribute) free(config->status_attribute);
  if (config->enrolled_date_attribute) free(config->enrolled_date_attribute);
  if (config->totp_prefix) free(config->totp_prefix);
  if (config->scratch_prefix) free(config->scratch_prefix);

  /* Free MFA enforcement settings */
  if (config->enforcement_mode) free(config->enforcement_mode);
  if (config->setup_service_dn) free(config->setup_service_dn);

  /* Free challenge-response settings */
  if (config->challenge_prompt) free(config->challenge_prompt);

  /* Zero out the entire struct for security */
  memset(config, 0, sizeof(pam_config_t));
}

/* Legacy compatibility wrapper */
int parse_totp_config(const char *config_file, totp_config_t *config) {
  return parse_config(config_file, config);
}

/* Legacy compatibility wrapper */
void free_totp_config(totp_config_t *config) {
  free_config(config);
}
