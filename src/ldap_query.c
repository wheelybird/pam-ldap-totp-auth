/*
 * ldap_query.c
 *
 * LDAP connection and query functions for retrieving TOTP secrets
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ldap.h>
#include "../include/pam_ldap_totp.h"

/* Connect to LDAP server */
LDAP *pam_ldap_connect(pam_handle_t *pamh, pam_config_t *config) {
  LDAP *ld = NULL;
  int rc;
  int version = LDAP_VERSION3;

  /* Initialize LDAP connection */
  rc = ldap_initialize(&ld, config->ldap_uri);
  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_initialize failed: %s", ldap_err2string(rc));
    return NULL;
  }

  DEBUG_LOG(config, "Connecting to LDAP: uri=%s base=%s binddn=%s",
            config->ldap_uri, config->ldap_base ? config->ldap_base : "(null)",
            config->ldap_bind_dn ? config->ldap_bind_dn : "(anonymous)");

  /* Set LDAP version */
  rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_set_option PROTOCOL_VERSION failed: %s",
                ldap_err2string(rc));
    ldap_unbind_ext_s(ld, NULL, NULL);
    return NULL;
  }

  /* Configure TLS options BEFORE initiating TLS handshake */
  if (config->tls_verify_cert == 0) {
    int reqcert = LDAP_OPT_X_TLS_NEVER;
    /* Set on both global and connection-specific handle for maximum compatibility */
    ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqcert);
    ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqcert);
    DEBUG_LOG(config, "TLS certificate validation disabled");
  }

  if (config->tls_ca_cert_file) {
    ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, config->tls_ca_cert_file);
    ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, config->tls_ca_cert_file);
    DEBUG_LOG(config, "TLS CA cert file: %s", config->tls_ca_cert_file);
  }

  /* Now initiate TLS if required */
  if (config->tls_mode && strcmp(config->tls_mode, "starttls") == 0) {
    /* StartTLS */
    DEBUG_LOG(config, "Initiating StartTLS...");
    rc = ldap_start_tls_s(ld, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "ldap_start_tls_s failed: %s", ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return NULL;
    }
    DEBUG_LOG(config, "StartTLS successful");
  }

  /* Bind to LDAP */
  if (config->ldap_bind_dn && config->ldap_bind_password) {
    struct berval cred;
    cred.bv_val = config->ldap_bind_password;
    cred.bv_len = strlen(config->ldap_bind_password);

    rc = ldap_sasl_bind_s(ld, config->ldap_bind_dn, LDAP_SASL_SIMPLE, &cred,
                           NULL, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "ldap_sasl_bind_s failed: %s", ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return NULL;
    }
  }
  else {
    /* Anonymous bind */
    rc = ldap_sasl_bind_s(ld, NULL, LDAP_SASL_SIMPLE, NULL, NULL, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "ldap_sasl_bind_s (anonymous) failed: %s",
                  ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return NULL;
    }
  }

  return ld;
}

/* Disconnect from LDAP */
void pam_ldap_disconnect(LDAP *ld) {
  if (ld) {
    ldap_unbind_ext_s(ld, NULL, NULL);
  }
}

/* Get TOTP secret from LDAP */
char *ldap_get_totp_secret(pam_handle_t *pamh, LDAP *ld, const char *username,
                            pam_config_t *config) {
  int rc;
  char filter[256];
  char *attrs[] = { config->totp_attribute, NULL };
  LDAPMessage *result = NULL;
  LDAPMessage *entry;
  struct berval **values;
  char *secret = NULL;
  size_t prefix_len = strlen(config->totp_prefix);
  char *escaped_username = NULL;

  /* Build search filter with LDAP injection protection */
  escaped_username = ldap_escape_filter(username);
  if (!escaped_username) {
    pam_syslog(pamh, LOG_ERR, "Failed to escape username for LDAP filter");
    return NULL;
  }

  const char *search_attr = config->login_attribute ? config->login_attribute : "uid";
  DEBUG_LOG(config, "Using login attribute: %s (login_attribute=%s)",
            search_attr, config->login_attribute ? config->login_attribute : "(null)");

  snprintf(filter, sizeof(filter), "(%s=%s)", search_attr, escaped_username);
  free(escaped_username);

  DEBUG_LOG(config, "LDAP search: base='%s' filter='%s' attr='%s'",
            config->ldap_base, filter, config->totp_attribute);

  /* Search for user */
  rc = ldap_search_ext_s(ld, config->ldap_base, LDAP_SCOPE_SUBTREE,
                          filter, attrs, 0, NULL, NULL, NULL,
                          LDAP_NO_LIMIT, &result);

  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_search_ext_s failed: %s", ldap_err2string(rc));
    return NULL;
  }

  int count = ldap_count_entries(ld, result);
  DEBUG_LOG(config, "LDAP search returned %d entries", count);

  /* Check for multiple matches if required */
  if (count > 1 && config->require_unique_match) {
    pam_syslog(pamh, LOG_WARNING, "Multiple LDAP entries (%d) matched for user '%s' - cannot authenticate. "
               "Administrator should configure LDAP filter to ensure unique match.", count, username);
    ldap_msgfree(result);
    return NULL;
  }

  if (count > 1) {
    DEBUG_LOG(config, "Multiple matches found, using first entry (require_unique_match=false)");
  }

  /* Get first entry */
  entry = ldap_first_entry(ld, result);
  if (!entry) {
    pam_syslog(pamh, LOG_NOTICE, "User %s not found in LDAP", username);
    ldap_msgfree(result);
    return NULL;
  }

  char *dn = ldap_get_dn(ld, entry);
  DEBUG_LOG(config, "Found user DN: %s", dn ? dn : "(null)");
  if (dn) ldap_memfree(dn);

  /* Get attribute values */
  DEBUG_LOG(config, "Requesting attribute '%s' with prefix '%s' (len=%zu)",
            config->totp_attribute, config->totp_prefix, prefix_len);
  values = ldap_get_values_len(ld, entry, config->totp_attribute);
  if (!values) {
    /* Check LDAP error - ldap_get_values_len doesn't set specific errors, just returns NULL */
    DEBUG_LOG(config, "ldap_get_values_len returned NULL for '%s' attribute (attribute not found or no values)",
              config->totp_attribute);

    /* List all attributes in entry for debugging */
    if (config->debug) {
      BerElement *ber = NULL;
      char *attr = ldap_first_attribute(ld, entry, &ber);
      DEBUG_LOG(config, "Available attributes in entry:");
      while (attr) {
        DEBUG_LOG(config, "  - %s", attr);
        ldap_memfree(attr);
        attr = ldap_next_attribute(ld, entry, ber);
      }
      if (ber) ber_free(ber, 0);
    }
    ldap_msgfree(result);
    return NULL;
  }

  DEBUG_LOG(config, "Found %d value(s) for %s attribute",
            ldap_count_values_len(values), config->totp_attribute);

  /* Find TOTP secret in values */
  for (int i = 0; values[i] != NULL; i++) {
    DEBUG_LOG(config, "Checking value %d: length=%lu prefix_len=%lu",
              i, (unsigned long)values[i]->bv_len, (unsigned long)prefix_len);

    if (strncmp(values[i]->bv_val, config->totp_prefix, prefix_len) == 0) {
      DEBUG_LOG(config, "Prefix match found");
      /* Found TOTP secret */
      char *secret_start = values[i]->bv_val + prefix_len;
      char *colon = strchr(secret_start, ':');

      if (colon) {
        /* Extract secret up to next colon */
        size_t secret_len = colon - secret_start;
        secret = strndup(secret_start, secret_len);
      }
      else {
        /* No options, use rest of string */
        secret = strdup(secret_start);
      }

      DEBUG_LOG(config, "Found TOTP secret for user %s", username);
      break;
    }
  }

  if (!secret) {
    DEBUG_LOG(config, "No matching TOTP secret found (prefix mismatch?)");
  } else {
    DEBUG_LOG(config, "Successfully extracted TOTP secret");
  }

  ldap_value_free_len(values);
  ldap_msgfree(result);

  return secret;
}

/* Check if scratch code exists in LDAP (for future use) */
int ldap_check_scratch_code(pam_handle_t *pamh, LDAP *ld, const char *username,
                              const char *code, pam_config_t *config) {
  int rc;
  char filter[256];
  char *attrs[] = { config->scratch_attribute, NULL };
  LDAPMessage *result = NULL;
  LDAPMessage *entry;
  struct berval **values;
  int found = 0;
  char *escaped_username = NULL;

  /* Build search filter with LDAP injection protection */
  escaped_username = ldap_escape_filter(username);
  if (!escaped_username) {
    pam_syslog(pamh, LOG_ERR, "Failed to escape username for LDAP filter");
    return 0;
  }

  const char *search_attr = config->login_attribute ? config->login_attribute : "uid";
  snprintf(filter, sizeof(filter), "(%s=%s)", search_attr, escaped_username);
  free(escaped_username);

  DEBUG_LOG(config, "Scratch code search filter: %s", filter);

  /* Search for user */
  rc = ldap_search_ext_s(ld, config->ldap_base, LDAP_SCOPE_SUBTREE,
                          filter, attrs, 0, NULL, NULL, NULL,
                          LDAP_NO_LIMIT, &result);

  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_search_ext_s failed: %s", ldap_err2string(rc));
    return 0;
  }

  /* Check for multiple matches if required */
  int count = ldap_count_entries(ld, result);
  if (count > 1 && config->require_unique_match) {
    pam_syslog(pamh, LOG_WARNING, "Multiple LDAP entries (%d) matched for user '%s' - cannot authenticate. "
               "Administrator should configure LDAP filter to ensure unique match.", count, username);
    ldap_msgfree(result);
    return 0;
  }

  if (count > 1) {
    DEBUG_LOG(config, "Multiple matches found, using first entry (require_unique_match=false)");
  }

  /* Get first entry */
  entry = ldap_first_entry(ld, result);
  if (!entry) {
    ldap_msgfree(result);
    return 0;
  }

  /* Get attribute values */
  values = ldap_get_values_len(ld, entry, config->scratch_attribute);
  if (!values) {
    DEBUG_LOG(config, "No scratch codes found for user %s", username);
    ldap_msgfree(result);
    return 0;
  }

  /* Look for matching scratch code using constant-time comparison */
  char *user_dn = NULL;
  size_t code_len = strlen(code);
  for (int i = 0; values[i] != NULL; i++) {
    /* Use constant-time comparison to prevent timing attacks */
    if (values[i]->bv_len == code_len &&
        constant_time_compare(values[i]->bv_val, code, code_len)) {
      found = 1;
      DEBUG_LOG(config, "Found matching scratch code for user %s", username);

      /* Get user DN for modification */
      user_dn = ldap_get_dn(ld, entry);
      break;
    }
  }

  ldap_value_free_len(values);
  ldap_msgfree(result);

  /* Remove the used scratch code from LDAP (single-use enforcement) */
  if (found && user_dn) {
    LDAPMod mod;
    LDAPMod *mods[2];
    struct berval bval;
    struct berval *bvals[2];

    /* Prepare the modification to delete this specific scratch code */
    bval.bv_val = (char *)code;
    bval.bv_len = strlen(code);
    bvals[0] = &bval;
    bvals[1] = NULL;

    mod.mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
    mod.mod_type = config->scratch_attribute;
    mod.mod_bvalues = bvals;

    mods[0] = &mod;
    mods[1] = NULL;

    rc = ldap_modify_ext_s(ld, user_dn, mods, NULL, NULL);
    if (rc == LDAP_SUCCESS) {
      DEBUG_LOG(config, "Successfully removed used scratch code for user %s", username);
      pam_syslog(pamh, LOG_NOTICE, "Removed used scratch code for user %s", username);
    } else {
      pam_syslog(pamh, LOG_WARNING, "Failed to remove scratch code for user %s: %s",
                 username, ldap_err2string(rc));
      /* Don't fail authentication if removal fails - code was still valid */
    }

    ldap_memfree(user_dn);
  }

  return found;
}

/* Generic function to retrieve any LDAP attribute for a user */
char *ldap_get_attribute(pam_handle_t *pamh, LDAP *ld, const char *username,
                          const char *attribute, pam_config_t *config) {
  int rc;
  char filter[256];
  char *attrs[] = { (char *)attribute, NULL };
  LDAPMessage *result = NULL;
  LDAPMessage *entry;
  struct berval **values;
  char *value = NULL;
  char *escaped_username = NULL;

  /* Build search filter with LDAP injection protection */
  escaped_username = ldap_escape_filter(username);
  if (!escaped_username) {
    pam_syslog(pamh, LOG_ERR, "Failed to escape username for LDAP filter");
    return NULL;
  }

  const char *search_attr = config->login_attribute ? config->login_attribute : "uid";
  snprintf(filter, sizeof(filter), "(%s=%s)", search_attr, escaped_username);
  free(escaped_username);

  /* Search for user */
  rc = ldap_search_ext_s(ld, config->ldap_base, LDAP_SCOPE_SUBTREE,
                          filter, attrs, 0, NULL, NULL, NULL,
                          LDAP_NO_LIMIT, &result);

  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_search_ext_s failed: %s", ldap_err2string(rc));
    return NULL;
  }

  /* Check for multiple matches if required */
  int count = ldap_count_entries(ld, result);
  if (count > 1 && config->require_unique_match) {
    pam_syslog(pamh, LOG_WARNING, "Multiple LDAP entries (%d) matched for user '%s' - cannot authenticate. "
               "Administrator should configure LDAP filter to ensure unique match.", count, username);
    ldap_msgfree(result);
    return NULL;
  }

  if (count > 1) {
    DEBUG_LOG(config, "Multiple matches found, using first entry (require_unique_match=false)");
  }

  /* Get first entry */
  entry = ldap_first_entry(ld, result);
  if (!entry) {
    ldap_msgfree(result);
    return NULL;
  }

  /* Get attribute values */
  values = ldap_get_values_len(ld, entry, attribute);
  if (!values) {
    ldap_msgfree(result);
    return NULL;
  }

  /* Get first value */
  if (values[0] != NULL) {
    value = strndup(values[0]->bv_val, values[0]->bv_len);
  }

  ldap_value_free_len(values);
  ldap_msgfree(result);

  return value;
}
