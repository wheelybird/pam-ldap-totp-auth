/*
 * pam_ldap_totp.h
 *
 * PAM module for LDAP-backed TOTP authentication
 * Retrieves TOTP secrets from LDAP and validates OTP codes
 */

#ifndef PAM_LDAP_TOTP_H
#define PAM_LDAP_TOTP_H

/* Version information */
#define PAM_LDAP_TOTP_VERSION "0.1.3"
#define PAM_LDAP_TOTP_VERSION_MAJOR 0
#define PAM_LDAP_TOTP_VERSION_MINOR 1
#define PAM_LDAP_TOTP_VERSION_PATCH 3

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <ldap.h>
#include <liboath/oath.h>

/* TOTP authentication mode */
typedef enum {
  TOTP_MODE_CHALLENGE = 0,     /* Challenge-response: separate prompts (default, SSH/sudo/login) */
  TOTP_MODE_APPEND = 1         /* Append mode: password+OTP concatenated (OpenVPN compatible) */
} totp_mode_e;

/* Unified configuration structure - Standalone module */
typedef struct {
  /* LDAP connection settings */
  char *ldap_uri;              /* LDAP server URI (e.g., ldap://server or ldaps://server:636) */
  char *ldap_base;             /* LDAP base DN for searches */
  char *ldap_bind_dn;          /* Service account DN for LDAP bind (optional) */
  char *ldap_bind_password;    /* Service account password (optional) */
  char *login_attribute;       /* LDAP attribute for user login (default: uid) */
  char *tls_mode;              /* TLS mode: none, starttls, ldaps (default: starttls) */
  int tls_verify_cert;         /* Verify TLS certificates (default: 1) */
  char *tls_ca_cert_file;      /* Path to CA certificate file */

  /* TOTP settings */
  int totp_enabled;            /* Enable TOTP validation (default: 1) */
  totp_mode_e totp_mode;       /* Authentication mode: challenge or append (default: challenge) */
  char *challenge_prompt;      /* Prompt message for TOTP code in challenge mode */
  char *totp_attribute;        /* LDAP attribute containing TOTP secret */
  char *scratch_attribute;     /* LDAP attribute for backup codes */
  char *status_attribute;      /* LDAP attribute for TOTP status */
  char *enrolled_date_attribute; /* LDAP attribute for enrollment date */
  char *totp_prefix;           /* Prefix for TOTP data in attribute */
  int time_step;               /* TOTP time step in seconds (default: 30) */
  int window_size;             /* Time window tolerance (default: 3) */

  /* MFA enforcement */
  int grace_period_days;       /* Grace period for MFA setup (default: 7) */
  char *enforcement_mode;      /* Enforcement: strict, graceful, warn_only */
  char *setup_service_dn;      /* Service DN allowed during setup */
  int require_unique_match;    /* Require unique LDAP match (default: 0) */

  /* MFA enrollment */
  char *grace_message;         /* Custom message shown during grace period */
  int show_grace_message;      /* Show grace period reminder (default: 1) */
  char *grace_period_attribute; /* LDAP attribute for user-specific grace period */

  /* Debug */
  int debug;                   /* Enable debug logging */
} pam_config_t;

/* DEPRECATED: Legacy structs kept for compatibility during migration */
typedef pam_config_t totp_config_t;
typedef pam_config_t ldap_config_t;

/* Function prototypes */

/* config.c - Configuration parsing */
int parse_config(const char *config_file, pam_config_t *config);
void free_config(pam_config_t *config);

/* DEPRECATED: Legacy functions for compatibility */
int parse_totp_config(const char *config_file, totp_config_t *config);
void free_totp_config(totp_config_t *config);

/* ldap_query.c - LDAP operations */
LDAP *pam_ldap_connect(pam_handle_t *pamh, pam_config_t *config);
int ldap_validate_password(pam_handle_t *pamh, LDAP *ld, const char *username,
                           const char *password, pam_config_t *config);
char *ldap_get_totp_secret(pam_handle_t *pamh, LDAP *ld, const char *username,
                            pam_config_t *config);
char *ldap_get_attribute(pam_handle_t *pamh, LDAP *ld, const char *username,
                          const char *attribute, pam_config_t *config);
int ldap_check_scratch_code(pam_handle_t *pamh, LDAP *ld, const char *username,
                              const char *code, pam_config_t *config);
void pam_ldap_disconnect(LDAP *ld);

/* DEPRECATED: Legacy functions */
LDAP *totp_ldap_connect(pam_handle_t *pamh, ldap_config_t *config, totp_config_t *totp_cfg);
void totp_ldap_disconnect(LDAP *ld);

/* totp_validate.c - TOTP validation */
int validate_totp_code(pam_handle_t *pamh, const char *secret, const char *code,
                        totp_config_t *config);
int validate_scratch_code(const char *code);

/* pam_ldap_totp.c - Main PAM module */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                                int argc, const char **argv);
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv);

/* Security utility functions */
int constant_time_compare(const char *a, const char *b, size_t len);
void secure_free(void *ptr, size_t len);
char *ldap_escape_filter(const char *input);
int is_safe_username(const char *username);
int is_valid_ldap_attribute(const char *attr);
int is_valid_date(int year, int month, int day, int hour, int min, int sec);
char *safe_strdup(const char *s);

/* Utility macros */
#define PAM_CONFIG_FILE "/etc/security/pam_ldap_totp_auth.conf"
#define TOTP_CONFIG_FILE "/etc/security/pam_ldap_totp.conf"  /* DEPRECATED */
#define FILE_BASED_OTP_DIR "/etc/openvpn/otp"

/* Info logging macro - always outputs to stderr for Docker logs visibility */
#define INFO_LOG(fmt, ...) \
  do { \
    fprintf(stderr, "[PAM_LDAP_TOTP] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
  } while(0)

/* Debug logging macro - outputs to stderr when debug enabled */
#define DEBUG_LOG(cfg, fmt, ...) \
  do { \
    if ((cfg)->debug) { \
      fprintf(stderr, "[PAM_LDAP_TOTP:DEBUG] " fmt "\n", ##__VA_ARGS__); \
      fflush(stderr); \
    } \
  } while(0)

/* Secure free macros for sensitive data */
#define SECURE_FREE_STRING(ptr) \
  do { \
    if (ptr) { \
      secure_free(ptr, strlen(ptr)); \
      ptr = NULL; \
    } \
  } while(0)

#endif /* PAM_LDAP_TOTP_H */
