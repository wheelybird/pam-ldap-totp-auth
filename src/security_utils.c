/*
 * security_utils.c
 *
 * Security utility functions for PAM LDAP TOTP module
 * Implements constant-time comparisons, input validation, and secure memory handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include "../include/pam_ldap_totp.h"

/*
 * Constant-time string comparison
 *
 * Prevents timing attacks by ensuring comparison takes the same time
 * regardless of where strings differ.
 *
 * Returns: 1 if strings match, 0 otherwise
 */
int constant_time_compare(const char *a, const char *b, size_t len) {
  volatile unsigned char result = 0;
  size_t i;

  if (!a || !b) {
    return 0;
  }

  /* Compare all bytes regardless of differences found */
  for (i = 0; i < len; i++) {
    result |= (unsigned char)a[i] ^ (unsigned char)b[i];
  }

  return result == 0;
}

/*
 * Secure memory clearing and deallocation
 *
 * Zeros memory before freeing to prevent secrets from remaining in memory
 * Uses volatile to prevent compiler optimization from removing memset
 */
void secure_free(void *ptr, size_t len) {
  if (ptr && len > 0) {
    /* Use volatile pointer to prevent compiler optimization */
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
      *p++ = 0;
    }
    free(ptr);
  }
}

/*
 * LDAP filter escaping (RFC 4515 Section 3)
 *
 * Escapes special characters in LDAP filter values to prevent injection:
 * - \ (backslash)
 * - * (asterisk)
 * - ( (left parenthesis)
 * - ) (right parenthesis)
 * - NUL (null character)
 *
 * Returns: Newly allocated escaped string, or NULL on error
 * Caller must free() the returned string
 */
char *ldap_escape_filter(const char *input) {
  size_t input_len;
  size_t output_len = 0;
  size_t i, j;
  char *escaped;

  if (!input) {
    return NULL;
  }

  input_len = strlen(input);

  /* Calculate required output length */
  for (i = 0; i < input_len; i++) {
    switch (input[i]) {
      case '\\':
      case '*':
      case '(':
      case ')':
      case '\0':
        output_len += 3;  /* \XX format */
        break;
      default:
        output_len += 1;
    }
  }

  /* Allocate output buffer */
  escaped = malloc(output_len + 1);
  if (!escaped) {
    return NULL;
  }

  /* Perform escaping */
  for (i = 0, j = 0; i < input_len; i++) {
    switch (input[i]) {
      case '\\':
        escaped[j++] = '\\';
        escaped[j++] = '5';
        escaped[j++] = 'c';
        break;
      case '*':
        escaped[j++] = '\\';
        escaped[j++] = '2';
        escaped[j++] = 'a';
        break;
      case '(':
        escaped[j++] = '\\';
        escaped[j++] = '2';
        escaped[j++] = '8';
        break;
      case ')':
        escaped[j++] = '\\';
        escaped[j++] = '2';
        escaped[j++] = '9';
        break;
      case '\0':
        escaped[j++] = '\\';
        escaped[j++] = '0';
        escaped[j++] = '0';
        break;
      default:
        escaped[j++] = input[i];
    }
  }

  escaped[j] = '\0';
  return escaped;
}

/*
 * Validate username for safe filesystem operations
 *
 * Ensures username contains only alphanumeric characters, underscore,
 * hyphen, and period. Prevents path traversal attacks.
 *
 * Returns: 1 if safe, 0 if unsafe
 */
int is_safe_username(const char *username) {
  size_t i;

  if (!username || username[0] == '\0') {
    return 0;
  }

  /* Check for path traversal patterns */
  if (strstr(username, "..") != NULL ||
      strstr(username, "/") != NULL ||
      strstr(username, "\\") != NULL) {
    return 0;
  }

  /* Validate each character */
  for (i = 0; username[i] != '\0'; i++) {
    char c = username[i];
    if (!((c >= 'a' && c <= 'z') ||
          (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') ||
          c == '_' || c == '-' || c == '.')) {
      return 0;
    }
  }

  /* Additional safety checks */
  if (i > 255) {  /* Username too long */
    return 0;
  }

  if (username[0] == '.' || username[0] == '-') {  /* Prevent hidden files or negative numbers */
    return 0;
  }

  return 1;
}

/*
 * Validate LDAP attribute name
 *
 * Ensures attribute name is reasonable length and contains safe characters
 *
 * Returns: 1 if valid, 0 if invalid
 */
int is_valid_ldap_attribute(const char *attr) {
  size_t len;
  size_t i;

  if (!attr || attr[0] == '\0') {
    return 0;
  }

  len = strlen(attr);

  /* LDAP attribute names should be reasonable length */
  if (len > 64) {
    return 0;
  }

  /* Check for valid LDAP attribute name characters */
  /* RFC 4512: attributetype = ALPHA *( ALPHA / DIGIT / HYPHEN ) */
  if (!isalpha((unsigned char)attr[0])) {
    return 0;
  }

  for (i = 1; i < len; i++) {
    char c = attr[i];
    if (!isalnum((unsigned char)c) && c != '-' && c != '_') {
      return 0;
    }
  }

  return 1;
}

/*
 * Validate date components are in valid ranges
 *
 * Returns: 1 if valid, 0 if invalid
 */
int is_valid_date(int year, int month, int day, int hour, int min, int sec) {
  /* Basic range checks */
  if (year < 1900 || year > 2100) return 0;
  if (month < 1 || month > 12) return 0;
  if (day < 1 || day > 31) return 0;
  if (hour < 0 || hour > 23) return 0;
  if (min < 0 || min > 59) return 0;
  if (sec < 0 || sec > 59) return 0;

  /* Month-specific day validation */
  if ((month == 4 || month == 6 || month == 9 || month == 11) && day > 30) {
    return 0;
  }

  /* February validation (simplified - doesn't check leap years perfectly) */
  if (month == 2) {
    int is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    if (day > (is_leap ? 29 : 28)) {
      return 0;
    }
  }

  return 1;
}

/*
 * Safe strdup with NULL check
 *
 * Returns: Duplicated string or NULL on failure
 */
char *safe_strdup(const char *s) {
  char *result;

  if (!s) {
    return NULL;
  }

  result = strdup(s);
  if (!result) {
    syslog(LOG_CRIT, "Memory allocation failed in safe_strdup");
  }

  return result;
}
