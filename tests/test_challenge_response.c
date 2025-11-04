/*
 * test_challenge_response.c
 *
 * Unit tests for challenge-response mode configuration and parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../include/pam_ldap_totp.h"

/* Test parsing totp_mode = challenge */
void test_parse_totp_mode_challenge(void) {
  pam_config_t config;
  FILE *fp;
  const char *test_config = "/tmp/pam_ldap_totp_test_challenge_mode.conf";

  /* Create test config file */
  fp = fopen(test_config, "w");
  assert(fp != NULL);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fprintf(fp, "totp_mode challenge\n");
  fclose(fp);

  /* Parse config */
  int result = parse_config(test_config, &config);
  assert(result == 0);
  assert(config.totp_mode == TOTP_MODE_CHALLENGE);

  /* Cleanup */
  free_config(&config);
  unlink(test_config);

  printf("✓ test_parse_totp_mode_challenge passed\n");
}

/* Test parsing totp_mode = append */
void test_parse_totp_mode_append(void) {
  pam_config_t config;
  FILE *fp;
  const char *test_config = "/tmp/pam_ldap_totp_test_append_mode.conf";

  /* Create test config file */
  fp = fopen(test_config, "w");
  assert(fp != NULL);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fprintf(fp, "totp_mode append\n");
  fclose(fp);

  /* Parse config */
  int result = parse_config(test_config, &config);
  assert(result == 0);
  assert(config.totp_mode == TOTP_MODE_APPEND);

  /* Cleanup */
  free_config(&config);
  unlink(test_config);

  printf("✓ test_parse_totp_mode_append passed\n");
}

/* Test parsing challenge_response alias */
void test_parse_totp_mode_challenge_response_alias(void) {
  pam_config_t config;
  FILE *fp;
  const char *test_config = "/tmp/pam_ldap_totp_test_cr_alias.conf";

  /* Create test config file */
  fp = fopen(test_config, "w");
  assert(fp != NULL);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fprintf(fp, "totp_mode challenge_response\n");
  fclose(fp);

  /* Parse config */
  int result = parse_config(test_config, &config);
  assert(result == 0);
  assert(config.totp_mode == TOTP_MODE_CHALLENGE);

  /* Cleanup */
  free_config(&config);
  unlink(test_config);

  printf("✓ test_parse_totp_mode_challenge_response_alias passed\n");
}

/* Test default totp_mode when not specified */
void test_totp_mode_defaults_to_challenge(void) {
  pam_config_t config;
  FILE *fp;
  const char *test_config = "/tmp/pam_ldap_totp_test_default_mode.conf";

  /* Create test config file without totp_mode */
  fp = fopen(test_config, "w");
  assert(fp != NULL);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fclose(fp);

  /* Parse config */
  int result = parse_config(test_config, &config);
  assert(result == 0);
  assert(config.totp_mode == TOTP_MODE_CHALLENGE); /* Default */

  /* Cleanup */
  free_config(&config);
  unlink(test_config);

  printf("✓ test_totp_mode_defaults_to_challenge passed\n");
}

/* Test parsing custom challenge_prompt */
void test_parse_challenge_prompt_custom(void) {
  pam_config_t config;
  FILE *fp;
  const char *test_config = "/tmp/pam_ldap_totp_test_custom_prompt.conf";

  /* Create test config file */
  fp = fopen(test_config, "w");
  assert(fp != NULL);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fprintf(fp, "challenge_prompt Enter MFA token:\n");
  fclose(fp);

  /* Parse config */
  int result = parse_config(test_config, &config);
  assert(result == 0);
  assert(config.challenge_prompt != NULL);
  assert(strcmp(config.challenge_prompt, "Enter MFA token:") == 0);

  /* Cleanup */
  free_config(&config);
  unlink(test_config);

  printf("✓ test_parse_challenge_prompt_custom passed\n");
}

/* Test default challenge_prompt */
void test_challenge_prompt_has_default(void) {
  pam_config_t config;
  FILE *fp;
  const char *test_config = "/tmp/pam_ldap_totp_test_default_prompt.conf";

  /* Create test config file without challenge_prompt */
  fp = fopen(test_config, "w");
  assert(fp != NULL);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fclose(fp);

  /* Parse config */
  int result = parse_config(test_config, &config);
  assert(result == 0);
  assert(config.challenge_prompt != NULL);
  assert(strcmp(config.challenge_prompt, "TOTP code:") == 0); /* Default */

  /* Cleanup */
  free_config(&config);
  unlink(test_config);

  printf("✓ test_challenge_prompt_has_default passed\n");
}

/* Test invalid totp_mode falls back to default (challenge) */
void test_invalid_totp_mode_uses_default(void) {
  pam_config_t config;
  FILE *fp;
  const char *test_config = "/tmp/pam_ldap_totp_test_invalid_mode.conf";

  /* Create test config file with invalid mode */
  fp = fopen(test_config, "w");
  assert(fp != NULL);
  fprintf(fp, "ldap_uri ldap://localhost\n");
  fprintf(fp, "ldap_base dc=example,dc=com\n");
  fprintf(fp, "totp_mode invalid_mode_name\n");
  fclose(fp);

  /* Parse config */
  int result = parse_config(test_config, &config);
  assert(result == 0);
  assert(config.totp_mode == TOTP_MODE_CHALLENGE); /* Falls back to default */

  /* Cleanup */
  free_config(&config);
  unlink(test_config);

  printf("✓ test_invalid_totp_mode_uses_default passed\n");
}

/* Test enum values are as expected */
void test_totp_mode_enum_values(void) {
  assert(TOTP_MODE_CHALLENGE == 0);
  assert(TOTP_MODE_APPEND == 1);

  printf("✓ test_totp_mode_enum_values passed\n");
}

int main(void) {
  printf("========================================\n");
  printf("Running Challenge-Response Mode Tests\n");
  printf("========================================\n\n");

  test_parse_totp_mode_challenge();
  test_parse_totp_mode_append();
  test_parse_totp_mode_challenge_response_alias();
  test_totp_mode_defaults_to_challenge();
  test_parse_challenge_prompt_custom();
  test_challenge_prompt_has_default();
  test_invalid_totp_mode_uses_default();
  test_totp_mode_enum_values();

  printf("\n========================================\n");
  printf("All challenge-response tests passed!\n");
  printf("========================================\n");

  return 0;
}
