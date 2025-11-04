# Makefile for PAM LDAP TOTP Unit Tests
# Uses Check framework for C unit testing

CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -I../include -I.
LIBS = -lpam -lldap -llber -loath

# Source files from parent directory
SRC_DIR = ../src

# Object directory
OBJDIR = obj

# Test executables
TESTS = test_config test_ldap_auth test_totp test_security test_challenge_response

.PHONY: all clean run check

all: $(TESTS)

# Object file rules
$(OBJDIR)/config.o: $(SRC_DIR)/config.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/ldap_auth.o: $(SRC_DIR)/ldap_auth.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/ldap_query.o: $(SRC_DIR)/ldap_query.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/totp_validate.o: $(SRC_DIR)/totp_validate.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/security_utils.o: $(SRC_DIR)/security_utils.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create object directory
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Build test executables
test_config: test_config.c $(OBJDIR)/config.o $(OBJDIR)/security_utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test_ldap_auth: test_ldap_auth.c $(OBJDIR)/ldap_auth.o $(OBJDIR)/ldap_query.o $(OBJDIR)/security_utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test_totp: test_totp.c $(OBJDIR)/totp_validate.o $(OBJDIR)/security_utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test_security: test_security.c $(OBJDIR)/security_utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test_challenge_response: test_challenge_response.c $(OBJDIR)/config.o $(OBJDIR)/security_utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Run all tests
run: all
	@echo "========================================="
	@echo "Running PAM LDAP TOTP Unit Tests"
	@echo "========================================="
	@for test in $(TESTS); do \
		echo ""; \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done
	@echo ""
	@echo "========================================="
	@echo "All test suites passed!"
	@echo "========================================="

check: run

# Clean build artefacts
clean:
	rm -rf $(OBJDIR) $(TESTS)
	rm -f /tmp/pam_ldap_totp_test_*
	@echo "Cleaned test build files"
