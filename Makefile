# Makefile for PAM LDAP TOTP Authentication Module
#
# Standalone module performing both LDAP password authentication and TOTP validation

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -I./include
LDFLAGS = -shared
LIBS = -lpam -lldap -llber -loath
TARGET = pam_ldap_totp_auth.so
INSTALL_DIR = /lib/security

SRCDIR = src
OBJDIR = obj

# Source files for standalone LDAP + TOTP authentication
SOURCES = $(SRCDIR)/pam_auth.c $(SRCDIR)/config.c $(SRCDIR)/ldap_auth.c \
          $(SRCDIR)/ldap_query.c $(SRCDIR)/totp_validate.c $(SRCDIR)/security_utils.c
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean install test check

all: $(TARGET)

check: test

# Build PAM module
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built $(TARGET) - Standalone LDAP + TOTP authentication module"

# Compile object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create object directory
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Clean build artefacts
clean:
	rm -rf $(OBJDIR) $(TARGET)
	@if [ -d tests ]; then $(MAKE) -C tests clean; fi
	@echo "Cleaned build files"

# Install PAM module
install: $(TARGET)
	install -D -m 0644 $(TARGET) $(INSTALL_DIR)/$(TARGET)
	@echo "Installed $(TARGET) to $(INSTALL_DIR)"

# Run unit tests
test:
	@echo "Running unit tests..."
	@if [ -d tests ]; then \
		$(MAKE) -C tests run; \
	else \
		echo "No tests directory found"; \
	fi

# Dependencies
$(OBJDIR)/pam_auth.o: include/pam_ldap_totp.h
$(OBJDIR)/config.o: include/pam_ldap_totp.h
$(OBJDIR)/ldap_auth.o: include/pam_ldap_totp.h
$(OBJDIR)/ldap_query.o: include/pam_ldap_totp.h
$(OBJDIR)/totp_validate.o: include/pam_ldap_totp.h
$(OBJDIR)/security_utils.o: include/pam_ldap_totp.h
