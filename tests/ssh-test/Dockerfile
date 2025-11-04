FROM ubuntu:24.04

# Install SSH server, LDAP client, and build dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server \
        build-essential \
        gcc \
        make \
        libpam0g-dev \
        libldap2-dev \
        liboath-dev \
        ldap-utils \
        nslcd \
        nscd \
        libnss-ldapd \
        expect \
        oathtool && \
    rm -rf /var/lib/apt/lists/*

# Create privilege separation directory for SSH
RUN mkdir -p /run/sshd

# Copy PAM module source and build it
COPY . /build/ldap-totp-pam
WORKDIR /build/ldap-totp-pam

RUN make clean && make && \
    cp pam_ldap_totp_auth.so /lib/x86_64-linux-gnu/security/ && \
    chmod 644 /lib/x86_64-linux-gnu/security/pam_ldap_totp_auth.so && \
    echo "✓ PAM module installed"

# Copy test configuration files
COPY tests/ssh-test/nslcd.conf /etc/nslcd.conf
COPY tests/ssh-test/pam_ldap_totp_auth.conf /etc/security/pam_ldap_totp_auth.conf
COPY tests/ssh-test/pam-sshd /etc/pam.d/sshd
COPY tests/ssh-test/sshd_config /etc/ssh/sshd_config

# Set proper permissions
RUN chmod 600 /etc/nslcd.conf && \
    chmod 644 /etc/security/pam_ldap_totp_auth.conf

# Create test script directory
RUN mkdir -p /test
COPY tests/ssh-test/test-*.sh /test/
COPY tests/ssh-test/test-*.exp /test/
RUN chmod +x /test/*.sh /test/*.exp

WORKDIR /test

# Expose SSH port
EXPOSE 22

# Start SSH and nslcd
CMD ["sh", "-c", "nslcd && /usr/sbin/sshd -D"]
