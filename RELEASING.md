# Releasing

1. As changes land, add them to CHANGELOG.md under `## [Unreleased]`.
2. On an up-to-date `main`, run `scripts/release.sh` (a patch release), or `scripts/release.sh minor` / `major`. It shows the notes, asks for confirmation, then stamps the changelog, bumps `PAM_LDAP_TOTP_VERSION`, commits, tags and pushes.
3. The tag triggers the Release workflow, which runs the unit tests and creates the GitHub release from that version's changelog section.

openvpn-server-ldap-otp builds this module from the release tarball, so after a release bump `PAM_MODULE_VERSION` in its Dockerfile and release that too.
