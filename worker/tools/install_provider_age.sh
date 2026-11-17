#!/usr/bin/env bash
set -euo pipefail

# Ubuntu's published amd64 security package, pinned by version and full bytes.
# This is run on the hosted runner before any private source, target or key is read.
test "$(dpkg --print-architecture)" = amd64
test -n "${RUNNER_TEMP:-}"
package="$RUNNER_TEMP/provider-age.deb"
destination="$RUNNER_TEMP/provider-age"
test ! -e "$package"
test ! -e "$destination"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 60 \
  --output "$package" \
  https://security.ubuntu.com/ubuntu/pool/universe/a/age/age_1.1.1-1ubuntu0.24.04.3_amd64.deb
test "$(stat -c '%s' "$package")" = 1629868
printf '%s  %s\n' 22ed034e16d8a7662d94dbb8d9f644f01284c6d87bc6b619903e38ba91125337 "$package" | sha256sum --check --status
mkdir -m 700 "$destination"
dpkg-deb --extract "$package" "$destination"
test -x "$destination/usr/bin/age"
test -x "$destination/usr/bin/age-keygen"
