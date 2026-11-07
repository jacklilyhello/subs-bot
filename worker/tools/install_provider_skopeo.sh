#!/usr/bin/env bash
set -euo pipefail

test "$(dpkg --print-architecture)" = amd64
package_version=1.13.3+ds1-2ubuntu0.24.04.3
sudo apt-get update
sudo apt-get install --yes --reinstall --no-install-recommends "skopeo=$package_version"
test "$(dpkg-query -W -f='${Version}' skopeo)" = "$package_version"
