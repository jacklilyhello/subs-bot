#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || -z ${2:-} ]]; then
  printf '%s\n' 'Usage: download-validation-client.sh <sing-box|mihomo> <archive path>' >&2
  exit 2
fi

client=$1
archive=$2
case "$client" in
  sing-box)
    asset_api=https://api.github.com/repos/SagerNet/sing-box/releases/assets/669526810
    release_url=https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz
    checksum=699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968
    ;;
  mihomo)
    asset_api=https://api.github.com/repos/MetaCubeX/mihomo/releases/assets/663189170
    release_url=https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-compatible-v1.19.33.gz
    checksum=386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6
    ;;
  *)
    printf '%s\n' 'Unsupported validation client.' >&2
    exit 2
    ;;
esac

transfer=(-q --fail --silent --show-error --location --max-redirs 5
  --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 60
  --retry 2 --retry-max-time 90 --retry-connrefused --output "$archive")
printf 'Downloading the pinned %s asset through the GitHub release API.\n' "$client"
if ! curl "${transfer[@]}" --header 'Accept: application/octet-stream' \
  --header 'X-GitHub-Api-Version: 2026-03-10' "$asset_api"; then
  printf '%s asset API download failed. Trying the official release URL.\n' "$client"
  curl "${transfer[@]}" "$release_url"
fi
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict
