#!/usr/bin/env bash
#
# Downloads the GeoLite2 City database.
#
#   ./scripts/fetch-geoip.sh <maxmind-license-key> [destination]
#
# The database is what turns an IP address into a place without asking an
# online service.
#
# Getting a key, once:
#   1. sign up at https://www.maxmind.com/en/geolite2/signup
#   2. in the account panel, Manage License Keys, generate one
#   3. run this script with it
#
# The default destination is ~/.local/share/grt-sentry, which the program
# prefers over the copy bundled at build time. Pass src-tauri/resources to
# refresh the bundled copy instead.
set -euo pipefail

KEY="${1:-}"
DESTINATION="${2:-${XDG_DATA_HOME:-$HOME/.local/share}/grt-sentry}"

if [[ -z "$KEY" ]]; then
  sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi

for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is needed and not installed." >&2; exit 1; }
done

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${KEY}&suffix=tar.gz"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Downloading GeoLite2 City (about 60 MB)…"
if ! curl -fsSL "$URL" -o "$WORK/geolite2.tar.gz"; then
  echo "The download failed. The usual cause is a license key that is not valid." >&2
  exit 1
fi

tar xzf "$WORK/geolite2.tar.gz" -C "$WORK"

FOUND="$(find "$WORK" -name 'GeoLite2-City.mmdb' -print -quit)"
if [[ -z "$FOUND" ]]; then
  echo "The archive did not contain GeoLite2-City.mmdb." >&2
  exit 1
fi

mkdir -p "$DESTINATION"
install -m 0644 "$FOUND" "$DESTINATION/GeoLite2-City.mmdb"

# MaxMind's licence asks that the attribution travels with the data.
for extra in COPYRIGHT.txt LICENSE.txt; do
  EXTRA_PATH="$(find "$WORK" -name "$extra" -print -quit)"
  [[ -n "$EXTRA_PATH" ]] && install -m 0644 "$EXTRA_PATH" "$DESTINATION/GeoLite2-$extra"
done

echo
echo "Installed: $DESTINATION/GeoLite2-City.mmdb"
du -h "$DESTINATION/GeoLite2-City.mmdb" | cut -f1 | sed 's/^/Size: /'
echo "Restart GRT Sentry to pick it up."
