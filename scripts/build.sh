#!/usr/bin/env bash
#
# Release build, with the geolocation database if it is here.
#
#   npm run build            a .deb and an AppImage
#   npm run build:binary     just the executable
#   ./scripts/build.sh --bundles deb
#
# The GeoLite2 database is not in the repository, and a declared resource that
# is missing is a hard build error, so tauri.conf.json lists only what is
# always present and tauri.geoip.conf.json is merged in when the database is
# there.
#
# Build through this rather than `cargo build --release`, which leaves the
# path of this directory inside the binary. See scripts/check-build.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATABASE="$HERE/src-tauri/resources/GeoLite2-City.mmdb"

cd "$HERE"

if [[ -f "$DATABASE" ]]; then
  echo "Including the GeoLite2 database ($(du -h "$DATABASE" | cut -f1))."
  exec npx tauri build --config src-tauri/tauri.geoip.conf.json "$@"
fi

echo "Note: no GeoLite2 database at src-tauri/resources/, so connections will"
echo "have no place attached to them. Everything else works. To add it:"
echo
echo "    ./scripts/fetch-geoip.sh <maxmind-license-key> src-tauri/resources"
echo
exec npx tauri build "$@"
