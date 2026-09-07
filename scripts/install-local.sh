#!/usr/bin/env bash
#
# Puts GRT Sentry in this user's application menu.
#
# User directories only: no root, no system files, no package manager. The
# operations that need root ask for it at the moment they run.
#
#   ./scripts/install-local.sh            install
#   ./scripts/install-local.sh --remove   undo it completely
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$HERE/src-tauri/target/release/grt-sentry"

BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/grt-sentry"
DESKTOP="$APP_DIR/org.grt.sentry.desktop"

if [[ "${1:-}" == "--remove" ]]; then
  rm -f "$BIN_DIR/grt-sentry" "$DESKTOP"
  rm -f "$ICON_DIR"/*/apps/grt-sentry.png
  systemctl --user disable --now grt-sentry-scan.timer 2>/dev/null
  rm -f "$HOME/.config/systemd/user/grt-sentry-scan."{timer,service}
  systemctl --user daemon-reload 2>/dev/null
  command -v update-desktop-database >/dev/null 2>&1 && \
    update-desktop-database "$APP_DIR" 2>/dev/null

  echo "Removed, including the scheduled scan."
  echo
  echo "Left in place:"
  echo "  database and quarantine  $DATA_DIR"
  echo "  configuration            ${XDG_CONFIG_HOME:-$HOME/.config}/grt-sentry"
  echo
  echo "Anything still in quarantine is in that first directory. Restore what"
  echo "is wanted before deleting it."
  echo
  echo "The firewall table, if you created one, is also still there:"
  echo "  sudo nft delete table inet grtsentry"
  exit 0
fi

if [[ ! -x "$BINARY" ]]; then
  echo "No release binary at $BINARY" >&2
  echo "Build it first:  npm run build" >&2
  exit 1
fi

mkdir -p "$BIN_DIR" "$APP_DIR" "$DATA_DIR"
install -m 755 "$BINARY" "$BIN_DIR/grt-sentry"

for size in 32x32 128x128; do
  source_icon="$HERE/src-tauri/icons/${size}.png"
  if [[ -f "$source_icon" ]]; then
    mkdir -p "$ICON_DIR/$size/apps"
    install -m 644 "$source_icon" "$ICON_DIR/$size/apps/grt-sentry.png"
  fi
done

# The database is not inside the binary, so a local install needs it beside
# the data. scripts/fetch-geoip.sh refreshes it later.
if [[ -f "$HERE/src-tauri/resources/GeoLite2-City.mmdb" ]]; then
  install -m 644 "$HERE/src-tauri/resources/GeoLite2-City.mmdb" "$DATA_DIR/GeoLite2-City.mmdb"
  for extra in GeoLite2-COPYRIGHT.txt GeoLite2-LICENSE.txt; do
    [[ -f "$HERE/src-tauri/resources/$extra" ]] && install -m 644 "$HERE/src-tauri/resources/$extra" "$DATA_DIR/$extra"
  done
  echo "Geolocation database installed at $DATA_DIR/GeoLite2-City.mmdb"
fi

cat > "$DESKTOP" <<DESKTOP_EOF
[Desktop Entry]
Type=Application
Name=GRT Sentry
GenericName=Security scanner
Comment=Check files, connections and system state, and act on what is found
Exec=$BIN_DIR/grt-sentry
Icon=grt-sentry
Terminal=false
Categories=System;Security;Utility;
StartupNotify=true
DESKTOP_EOF

chmod 644 "$DESKTOP"

command -v update-desktop-database >/dev/null 2>&1 && \
  update-desktop-database "$APP_DIR" 2>/dev/null
command -v gtk-update-icon-cache >/dev/null 2>&1 && \
  gtk-update-icon-cache -f -t "$ICON_DIR" 2>/dev/null

echo "Installed for this user:"
echo "  program   $BIN_DIR/grt-sentry"
echo "  launcher  $DESKTOP"
echo
echo "Two optional steps, both explained in the README:"
echo "  a VirusTotal key, in Settings, to check files against the engines"
echo "  sudo ./scripts/setup-nftables.sh, to make \"Block address\" work"
echo
echo "To undo: $0 --remove"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo
  echo "Note: $BIN_DIR is not on your PATH, so typing 'grt-sentry' in a terminal"
  echo "will not find it. The menu entry works regardless."
fi
