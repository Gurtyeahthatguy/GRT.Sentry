#!/usr/bin/env bash
#
# Opens the interface in a normal browser, with fake data.
#
#   ./scripts/preview-ui.sh [port]
#
# The frontend talks to the backend through window.__TAURI__, which does not
# exist outside the application. This copies src/ to a temporary directory,
# injects tests/mock-tauri.js ahead of the real script, and serves it.
#
# Nothing here is part of a build: src/index.html does not mention the mock.
set -euo pipefail

PORT="${1:-8731}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp -r "$HERE/src/." "$WORK/"
cp "$HERE/tests/mock-tauri.js" "$WORK/mock.js"

# The mock has to load before the module that reads window.__TAURI__.
sed -i 's|<script type="module" src="js/main.js"></script>|<script src="mock.js"></script>\n    <script type="module" src="js/main.js"></script>|' "$WORK/index.html"

echo "Serving the interface with mock data at http://localhost:$PORT"
echo "Ctrl-C to stop."
cd "$WORK" && python3 -m http.server "$PORT"
