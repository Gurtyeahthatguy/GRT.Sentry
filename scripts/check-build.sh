#!/usr/bin/env bash
#
# What the release binary can reach, and what it says about whoever built it.
#
#   ./scripts/check-build.sh src-tauri/target/release/grt-sentry
#
# GRT Sentry does use the network, so this cannot check for the absence of
# every address. It checks that the binary holds no contactable address other
# than the ones written down, with a reason, in allowed-strings.txt.
#
# Exit 0 is clean, 1 is something to look at.
set -uo pipefail

BINARY="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOWED_FILE="$HERE/allowed-strings.txt"

if [[ -z "$BINARY" || ! -f "$BINARY" ]]; then
  echo "Usage: $0 <binary-path>" >&2
  exit 2
fi

if ! command -v strings >/dev/null 2>&1; then
  echo "ERROR: 'strings' is not available (binutils package)" >&2
  exit 2
fi

echo "Checking: $BINARY"
echo "Size:     $(du -h "$BINARY" | cut -f1)"
echo

FAILED=0

# --- 1. Absolute build paths ----------------------------------------------
# These name whoever built the binary. See src-tauri/.cargo/config.toml.
echo "[1/5] Absolute paths…"
PATHS=$(strings "$BINARY" | grep -E '(/home/[a-zA-Z0-9._-]+/|/Users/[a-zA-Z0-9._-]+/|[A-Z]:\\Users\\)' | sort -u)
if [[ -n "$PATHS" ]]; then
  echo "  FOUND:"
  echo "$PATHS" | head -20 | sed 's/^/    /'
  FAILED=1
else
  echo "  OK"
fi

# --- 2. Network endpoints -------------------------------------------------
# Split rather than filtered, because a check that cries wolf stops being read.
# Brotli embeds a dictionary of English fragments that look like addresses.
echo "[2/5] Network references…"

KNOWN_TLDS='(com|org|net|io|dev|app|edu|gov|mil|int|info|biz|xyz|tv|me|ai|co|uk|de|fr|it|es|nl|se|no|dk|fi|pl|pt|cz|gr|ie|ch|at|be|eu|us|ca|au|nz|ru|cn|jp|kr|tw|hk|sg|in|br|mx|za|il|test|local|localhost|onion)'

ALLOWED_PATTERN=$(grep -vE '^\s*(#|$)' "$ALLOWED_FILE" 2>/dev/null | sed 's/[.[\*^$()+?{|]/\\&/g' | paste -sd '|')

ALL_URLS=$(strings "$BINARY" \
  | grep -Eo 'https?://(localhost|[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)(:[0-9]+)?(/[a-zA-Z0-9./_?=-]*)?' \
  | sort -u)

if [[ -n "$ALLOWED_PATTERN" ]]; then
  ALL_URLS=$(echo "$ALL_URLS" | grep -Ev "^($ALLOWED_PATTERN)" | grep -v '^$')
fi

REAL=$(echo "$ALL_URLS" | grep -Ei "^https?://([a-zA-Z0-9-]+\.)*$KNOWN_TLDS(:[0-9]+)?(/|$)")
FRAGMENTS=$(echo "$ALL_URLS" | grep -Eiv "^https?://([a-zA-Z0-9-]+\.)*$KNOWN_TLDS(:[0-9]+)?(/|$)" | grep -v '^$')

if [[ -n "$REAL" ]]; then
  echo "  FAIL: addresses that are not in allowed-strings.txt"
  echo "$REAL" | head -20 | sed 's/^/    /'
  FAILED=1
else
  echo "  OK: nothing contactable outside the allow list"
fi

if [[ -n "$FRAGMENTS" ]]; then
  COUNT=$(echo "$FRAGMENTS" | wc -l)
  echo "  REVIEW: $COUNT string(s) with no recognisable domain, expected from brotli"
  echo "$FRAGMENTS" | head -8 | sed 's/^/    /'
  [[ $COUNT -gt 8 ]] && echo "    … $((COUNT - 8)) more"
fi

# --- 3. Telemetry and crash reporters -------------------------------------
# There is a crash-reporting service called Sentry and a program here called
# GRT Sentry, so the search is for the shapes that service's libraries leave.
echo "[3/5] Telemetry and crash reporters…"
TELEMETRY=$(strings "$BINARY" \
  | grep -Eio '(sentry[-_](core|types|backtrace|contexts|panic)|getsentry|ingest\.sentry\.io|bugsnag|datadog|mixpanel|amplitude|google-analytics|posthog|crashlytics)' \
  | sort -u)
if [[ -n "$TELEMETRY" ]]; then
  echo "  FOUND:"
  echo "$TELEMETRY" | sed 's/^/    /'
  FAILED=1
else
  echo "  OK"
fi

# --- 4. Debug symbols -----------------------------------------------------
echo "[4/5] Debug symbols…"
if command -v file >/dev/null 2>&1; then
  if file "$BINARY" | grep -q 'not stripped'; then
    echo "  WARNING: symbols present, set strip = true"
    FAILED=1
  else
    echo "  OK"
  fi
else
  echo "  SKIPPED ('file' is not available)"
fi

# --- 5. The API key ------------------------------------------------------
# The API key belongs in a 0600 file, never in the binary.
echo "[5/5] Embedded credentials…"
KEYS=$(strings "$BINARY" | grep -E '^[a-f0-9]{64}$' | sort -u)
if [[ -n "$KEYS" ]]; then
  echo "  REVIEW: 64-character hex strings, which is the shape of a VirusTotal key"
  echo "$KEYS" | head -5 | sed 's/^/    /'
  echo "    (test fixtures use hashes of that shape; check before releasing)"
else
  echo "  OK"
fi

echo
if [[ $FAILED -eq 0 ]]; then
  echo "RESULT: binary is clean."
else
  echo "RESULT: something to fix. Do not distribute before it is dealt with."
fi

exit $FAILED
