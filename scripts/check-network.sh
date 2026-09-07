#!/usr/bin/env bash
#
# Every address the running program actually contacts.
#
#   ./scripts/check-network.sh src-tauri/target/release/grt-sentry
#
# Use the program normally, then close it. What comes back is the list of
# addresses it opened a socket to. The expected answer is VirusTotal during a
# scan and nothing else.
#
# check-build.sh reads the binary. This watches the process, which is the
# stronger of the two.
set -uo pipefail

BINARY="${1:-}"

if [[ -z "$BINARY" || ! -x "$BINARY" ]]; then
  echo "Usage: $0 <path-to-binary>" >&2
  exit 2
fi

if ! command -v strace >/dev/null 2>&1; then
  echo "ERROR: strace is not installed (sudo apt install strace)" >&2
  exit 2
fi

LOG="$(mktemp -t grt-sentry-network-XXXXXX.log)"
echo "Tracing $BINARY"
echo "Use the program, then close it to see the result."
echo

strace -f -qq -e trace=socket,connect,sendto -o "$LOG" "$BINARY" >/dev/null 2>&1

# Only AF_INET and AF_INET6 to something other than loopback mean the network
# was used.
HITS=$(grep -E 'connect\(.*(sin_addr|sin6_addr)' "$LOG" \
  | grep -v '127\.0\.0\.1' \
  | grep -v 'inet6_addr("::1")' \
  | sed 's/.*inet_addr("\([^"]*\)").*/\1/;s/.*inet6_addr("\([^"]*\)").*/\1/' \
  | sort -u)

echo "----------------------------------------"
if [[ -z "$HITS" ]]; then
  echo "RESULT: no outbound connection was made."
else
  echo "RESULT: connections were made to:"
  echo "$HITS" | sed 's/^/  /'
  echo
  echo "Resolve them if you want names:"
  echo "$HITS" | head -5 | sed 's/^/  getent hosts /'
fi
echo
echo "Full trace kept at: $LOG"
