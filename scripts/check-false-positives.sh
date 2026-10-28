#!/usr/bin/env bash
#
# How often the rules cry wolf on a machine with nothing wrong with it.
#
#   ./scripts/check-false-positives.sh [dir:dir:...]
#
# Every file under /usr, /etc and /opt, or the directories given, goes through
# the rules and the archive reader. A match above information is an alarm,
# and the budget for alarms on a clean machine is written in the test
# (content.rs, false_positive_budget). It also prints the time and the peak
# memory, which are the other two budgets the scan has.
#
# Exit 0 is within budget, 1 is over it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE/src-tauri"

if [[ -n "${1:-}" ]]; then
  export GRT_FP_ROOTS="$1"
fi

BINARY=$(cargo test --release --lib --no-run --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | grep grt_sentry_lib | head -1)

if [[ -z "$BINARY" ]]; then
  echo "The test binary did not build." >&2
  exit 2
fi

if [[ -x /usr/bin/time ]]; then
  exec /usr/bin/time -f "peak memory: %M KB" "$BINARY" content::tests::false_positive_budget --ignored --nocapture
fi
exec "$BINARY" content::tests::false_positive_budget --ignored --nocapture
