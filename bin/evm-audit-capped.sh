#!/bin/bash
# Hard RSS cap for the Go auditor binary.
# macOS doesn't honor ulimit -v / RLIMIT_AS for native Mach-Os, so we run
# the binary in the background and SIGKILL it if its RSS exceeds CAP_MB.
# Exit 137 indicates a memory-cap kill (distinguishable from a clean exit).

set -u

CAP_MB="${EVM_AUDIT_MAX_RSS_MB:-2048}"
POLL_MS="${EVM_AUDIT_RSS_POLL_MS:-500}"
BIN_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BIN="${BIN_DIR}/evm-audit-darwin-arm64"

if [ ! -x "$REAL_BIN" ]; then
  echo "evm-audit-capped: missing $REAL_BIN" >&2
  exit 127
fi

CAP_KB=$(( CAP_MB * 1024 ))
POLL_S=$(awk -v ms="$POLL_MS" 'BEGIN{printf "%.3f", ms/1000.0}')

"$REAL_BIN" "$@" &
CHILD=$!

trap 'kill -TERM "$CHILD" 2>/dev/null; exit 143' TERM INT

while kill -0 "$CHILD" 2>/dev/null; do
  RSS=$(ps -o rss= -p "$CHILD" 2>/dev/null | tr -d ' ')
  if [ -n "$RSS" ] && [ "$RSS" -gt "$CAP_KB" ]; then
    echo "evm-audit-capped: RSS ${RSS}KB > cap ${CAP_KB}KB, sending SIGKILL to pid ${CHILD}" >&2
    kill -9 "$CHILD" 2>/dev/null
    wait "$CHILD" 2>/dev/null
    exit 137
  fi
  sleep "$POLL_S"
done

wait "$CHILD"
exit $?
