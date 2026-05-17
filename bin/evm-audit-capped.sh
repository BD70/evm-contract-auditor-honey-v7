#!/bin/bash
# Hard RSS cap for the Go auditor binary.
# macOS doesn't honor ulimit -v / RLIMIT_AS for native Mach-Os, so we run
# the binary in the background and SIGKILL it if its RSS exceeds CAP_MB.
# Exit 137 indicates a memory-cap kill (distinguishable from a clean exit).
#
# Sizing rationale (v11 — reverted from 8 GB back to 2 GB):
# The root cause of the 4-6 GB peaks was exponential Expr string growth in
# stacksim.go's binop(). That's now fixed (Expr strings capped at 1KB with
# CRC32 hash). Legitimate peak RSS should be under 500 MB. Keeping the cap
# at 2 GB as a generous safety net.
#
# Override per-invocation via EVM_AUDIT_MAX_RSS_MB.

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

# Track peak RSS so the diagnostic in stderr is more useful — if it
# fires near the cap repeatedly we know we need to raise it again.
PEAK_KB=0

while kill -0 "$CHILD" 2>/dev/null; do
  RSS=$(ps -o rss= -p "$CHILD" 2>/dev/null | tr -d ' ')
  if [ -n "$RSS" ]; then
    if [ "$RSS" -gt "$PEAK_KB" ]; then
      PEAK_KB="$RSS"
    fi
    if [ "$RSS" -gt "$CAP_KB" ]; then
      echo "evm-audit-capped: RSS ${RSS}KB > cap ${CAP_KB}KB (${CAP_MB}MB), peak ${PEAK_KB}KB, sending SIGKILL to pid ${CHILD}" >&2
      kill -9 "$CHILD" 2>/dev/null
      wait "$CHILD" 2>/dev/null
      exit 137
    fi
  fi
  sleep "$POLL_S"
done

wait "$CHILD"
EXIT=$?
# Surface peak RSS on non-zero exits so we can spot the slow march toward
# the cap before the next bump. Keeps successful runs quiet.
if [ "$EXIT" != "0" ] && [ "$PEAK_KB" -gt 0 ]; then
  echo "evm-audit-capped: child exited ${EXIT}, peak RSS was ${PEAK_KB}KB ($(( PEAK_KB / 1024 ))MB)" >&2
fi
exit "$EXIT"
