#!/bin/sh
# SessionStart hook (user side). It only READS what the root check last recorded; it never scans
# and never writes. If the root check has stopped, `status` says STALE, which is the point.
# Set AGENT_INTEGRITY_STORE if you installed the store somewhere other than the default.
HERE="$(cd "$(dirname "$0")/.." && pwd)"
STORE="${AGENT_INTEGRITY_STORE:-}"
if [ -n "$STORE" ]; then
  exec python3 "$HERE/agent_integrity.py" status --store "$STORE"
fi
exec python3 "$HERE/agent_integrity.py" status
