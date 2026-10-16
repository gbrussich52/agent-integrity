#!/bin/sh
# install-user.sh - NO sudo. Installs the hourly `watch --explain` autopilot for your account.
#
#   ./install-user.sh [--store DIR] [--user-dir DIR] [--interval SECONDS] [--no-explain]
#   ./install-user.sh --uninstall
#
# What it does:
#   1. copies agent_integrity.py into your user dir (default ~/.agent-integrity)
#   2. installs a LaunchAgent (macOS) or a systemd --user timer (Linux) that runs
#      `watch --tier all --explain` hourly: plain-English drift, alerts on NEW risk only,
#      and a dashboard at <user dir>/dashboard.html
#
# What it is not: the trust anchor. Protection comes from the root daemon (install-root.sh);
# without it every output says "mode: unprotected (detection only)". Undo: --uninstall (your
# user dir, history and quarantine folder are left in place).
set -eu

USER_DIR="${AGENT_INTEGRITY_HOME:-$HOME/.agent-integrity}"
STORE_ARG=""
SERVICE_DIR=""
INTERVAL=3600
NO_SERVICE=0
UNINSTALL=0
EXPLAIN="--explain"
LABEL="dev.agent-integrity.watch"
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() { sed -n '2,15p' "$0"; exit "${1:-2}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --user-dir) USER_DIR="$2"; shift 2 ;;
    --store) STORE_ARG="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --service-dir) SERVICE_DIR="$2"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --no-explain) EXPLAIN=""; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  echo "install-user.sh is for your own account; do not run it with sudo." >&2
  exit 2
fi
case "$INTERVAL" in ''|*[!0-9]*) echo "--interval must be whole seconds" >&2; exit 2 ;; esac

if [ "$(uname -s)" = "Darwin" ]; then
  [ -n "$SERVICE_DIR" ] || SERVICE_DIR="$HOME/Library/LaunchAgents"
else
  [ -n "$SERVICE_DIR" ] || SERVICE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
fi

if [ "$UNINSTALL" -eq 1 ]; then
  if [ "$(uname -s)" = "Darwin" ]; then
    [ "$NO_SERVICE" -eq 1 ] || launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$SERVICE_DIR/$LABEL.plist"
  else
    [ "$NO_SERVICE" -eq 1 ] || systemctl --user disable --now agent-integrity-watch.timer 2>/dev/null || true
    rm -f "$SERVICE_DIR/agent-integrity-watch.service" "$SERVICE_DIR/agent-integrity-watch.timer"
  fi
  echo "watch service removed. $USER_DIR is left in place (history, dashboard, quarantine)."
  exit 0
fi

[ -f "$HERE/agent_integrity.py" ] || { echo "missing $HERE/agent_integrity.py" >&2; exit 2; }
mkdir -p "$USER_DIR"
chmod 700 "$USER_DIR"
cp "$HERE/agent_integrity.py" "$USER_DIR/agent_integrity.py"
chmod 755 "$USER_DIR/agent_integrity.py"

CMD_PY="$USER_DIR/agent_integrity.py"
WATCH_ARGS="watch --tier all --user-dir $USER_DIR $EXPLAIN"
[ -z "$STORE_ARG" ] || WATCH_ARGS="$WATCH_ARGS --store $STORE_ARG"

mkdir -p "$SERVICE_DIR"
if [ "$(uname -s)" = "Darwin" ]; then
  PLIST="$SERVICE_DIR/$LABEL.plist"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict>'
    echo "<key>Label</key><string>$LABEL</string>"
    echo '<key>ProgramArguments</key><array>'
    echo '<string>/usr/bin/python3</string>'
    echo "<string>$CMD_PY</string>"
    for a in $WATCH_ARGS; do echo "<string>$a</string>"; done
    echo '</array>'
    echo "<key>StartInterval</key><integer>$INTERVAL</integer>"
    echo '<key>RunAtLoad</key><true/>'
    echo "<key>StandardOutPath</key><string>$USER_DIR/last-watch.log</string>"
    echo "<key>StandardErrorPath</key><string>$USER_DIR/last-watch.log</string>"
    echo '</dict></plist>'
  } > "$PLIST"
  chmod 644 "$PLIST"
  if [ "$NO_SERVICE" -eq 0 ]; then
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST"
  fi
else
  cat > "$SERVICE_DIR/agent-integrity-watch.service" <<UNIT
[Unit]
Description=agent-integrity watch

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $CMD_PY $WATCH_ARGS
UNIT
  cat > "$SERVICE_DIR/agent-integrity-watch.timer" <<UNIT
[Unit]
Description=agent-integrity hourly watch

[Timer]
OnBootSec=5min
OnUnitActiveSec=${INTERVAL}s

[Install]
WantedBy=timers.target
UNIT
  if [ "$NO_SERVICE" -eq 0 ]; then
    systemctl --user daemon-reload
    systemctl --user enable --now agent-integrity-watch.timer
  fi
fi

echo "installed: user dir=$USER_DIR (no sudo). Dashboard: $USER_DIR/dashboard.html"
