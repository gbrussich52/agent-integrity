#!/bin/sh
# install-root.sh - run ONCE, by a human, with sudo. Read it first; it is short.
#
#   sudo ./install-root.sh --pubkey /path/to/your_signing_key.pub --user-home "$HOME"
#
# What it does:
#   1. creates a root-owned store (default below) the agent's user account cannot write
#   2. copies the verifier (agent_integrity.py) and your PUBLIC signing key (as allowed_signers) into it
#   3. writes config.json telling the verifier a fresh root heartbeat is required
#   4. installs a root launchd daemon (macOS) or systemd timer (Linux) that runs `check` hourly
#
# What it never does: touch your private key, your agent configs, or anything outside the store
# and the service definition. Undo with:  sudo ./install-root.sh --uninstall
set -eu

case "$(uname -s)" in
  Darwin) STORE_DEFAULT="/Library/Application Support/agent-integrity"; SERVICE_DIR_DEFAULT="/Library/LaunchDaemons" ;;
  *)      STORE_DEFAULT="/var/lib/agent-integrity";                     SERVICE_DIR_DEFAULT="/etc/systemd/system" ;;
esac

STORE="$STORE_DEFAULT"
SERVICE_DIR="$SERVICE_DIR_DEFAULT"
PUBKEY=""
USER_HOME=""
PROJECTS=""
INTERVAL=3600
NO_SERVICE=0
UNINSTALL=0
LABEL="dev.agent-integrity.check"
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() { sed -n '2,16p' "$0"; exit "${1:-2}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --store) STORE="$2"; shift 2 ;;
    --pubkey) PUBKEY="$2"; shift 2 ;;
    --user-home) USER_HOME="$2"; shift 2 ;;
    --project) PROJECTS="$PROJECTS $2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --service-dir) SERVICE_DIR="$2"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

# Root is the whole point: a store the same user can write proves nothing. The override exists
# only so the test suite can exercise this script against a temp dir.
if [ "$(id -u)" -ne 0 ] && [ "${AGENT_INTEGRITY_ALLOW_NONROOT:-0}" != "1" ]; then
  echo "install-root.sh must run as root (sudo). Read it first, then: sudo $0 ..." >&2
  exit 2
fi

if [ "$UNINSTALL" -eq 1 ]; then
  if [ "$(uname -s)" = "Darwin" ]; then
    [ "$NO_SERVICE" -eq 1 ] || launchctl bootout "system/$LABEL" 2>/dev/null || true
    rm -f "$SERVICE_DIR/$LABEL.plist"
  else
    [ "$NO_SERVICE" -eq 1 ] || systemctl disable --now agent-integrity.timer 2>/dev/null || true
    rm -f "$SERVICE_DIR/agent-integrity.service" "$SERVICE_DIR/agent-integrity.timer"
  fi
  echo "service removed. The store at $STORE is left in place (it holds your signed baseline)."
  exit 0
fi

[ -n "$PUBKEY" ] && [ -f "$PUBKEY" ] || { echo "--pubkey must point to your PUBLIC signing key (.pub)" >&2; exit 2; }
[ -n "$USER_HOME" ] && [ -d "$USER_HOME" ] || { echo "--user-home must be the home dir of the account to watch" >&2; exit 2; }
case "$INTERVAL" in ''|*[!0-9]*) echo "--interval must be whole seconds" >&2; exit 2 ;; esac
grep -q "PRIVATE KEY" "$PUBKEY" && { echo "that file is a PRIVATE key; pass the .pub file" >&2; exit 2; }
# Refuse a store inside the watched home: root ownership there would be meaningless.
case "$STORE" in "$USER_HOME"/*) echo "--store must not live under the watched home" >&2; exit 2 ;; esac
for f in "$HERE/agent_integrity.py"; do [ -f "$f" ] || { echo "missing $f" >&2; exit 2; }; done

set -- $(cat "$PUBKEY")
[ $# -ge 2 ] || { echo "unreadable public key" >&2; exit 2; }
KEYTYPE="$1"; KEYBODY="$2"

mkdir -p "$STORE"
cp "$HERE/agent_integrity.py" "$STORE/agent_integrity.py"
# The principal and namespace pin this key to agent-integrity signatures only.
printf 'agent-integrity namespaces="agent-integrity" %s %s\n' "$KEYTYPE" "$KEYBODY" > "$STORE/allowed_signers"

PROJ_JSON="[]"
if [ -n "$PROJECTS" ]; then
  PROJ_JSON="["; sep=""
  for p in $PROJECTS; do PROJ_JSON="$PROJ_JSON$sep\"$p\""; sep=","; done
  PROJ_JSON="$PROJ_JSON]"
fi
cat > "$STORE/config.json" <<EOF
{"heartbeat_required": true, "stale_after": $((INTERVAL * 3)), "home": "$USER_HOME", "projects": $PROJ_JSON}
EOF

# Root ownership is what makes the store tamper-resistant. chown only when we are really root.
if [ "$(id -u)" -eq 0 ]; then
  GROUP=wheel; [ "$(uname -s)" = "Darwin" ] || GROUP=root
  chown -R "root:$GROUP" "$STORE"
fi
chmod 755 "$STORE"
chmod 644 "$STORE/allowed_signers" "$STORE/config.json"
chmod 755 "$STORE/agent_integrity.py"

CMD_PY="$STORE/agent_integrity.py"
# One positional parameter per argument. Building this as a single string and word-splitting it
# broke any path with a space ("/Library/Application Support/..."), so the daemon failed on every run.
set -- check --tier all --store "$STORE" --home "$USER_HOME" --write-heartbeat --quiet

xml_esc() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
# systemd splits ExecStart on whitespace unless an argument is double-quoted; % starts a specifier.
sd_quote() { printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/%/%%/g')"; }

if [ "$NO_SERVICE" -eq 0 ] || [ -n "${AGENT_INTEGRITY_ALLOW_NONROOT:-}" ]; then
  mkdir -p "$SERVICE_DIR"
  if [ "$(uname -s)" = "Darwin" ]; then
    PLIST="$SERVICE_DIR/$LABEL.plist"
    {
      echo '<?xml version="1.0" encoding="UTF-8"?>'
      echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
      echo '<plist version="1.0"><dict>'
      echo "<key>Label</key><string>$(xml_esc "$LABEL")</string>"
      echo '<key>ProgramArguments</key><array>'
      echo '<string>/usr/bin/python3</string>'
      echo "<string>$(xml_esc "$CMD_PY")</string>"
      for a in "$@"; do echo "<string>$(xml_esc "$a")</string>"; done
      echo '</array>'
      echo "<key>StartInterval</key><integer>$INTERVAL</integer>"
      # A new or edited launch agent re-runs the check at once instead of waiting out the hour.
      echo "<key>WatchPaths</key><array><string>$(xml_esc "$USER_HOME/Library/LaunchAgents")</string></array>"
      echo '<key>RunAtLoad</key><true/>'
      echo "<key>StandardOutPath</key><string>$(xml_esc "$STORE/last-run.log")</string>"
      echo "<key>StandardErrorPath</key><string>$(xml_esc "$STORE/last-run.log")</string>"
      echo '</dict></plist>'
    } > "$PLIST"
    chmod 644 "$PLIST"
    [ "$(id -u)" -ne 0 ] || chown root:wheel "$PLIST"
    if [ "$NO_SERVICE" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
      launchctl bootout "system/$LABEL" 2>/dev/null || true
      launchctl bootstrap system "$PLIST"
    fi
  else
    EXEC_LINE="/usr/bin/python3 $(sd_quote "$CMD_PY")"
    for a in "$@"; do EXEC_LINE="$EXEC_LINE $(sd_quote "$a")"; done
    cat > "$SERVICE_DIR/agent-integrity.service" <<EOF
[Unit]
Description=agent-integrity check

[Service]
Type=oneshot
ExecStart=$EXEC_LINE
EOF
    cat > "$SERVICE_DIR/agent-integrity.timer" <<EOF
[Unit]
Description=agent-integrity hourly check

[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL}s

[Install]
WantedBy=timers.target
EOF
    if [ "$NO_SERVICE" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
      systemctl daemon-reload
      systemctl enable --now agent-integrity.timer
    fi
  fi
fi

echo "installed: store=$STORE"
echo "next (as you, not root):"
echo "  python3 agent_integrity.py baseline --store \"$STORE\""
echo "  python3 agent_integrity.py sign --key /path/to/your_signing_key --store \"$STORE\""
echo "(sign asks for your key passphrase, then prints the one sudo command that places the signed manifest.)"
