#!/usr/bin/env bash
set -euo pipefail

# Xibalba Shield - macOS Agent Installer
# Configures directories, LaunchDaemon, and permissions on macOS.

if [ "$(uname -s)" != "Darwin" ]; then
  printf 'install_macos_agent.sh is designed for macOS (Darwin).\nFor Linux, use scripts/install_linux_agent.sh.\n' >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  printf 'install_macos_agent.sh must run with sudo/root to install LaunchDaemons and write system paths.\n' >&2
  exit 1
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
  printf 'Python 3 interpreter not found: %s\n' "$PYTHON_BIN" >&2
  exit 1
}

CONFIG_DIR="${CONFIG_DIR:-/etc/xibalba-shield}"
POLICY_DIR="${POLICY_DIR:-${CONFIG_DIR}/policies}"
LOG_DIR="${LOG_DIR:-/var/log/xibalba-shield}"
STATE_DIR="${STATE_DIR:-/var/lib/xibalba-shield}"
APP_SUPPORT_DIR="${APP_SUPPORT_DIR:-/Library/Application Support/xibalba-shield}"
LAUNCHD_DIR="${LAUNCHD_DIR:-/Library/LaunchDaemons}"
ENABLE_SERVICE="${ENABLE_SERVICE:-1}"

printf '==> [1/4] Creating system directories...\n'
install -d -m 0755 "$CONFIG_DIR" "$POLICY_DIR" "$LOG_DIR" "$STATE_DIR" "$APP_SUPPORT_DIR"

printf '==> [2/4] Installing Python package...\n'
"$PYTHON_BIN" -m pip install --upgrade .

printf '==> [3/4] Installing LaunchDaemon scripts & plist...\n'
install -d -m 0755 /usr/local/bin
install -m 0755 packaging/launchd/xibalba-shield-run.sh /usr/local/bin/xibalba-shield-run
install -m 0644 packaging/launchd/com.xibalba.shield.plist "$LAUNCHD_DIR/com.xibalba.shield.plist"

if [ ! -f "$CONFIG_DIR/shield.env" ]; then
  install -m 0600 packaging/systemd/shield.env.example "$CONFIG_DIR/shield.env"
fi

printf '==> [4/4] Activating LaunchDaemon...\n'
if [ "$ENABLE_SERVICE" = "1" ]; then
  # Unload previous instance if running
  launchctl bootout system/"com.xibalba.shield" 2>/dev/null || launchctl unload "$LAUNCHD_DIR/com.xibalba.shield.plist" 2>/dev/null || true
  # Load new daemon
  launchctl bootstrap system "$LAUNCHD_DIR/com.xibalba.shield.plist" 2>/dev/null || launchctl load -w "$LAUNCHD_DIR/com.xibalba.shield.plist"
  printf '✓ Xibalba Shield LaunchDaemon activated: com.xibalba.shield\n'
else
  printf 'LaunchDaemon installed at %s/com.xibalba.shield.plist (ENABLE_SERVICE=0, not started)\n' "$LAUNCHD_DIR"
fi

printf '\n================================================================\n'
printf '  ✓ Xibalba Shield macOS Agent Successfully Installed\n'
printf '  Configuration:  %s\n' "$CONFIG_DIR"
printf '  Logs:           %s\n' "$LOG_DIR"
printf '  LaunchDaemon:   %s/com.xibalba.shield.plist\n' "$LAUNCHD_DIR"
printf '================================================================\n'
