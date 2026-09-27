#!/usr/bin/env bash
set -euo pipefail

# Deploy the current checkout into the system Shield venv.
# This is intentionally dependency-free: it updates Shield code only and preserves
# /etc configuration, DID keys, wallets, queues, and policy files.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/update_installed_shield_from_checkout.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${SHIELD_PYTHON:-/opt/xibalba-shield/venv/bin/python}"
uv_bin="${UV_BIN:-/home/xibalba/.local/bin/uv}"

[[ -x "$python_bin" ]] || { echo "Service Python not found: $python_bin" >&2; exit 1; }
[[ -x "$uv_bin" ]] || { echo "uv not found: $uv_bin" >&2; exit 1; }

echo "Installing checkout code into $python_bin (dependencies and identity material unchanged)..."
"$uv_bin" pip install \
  --python "$python_bin" \
  --no-deps \
  --reinstall \
  --link-mode=copy \
  "$repo_root"

# The systemd unit invokes this launcher directly; updating the Python package
# alone does not update its argument/env wiring.
install -m 0755 "$repo_root/packaging/systemd/xibalba-shield-run" /usr/local/bin/xibalba-shield-run

systemctl daemon-reload
systemctl restart xibalba-shield.service
systemctl is-active --quiet xibalba-shield.service

echo "Installed checkout and restarted Shield."
systemctl --no-pager --full status xibalba-shield.service | sed -n '1,18p'
