#!/usr/bin/env bash
set -euo pipefail

# Install the local Integrity SDK checkout into the system Shield venv.
# This repairs the signed schema-v2 observed_at contract without changing
# Shield configuration, DID material, wallets, or queues.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/update_installed_integrity_sdk_from_checkout.sh" >&2
  exit 1
fi

sdk_root="${INTEGRITY_SDK_ROOT:-/home/xibalba/Projects/integrity-core/integrity-sdk}"
python_bin="${SHIELD_PYTHON:-/opt/xibalba-shield/venv/bin/python}"
uv_bin="${UV_BIN:-/home/xibalba/.local/bin/uv}"
service="${SHIELD_SERVICE:-xibalba-shield.service}"

[[ -d "$sdk_root/integrity_sdk" ]] || { echo "Integrity SDK checkout not found: $sdk_root" >&2; exit 1; }
[[ -x "$python_bin" ]] || { echo "Shield Python not found: $python_bin" >&2; exit 1; }
[[ -x "$uv_bin" ]] || { echo "uv not found: $uv_bin" >&2; exit 1; }

echo "Installing Integrity SDK checkout into $python_bin..."
"$uv_bin" pip install \
  --python "$python_bin" \
  --no-deps \
  --reinstall \
  --link-mode=copy \
  "$sdk_root"

installed_client="$($python_bin - <<'PY'
import inspect
from integrity_sdk import client

source = inspect.getsource(client.IntegrityClient.flush_telemetry)
if '"observed_at"' not in source:
    raise SystemExit("installed Integrity SDK still lacks signed observed_at")
print(client.__file__)
PY
)"
echo "Verified signed observed_at support: $installed_client"

systemctl daemon-reload
systemctl restart "$service"
systemctl is-active --quiet "$service"

echo "PASS installed Integrity SDK and restarted $service."
echo "Next: sudo ./scripts/verify_local_realtime_integrations.sh"
