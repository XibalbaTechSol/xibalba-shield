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

# Production must run the SDK that Shield's CI tests: the integrity-core ref pinned in
# .github/workflows/ci.yml. The sibling checkout moves independently (its 2026-09-28
# restructure removed APIs Shield still imports), so refuse any other commit.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pinned_ref="$(awk '/repository: XibalbaTechSol\/integrity-core/{f=1} f&&/ref:/{print $2; exit}' "$repo_root/.github/workflows/ci.yml")"
checkout_ref="$(runuser -u xibalba -- git -C "$sdk_root" rev-parse HEAD 2>/dev/null || true)"
if [[ "${SHIELD_ALLOW_UNPINNED_SDK:-}" != "1" && "$checkout_ref" != "$pinned_ref" ]]; then
  echo "integrity-core checkout is at ${checkout_ref:-unknown}, but Shield CI pins $pinned_ref." >&2
  echo "Use sudo ./scripts/sync_production_venv.sh (installs the pinned SDK), or bump the CI pin first." >&2
  exit 1
fi

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
