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

# Refuse to deploy onto a venv that differs from the tested lock. --no-deps below keeps a
# deploy from changing dependencies; this makes sure it also doesn't hide drift that
# already happened (2026-09-27: an untested web3 8 stack and missing packages in /opt).
lock_req="$(mktemp /root/shield-lock-req.XXXXXX)"
trap 'rm -f "$lock_req"' EXIT
(cd "$repo_root" && runuser -u xibalba -- "$uv_bin" export --frozen --no-dev --no-hashes --no-emit-project --no-emit-package integrity-sdk) \
  | grep -vE '^#|^ ' > "$lock_req"
drift="$("$uv_bin" pip install --dry-run --python "$python_bin" -r "$lock_req" 2>&1 | grep -E '^ [+-]' || true)"
if [[ -n "$drift" ]]; then
  echo "Production venv differs from uv.lock:" >&2
  echo "$drift" >&2
  echo "Run sudo ./scripts/sync_production_venv.sh first (snapshot + lock sync + rollback)." >&2
  exit 1
fi

echo "Installing checkout code into $python_bin (dependencies and identity material unchanged)..."
"$uv_bin" pip install \
  --python "$python_bin" \
  --no-deps \
  --reinstall \
  --link-mode=copy \
  "$repo_root"

# --no-deps keeps dependency versions stable, so verify here that every dependency the
# checkout declares is actually present, and that runtime data files shipped in the
# package, before restarting the sensor. Missing jsonschema and unpackaged schema JSON both
# reached production this way (2026-09-27, C5 install).
if ! "$uv_bin" pip check --python "$python_bin"; then
  echo "Deployed venv has dependency incompatibilities (see above); run sync_production_venv.sh." >&2
  exit 1
fi
"$python_bin" -c "import shield.cli, shield.policy_engine.engine, shield.integrity_exporter, shield.hermes_contract, shield.network_contract, shield.hermes_transport, shield.hermes_analyst" \
  || { echo "Deployed package failed its import smoke test; not restarting the sensor." >&2; exit 1; }

# The systemd unit invokes this launcher directly; updating the Python package
# alone does not update its argument/env wiring.
install -m 0755 "$repo_root/packaging/systemd/xibalba-shield-run" /usr/local/bin/xibalba-shield-run

systemctl daemon-reload
systemctl restart xibalba-shield.service
systemctl is-active --quiet xibalba-shield.service

echo "Installed checkout and restarted Shield."
systemctl --no-pager --full status xibalba-shield.service | sed -n '1,18p'
