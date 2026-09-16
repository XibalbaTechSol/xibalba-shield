#!/usr/bin/env bash
set -euo pipefail

# Deploy only the Cortex outbox provider/worker code into the existing live Shield
# virtualenv. This deliberately leaves device identity, configuration, and the
# durable outbox database untouched.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python_bin=${PYTHON_BIN:-/opt/xibalba-shield/venv/bin/python}
uv_bin=${UV_BIN:-/home/xibalba/.local/bin/uv}
unit=xibalba-shield-cortex-outbox.service
build_dir=$(mktemp -d /tmp/xibalba-shield-outbox.XXXXXX)
trap 'rm -rf "$build_dir"' EXIT

if [[ "${EUID}" -ne 0 ]]; then
    exec sudo -- "$0" "$@"
fi

[[ -x "$python_bin" ]] || { echo "missing live Python: $python_bin" >&2; exit 1; }
[[ -x "$uv_bin" ]] || { echo "missing uv installer: $uv_bin" >&2; exit 1; }

"$uv_bin" build --wheel --out-dir "$build_dir" "$repo_root"
wheel=$(find "$build_dir" -maxdepth 1 -type f -name 'xibalba_shield-*.whl' -print -quit)
[[ -n "$wheel" ]] || { echo "wheel build produced no artifact" >&2; exit 1; }
"$uv_bin" pip install --python "$python_bin" --no-deps --reinstall "$wheel"

"$python_bin" - <<'PY'
from shield.agent_core import cortex_memory

assert cortex_memory._OUTBOX_MAX_BYTES == 16 * 1024 * 1024
assert cortex_memory._OUTBOX_MAX_FLUSH_ROWS == 10
assert cortex_memory._OUTBOX_MAX_WORKERS == 1
print("installed Cortex outbox provider has 16 MiB / 10-row / 1-worker caps")
PY

systemctl restart "$unit"
systemctl show "$unit" \
    -p MainPID -p ActiveState -p SubState -p Restart \
    -p MemoryMax -p MemorySwapMax -p CPUQuotaPerSecUSec \
    -p TasksMax -p LimitNOFILE
