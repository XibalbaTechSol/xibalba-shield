#!/usr/bin/env bash
set -euo pipefail

python_bin=${PYTHON_BIN:-/opt/xibalba-shield/venv/bin/python}
unit=${UNIT:-xibalba-shield-cortex-outbox.service}

[[ -x "$python_bin" ]] || { echo "missing live Python: $python_bin" >&2; exit 1; }

"$python_bin" - <<'PY'
import inspect
import shield.agent_core.cortex_memory as provider
import shield.cortex_outbox_worker as worker

expected = {
    "outbox_max_bytes": 16 * 1024 * 1024,
    "outbox_max_flush_rows": 10,
    "outbox_max_workers": 1,
}
actual = {
    "outbox_max_bytes": getattr(provider, "_OUTBOX_MAX_BYTES", None),
    "outbox_max_flush_rows": getattr(provider, "_OUTBOX_MAX_FLUSH_ROWS", None),
    "outbox_max_workers": getattr(provider, "_OUTBOX_MAX_WORKERS", None),
}
if actual != expected:
    raise SystemExit(f"provider caps mismatch: {actual!r}")
if not hasattr(provider.CortexMemoryProvider, "_outbox_size_bytes"):
    raise SystemExit("provider storage ceiling is absent")
if "include_counts=False" not in inspect.getsource(worker.main):
    raise SystemExit("worker still performs aggregate flush counts")
print("provider=bounded-16MiB/10-rows/1-worker")
print("worker=aggregate-counts-disabled")
PY

systemctl show "$unit" \
    -p MainPID -p ExecMainStartTimestamp -p Restart -p ActiveState -p SubState \
    -p MemoryMax -p MemorySwapMax -p CPUQuotaPerSecUSec -p TasksMax -p LimitNOFILE
