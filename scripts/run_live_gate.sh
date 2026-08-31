#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${ROOT_DIR}/artifacts/live-gate"
mkdir -p "${ARTIFACT_DIR}"
cd "${ROOT_DIR}"

UV_BIN="$(command -v uv || true)"
if [[ -z "${UV_BIN}" ]]; then
  echo "uv is required but was not found on the caller PATH" >&2
  exit 1
fi

echo "== Shield live gate =="
echo "host: $(hostname)"
echo "kernel: $(uname -r)"
echo "artifacts: ${ARTIFACT_DIR}"

echo "[1/4] TCP-connect eBPF verification"
sudo -E "${UV_BIN}" run python scripts/verify_tcp_connect_root.py \
  2>&1 | tee "${ARTIFACT_DIR}/tcp-connect-root.log"

echo "[2/4] root eBPF tests"
sudo -E "${UV_BIN}" run pytest -q tests/test_ebpf_sensor.py \
  2>&1 | tee "${ARTIFACT_DIR}/ebpf-tests.log"

echo "[3/4] full Shield regression suite"
"${UV_BIN}" run pytest -q \
  2>&1 | tee "${ARTIFACT_DIR}/pytest.log"

echo "[4/4] pilot-gate JSON report"
"${UV_BIN}" run python scripts/e2e_validate.py --json \
  2>&1 | tee "${ARTIFACT_DIR}/e2e-validate.json"

echo "Live-gate artifacts written to ${ARTIFACT_DIR}"
