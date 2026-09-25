#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/test_disposable_responders.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${SHIELD_TEST_PYTHON:-/opt/xibalba-shield/venv/bin/python}"
[[ -x "$python_bin" ]] || python_bin="$(command -v python3)"

exec "$python_bin" "$repo_root/scripts/test_disposable_responders.py"
