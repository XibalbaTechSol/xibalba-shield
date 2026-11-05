#!/usr/bin/env bash
# Xibalba Shield Hybrid Endpoint Installer
set -euo pipefail

BACKEND_URL="${SHIELD_BACKEND_URL:-https://xibalba-shield.onrender.com}"

printf '================================================================\n'
printf '  Installing Xibalba Shield Hybrid Protection Agent\n'
printf '================================================================\n'

if ! command -v python3 >/dev/null 2>&1; then
  printf 'Error: Python 3.12+ is required to install Xibalba Shield.\n' >&2
  exit 1
fi

if command -v uv >/dev/null 2>&1; then
  printf 'Installing via uv tool...\n'
  uv tool install --upgrade git+https://github.com/XibalbaTechSol/xibalba-shield.git || pip install --upgrade git+https://github.com/XibalbaTechSol/xibalba-shield.git
else
  printf 'Installing via pip...\n'
  pip install --upgrade git+https://github.com/XibalbaTechSol/xibalba-shield.git
fi

shield install --backend-url "$BACKEND_URL"
