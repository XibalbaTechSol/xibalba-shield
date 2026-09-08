#!/usr/bin/env bash
set -euo pipefail

# Compatibility wrapper. The canonical gate owns privilege checks, cleanup, logs,
# and pass/fail propagation; never weaken home-directory permissions here.
exec "$(dirname "$0")/scripts/run_live_gate.sh" "$@"
