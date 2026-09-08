#!/usr/bin/env bash
# Root-only live verification that the hardened confinement profile in
# packaging/systemd/xibalba-shield.service (2026-09-05: User=/Group=, ProtectSystem=strict,
# PrivateDevices, RestrictNamespaces, etc.) does not break real eBPF sensor attach.
#
# This is the checkable step docs/PRODUCTION_READINESS_PLAN.md §7 item 5's own unit-file
# comment names: SystemCallFilter=/MemoryDenyWriteExecute= were deliberately left OUT of
# the shipped unit because guessing whether they'd break BCC's userspace LLVM JIT (used by
# `BPF(text=...)` to compile the eBPF C source before loading it via the bpf() syscall) is
# exactly the kind of unverified claim this codebase's "no silent mocks" rule forbids. Every
# OTHER hardening directive in the unit IS replicated here and IS being verified for real.
#
# Usage: sudo scripts/verify_hardened_unit.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "verify_hardened_unit.sh must run as root (systemd-run needs it to set User=/capabilities)." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$REPO_ROOT/.venv/bin/python3}"
SERVICE_USER="${SERVICE_USER:-xibalba-shield}"

command -v systemd-run >/dev/null 2>&1 || {
  echo "systemd-run not found -- this verification needs a real systemd host." >&2
  exit 1
}
[ -x "$PYTHON_BIN" ] || {
  echo "Python interpreter not found or not executable: $PYTHON_BIN" >&2
  echo "(set PYTHON_BIN=... if this repo's venv lives somewhere other than .venv/)" >&2
  exit 1
}
if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
  echo "Service account '$SERVICE_USER' does not exist -- run scripts/install_linux_agent.sh first, or:" >&2
  echo "  groupadd --system $SERVICE_USER && useradd --system --gid $SERVICE_USER --no-create-home --shell /usr/sbin/nologin $SERVICE_USER" >&2
  exit 1
fi

echo "Running shield.sensors.ebpf.loader.self_test() (all 3 sensors) under the hardened confinement profile as $SERVICE_USER..."
systemd-run --pty --wait --collect \
  --unit="shield-hardening-verify-$$" \
  --working-directory="$REPO_ROOT" \
  --property=User="$SERVICE_USER" \
  --property=Group="$SERVICE_USER" \
  --property=NoNewPrivileges=true \
  --property=PrivateTmp=true \
  --property=PrivateDevices=true \
  --property=ProtectSystem=strict \
  --property=ProtectHome=read-only \
  --property=ProtectKernelTunables=true \
  --property=ProtectControlGroups=true \
  --property=ProtectClock=true \
  --property=ProtectHostname=true \
  --property=ProtectProc=invisible \
  --property=ProcSubset=pid \
  --property=LockPersonality=true \
  --property=RestrictSUIDSGID=true \
  --property=RestrictNamespaces=true \
  --property=RestrictRealtime=true \
  --property=RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6" \
  --property=SystemCallArchitectures=native \
  --property=UMask=0077 \
  --property=CapabilityBoundingSet="CAP_BPF CAP_PERFMON CAP_SYS_ADMIN" \
  --property=AmbientCapabilities="CAP_BPF CAP_PERFMON CAP_SYS_ADMIN" \
  "$PYTHON_BIN" -m shield.sensors.ebpf.loader

status=$?
if [ "$status" -eq 0 ]; then
  echo "PASS: all 3 sensors attached and observed a real event under the hardened profile."
else
  echo "FAIL: at least one sensor did not attach/observe under the hardened profile (exit $status)." >&2
  echo "Do not ship the confinement change in packaging/systemd/xibalba-shield.service until this passes." >&2
fi
exit "$status"
