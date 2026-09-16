#!/usr/bin/env bash
set -euo pipefail

unit='xibalba-shield-cortex-outbox.service'
drop_in="/etc/systemd/system/${unit}.d/limits.conf"

if [[ "${EUID}" -ne 0 ]]; then
    exec sudo -- "$0" "$@"
fi

install -d -m 0755 "$(dirname "$drop_in")"
install -m 0644 /dev/stdin "$drop_in" <<'EOF'
[Unit]
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Environment=XIBALBA_CORTEX_OUTBOX_WORKERS=1
ExecStart=
ExecStart=/opt/xibalba-shield/venv/bin/python -m shield.cortex_outbox_worker --device-id xibalba-HP-Desktop-M01-F0xxx --batch-size 10 --interval 30
Restart=on-failure
RestartSec=30
TimeoutStopSec=10
MemoryMax=256M
MemorySwapMax=256M
CPUQuota=25%
TasksMax=64
LimitNOFILE=1024
EOF

systemctl daemon-reload
systemctl kill --signal=CONT "$unit" 2>/dev/null || true
systemctl stop "$unit"
systemctl reset-failed "$unit" 2>/dev/null || true
systemctl start "$unit"

systemctl show "$unit" \
    -p MainPID -p ActiveState -p SubState -p Restart \
    -p MemoryMax -p MemorySwapMax -p CPUQuotaPerSecUSec \
    -p TasksMax -p LimitNOFILE
