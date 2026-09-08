#!/usr/bin/env python3
"""Root-only live verification runner for the file-write eBPF sensor.

This script is intentionally independent of pytest so an operator can run it on a target
kernel with only the installed Shield package and BCC runtime available. Mirrors
`verify_tcp_connect_root.py`'s shape, added for evidence-script parity across all three
sensors (`docs/SUPPORTED_MATRIX.md`'s per-kernel closing procedure).
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def main() -> int:
    report = {
        "check": "file_write_root_verification",
        "requires_root": True,
        "command": "python3 scripts/verify_file_write_root.py",
    }
    if os.geteuid() != 0:
        report.update({"status": "blocked", "reason": "must run as root or with CAP_BPF/CAP_PERFMON"})
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2

    try:
        from shield.sensors.ebpf.loader import self_test_file_write

        rc = self_test_file_write(seconds=5)
    except Exception as exc:  # noqa: BLE001 - operator-facing verification should report the blocker
        report.update(
            {
                "status": "fail",
                "returncode": 1,
                "reason": str(exc),
                "stage": getattr(exc, "stage", None),
                "traceback_tail": traceback.format_exc()[-2000:],
            }
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    report.update(
        {
            "status": "pass" if rc == 0 else "fail",
            "returncode": rc,
            "reason": "observed this process's real write-open" if rc == 0 else "did not observe real write-open",
        }
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
