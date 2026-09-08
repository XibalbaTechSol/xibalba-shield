#!/usr/bin/env python3
"""Runs the real chaos/adversarial test suite and produces a JSON artifact
`scripts/pilot_gate_report.py`'s adversarial gate can consume -- same pattern as
`scripts/burn_in.py` producing a real, checkable artifact rather than requiring an
operator to hand-type a self-attestation (see `_installer_gate`/`_hardening_gate`'s
documented stub status in `docs/PRODUCTION_READINESS_PLAN.md` §7 item 6 for what this
is deliberately NOT doing).

This does not itself contain any adversarial logic -- it runs
`tests/test_chaos_adversarial.py` (real pytest, real assertions) and reports whether it
passed, alongside a pointer to the threat-model matrix
(docs/design/threat-model-matrix-2026-09-06.md) a human reviewer needs for Gate 6's "no
unexplained critical bypasses" criterion, which a passing test run alone cannot fully
attest to (PID reuse, for one, is disclosed there as not independently tested).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_FILE = "tests/test_chaos_adversarial.py"
THREAT_MODEL_MATRIX = "docs/design/threat-model-matrix-2026-09-06.md"


def run_adversarial_tests(*, python_bin: str = sys.executable) -> dict:
    started = time.time()
    result = subprocess.run(
        [python_bin, "-m", "pytest", TEST_FILE, "-v", "--tb=short"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    duration = time.time() - started
    passed = result.returncode == 0
    return {
        "status": "pass" if passed else "fail",
        "test_file": TEST_FILE,
        "threat_model_matrix": THREAT_MODEL_MATRIX,
        "returncode": result.returncode,
        "duration_sec": round(duration, 2),
        "reason": "all chaos/adversarial tests passed" if passed
        else f"pytest exited {result.returncode} -- see stdout_tail",
        "stdout_tail": result.stdout[-4000:],
        "stderr_tail": result.stderr[-2000:],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/run_adversarial_tests.py")
    parser.add_argument("--out", type=Path, required=True, help="destination JSON artifact path")
    parser.add_argument("--python-bin", default=sys.executable)
    args = parser.parse_args(argv)

    report = run_adversarial_tests(python_bin=args.python_bin)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
