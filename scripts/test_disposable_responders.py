#!/usr/bin/env python3
"""Development-only responder smoke test.

Exercises SIGSTOP/SIGCONT and SIGKILL against two disposable sleep processes.
It does not load a readiness artifact, alter the Shield service, or touch a
user workload. Production responder gates remain unchanged.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

from shield.agent_core.action_broker import ActionBroker
from shield.agent_core.readiness import BASE_PROOFS, ProductionReadiness


def disposable_readiness() -> ProductionReadiness:
    # This is intentionally in-memory and scoped to this smoke test. It is not
    # serialized, not accepted by shield run, and cannot unlock production.
    proofs = {key: True for key in BASE_PROOFS}
    proofs.update(kill_runtime_tested=True, cgroup_runtime_tested=True)
    return ProductionReadiness.from_mapping(proofs)


def main() -> int:
    if os.geteuid() != 0:
        print("Run with sudo: sudo ./scripts/test_disposable_responders.py", file=sys.stderr)
        return 1

    broker = ActionBroker(
        enable_destructive=True,
        readiness=disposable_readiness(),
    )

    frozen = subprocess.Popen(["/usr/bin/sleep", "30"])
    killed = subprocess.Popen(["/usr/bin/sleep", "30"])
    try:
        broker.freeze_process(frozen.pid)
        time.sleep(0.2)
        state = next((line for line in open(f"/proc/{frozen.pid}/status", encoding="ascii") if line.startswith("State:")), "")
        if "T" not in state:
            raise RuntimeError(f"disposable process was not stopped: {state.strip()}")
        broker.resume(frozen.pid)
        print(f"PASS freeze/resume: disposable pid {frozen.pid}")

        broker.kill_process(killed.pid)
        return_code = killed.wait(timeout=2)
        if return_code != -signal.SIGKILL:
            raise RuntimeError(f"disposable process exit code was {return_code}, expected {-signal.SIGKILL}")
        print(f"PASS kill: disposable pid {killed.pid} exited by SIGKILL")
        print("RESULT PASS — disposable responder mechanics work; production readiness remains unchanged.")
        return 0
    finally:
        if frozen.poll() is None:
            broker.resume(frozen.pid)
        if frozen.poll() is None:
            frozen.terminate()
            frozen.wait(timeout=2)
        if killed.poll() is None:
            killed.kill()
            killed.wait(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
