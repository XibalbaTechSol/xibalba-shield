"""Bounded process containment for Agent Core.

The broker is deliberately separate from policy evaluation. A caller supplies an already
authorized action and this module performs only the narrow OS operation requested. The default
process path is resumable: SIGSTOP freezes a process and SIGCONT resumes it. SIGKILL is available
only through explicit escalation after the caller's timeout has elapsed.
"""

from __future__ import annotations

import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .readiness import ProductionReadiness
from .responders import ResponderCapabilities, ResponderDisabled


@dataclass(frozen=True)
class ActionResult:
    pid: int
    action: str
    method: str
    completed: bool
    escalated: bool = False
    cgroup_path: str | None = None
    error: str | None = None


class ActionBroker:
    """Execute bounded containment actions for a single target process."""

    def __init__(
        self,
        *,
        kill: Callable[[int, int], None] = os.kill,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        enable_destructive: bool = False,
        enable_cgroup: bool = False,
        enable_network: bool = False,
        block_network: Callable[[dict[str, object]], str] | None = None,
        readiness: ProductionReadiness | None = None,
    ) -> None:
        self._kill = kill
        self._monotonic = monotonic
        self._sleep = sleep
        self._enable_destructive = enable_destructive
        self._enable_cgroup = enable_cgroup
        self._block_network = block_network
        self.readiness = readiness or ProductionReadiness.from_mapping()
        self.capabilities = ResponderCapabilities(
            kill_process=enable_destructive and self.readiness.allowed("kill_process"),
            freeze_cgroup=enable_cgroup and self.readiness.allowed("freeze_cgroup"),
            block_flow=enable_network and block_network is not None and self.readiness.allowed("block_flow"),
        )

    def status(self) -> dict[str, object]:
        """Return the operator-visible gate and effective responder capabilities."""
        return {"capabilities": self.capabilities.__dict__, "readiness": self.readiness.as_dict()}

    @staticmethod
    def _validate_pid(pid: int) -> None:
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
            raise ValueError("pid must be an integer greater than 1")

    @staticmethod
    def _cgroup_freeze_file(cgroup_path: str | os.PathLike[str]) -> Path:
        path = Path(cgroup_path)
        if not path.is_dir():
            raise ValueError(f"cgroup path is not a directory: {path}")
        freeze_file = path / "cgroup.freeze"
        if not freeze_file.is_file():
            raise ValueError(f"cgroup freezer is unavailable: {freeze_file}")
        return freeze_file

    def freeze(self, pid: int, *, cgroup_path: str | os.PathLike[str] | None = None) -> ActionResult:
        """Freeze a process, preferring cgroup v2 when explicitly requested."""
        self._validate_pid(pid)
        if cgroup_path is not None:
            if not self.capabilities.freeze_cgroup:
                raise ResponderDisabled("freeze_cgroup is disabled until every production readiness proof passes")
            freeze_file = self._cgroup_freeze_file(cgroup_path)
            freeze_file.write_text("1\n", encoding="ascii")
            return ActionResult(pid, "freeze", "cgroup.freeze", True, cgroup_path=str(freeze_file.parent))
        self._kill(pid, signal.SIGSTOP)
        return ActionResult(pid, "freeze", "SIGSTOP", True)

    def freeze_process(self, pid: int) -> ActionResult:
        """Validated responder entry point for process freezing."""
        return self.freeze(pid)

    def kill_process(self, pid: int) -> ActionResult:
        """Destructive responder reserved until a live kill gate is approved."""
        self._validate_pid(pid)
        if not self.capabilities.kill_process:
            raise ResponderDisabled("kill_process is disabled until every production readiness proof passes")
        self._kill(pid, signal.SIGKILL)
        return ActionResult(pid, "terminate", "SIGKILL", True)

    def freeze_cgroup(self, cgroup_path: str | os.PathLike[str], *, pid: int = 0) -> ActionResult:
        """Cgroup freeze responder reserved until its runtime gate passes."""
        if not self.capabilities.freeze_cgroup:
            raise ResponderDisabled("freeze_cgroup is disabled until every production readiness proof passes")
        freeze_file = self._cgroup_freeze_file(cgroup_path)
        freeze_file.write_text("1\n", encoding="ascii")
        return ActionResult(pid, "freeze", "cgroup.freeze", True, cgroup_path=str(freeze_file.parent))

    def block_flow(self, flow: dict[str, object]) -> ActionResult:
        """Install a validated, scoped network block through the configured adapter."""
        if not self.capabilities.block_flow or self._block_network is None:
            raise ResponderDisabled("block_flow is disabled until every production readiness proof passes")
        pid = flow.get("pid", 0)
        if not isinstance(pid, int) or isinstance(pid, bool) or pid < 0:
            raise ValueError("flow pid must be a non-negative integer")
        method = self._block_network(flow)
        return ActionResult(pid, "block_flow", method, True)

    def resume(self, pid: int, *, cgroup_path: str | os.PathLike[str] | None = None) -> ActionResult:
        """Resume a previously frozen process without terminating it."""
        self._validate_pid(pid)
        if cgroup_path is not None:
            freeze_file = self._cgroup_freeze_file(cgroup_path)
            freeze_file.write_text("0\n", encoding="ascii")
            return ActionResult(pid, "resume", "cgroup.freeze", True, cgroup_path=str(freeze_file.parent))
        self._kill(pid, signal.SIGCONT)
        return ActionResult(pid, "resume", "SIGCONT", True)

    def escalate_to_kill(
        self,
        pid: int,
        *,
        timeout_seconds: float,
        cgroup_path: str | os.PathLike[str] | None = None,
    ) -> ActionResult:
        """Wait for the caller's timeout, then terminate the frozen process.

        This method does not poll process state: a broker caller owns the policy decision and
        timeout. Waiting here makes the ordering explicit and prevents an accidental immediate
        SIGKILL fallback.
        """
        self._validate_pid(pid)
        if not self.capabilities.kill_process:
            raise ResponderDisabled("kill_process is disabled until every production readiness proof passes")
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must be non-negative")
        deadline = self._monotonic() + timeout_seconds
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                break
            self._sleep(remaining)
        self._kill(pid, signal.SIGKILL)
        return ActionResult(pid, "terminate", "SIGKILL", True, escalated=True, cgroup_path=str(cgroup_path) if cgroup_path else None)

    def contain(
        self,
        pid: int,
        *,
        timeout_seconds: float | None = None,
        cgroup_path: str | os.PathLike[str] | None = None,
    ) -> ActionResult:
        """Freeze immediately; optionally escalate to SIGKILL only after a timeout."""
        result = self.freeze(pid, cgroup_path=cgroup_path)
        if timeout_seconds is None:
            return result
        return self.escalate_to_kill(pid, timeout_seconds=timeout_seconds, cgroup_path=cgroup_path)


__all__ = ["ActionBroker", "ActionResult"]
