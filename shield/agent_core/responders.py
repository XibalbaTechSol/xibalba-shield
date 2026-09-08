"""Explicit responder contract for policy-approved enforcement actions.

Only process freezing is enabled by the current local proof.  Kill, cgroup,
and flow-block responders remain opt-in until each has a privileged runtime
test on the supported host matrix.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class ResponderDisabled(RuntimeError):
    """Raised when an action has no validated runtime implementation yet."""


@dataclass(frozen=True)
class ResponderCapabilities:
    freeze_process: bool = True
    kill_process: bool = False
    freeze_cgroup: bool = False
    block_flow: bool = False


class Responder(Protocol):
    capabilities: ResponderCapabilities

    def freeze_process(self, pid: int) -> Any: ...
    def kill_process(self, pid: int) -> Any: ...
    def freeze_cgroup(self, cgroup_path: str, *, pid: int = 0) -> Any: ...
    def block_flow(self, flow: dict[str, Any]) -> Any: ...


__all__ = ["Responder", "ResponderCapabilities", "ResponderDisabled"]
