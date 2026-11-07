"""In-memory provider for tests, demos, and development without an EDR tenant.

Every result it returns is marked ``simulated=True`` and its vendor is ``"simulated"`` so it
can never be mistaken for a real endpoint action in the ledger or the UI.
"""

from __future__ import annotations

from datetime import datetime

from .provider import ActionResult, Detection, EndpointProvider, Host, UnsupportedAction
from .response_gateway import ResponseIntent


class SimulatedProvider(EndpointProvider):
    vendor = "simulated"

    def __init__(self, *, hosts: list[Host] | None = None, detections: list[Detection] | None = None) -> None:
        self._hosts = {h.host_id: h for h in hosts or []}
        self._detections = {d.detection_id: d for d in detections or []}
        self.performed: list[ResponseIntent] = []

    def list_detections(self, *, since: datetime, limit: int = 100) -> list[Detection]:
        cutoff = since.isoformat()
        rows = [d for d in self._detections.values() if (d.created_at or "") >= cutoff]
        return sorted(rows, key=lambda d: d.created_at or "", reverse=True)[:limit]

    def get_detection(self, detection_id: str) -> Detection | None:
        return self._detections.get(detection_id)

    def get_host(self, host_id: str) -> Host | None:
        return self._hosts.get(host_id)

    def console_url(self, *, host_id: str | None = None, detection_id: str | None = None) -> str | None:
        return None

    def _perform(self, intent: ResponseIntent) -> ActionResult:
        host = self._hosts.get(intent.host_id)
        if host is None:
            return ActionResult(self.vendor, intent.action, intent.host_id, "failed", detail="unknown host", simulated=True)
        if intent.action in {"contain_host", "lift_containment"}:
            state = "contained" if intent.action == "contain_host" else "normal"
            self._hosts[host.host_id] = Host(
                host.vendor, host.host_id, host.hostname, host.platform, state, host.console_url, host.raw
            )
        elif intent.action not in {"kill_process", "quarantine_file", "rtr_command"}:
            raise UnsupportedAction(f"simulated provider does not implement {intent.action}")
        self.performed.append(intent)
        return ActionResult(
            self.vendor,
            intent.action,
            intent.host_id,
            "succeeded",
            vendor_reference=f"sim-{len(self.performed)}",
            simulated=True,
        )


__all__ = ["SimulatedProvider"]
