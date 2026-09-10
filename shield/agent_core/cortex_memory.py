"""Optional redacted Cortex memory provider for Shield's hybrid agent path."""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from ..codex_agent import redact_event


class CortexMemoryProvider:
    """Best-effort cloud-memory sink; local Shield policy remains authoritative."""

    def __init__(self, *, base_url: str, token: str, agent_id: str, device_id: str, timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.agent_id = agent_id
        self.device_id = device_id
        self.timeout = timeout

    @classmethod
    def from_environment(cls, *, device_id: str, agent_id: str | None = None, base_url: str | None = None, token: str | None = None) -> "CortexMemoryProvider | None":
        base_url = (base_url or os.environ.get("XIBALBA_CORTEX_URL", "")).strip()
        token = (token or os.environ.get("XIBALBA_CORTEX_TOKEN", "")).strip()
        canonical_agent_id = (agent_id or os.environ.get("XIBALBA_AGENT_ID", "")).strip()
        if not (base_url and token and canonical_agent_id):
            return None
        return cls(base_url=base_url, token=token, agent_id=canonical_agent_id, device_id=device_id)

    def remember_event(self, event: Any, decision: Any) -> None:
        raw_event = event.to_dict() if hasattr(event, "to_dict") else {"class": type(event).__name__}
        payload = {
            "content": json.dumps(redact_event({"event": raw_event, "decision": getattr(decision, "to_dict", lambda: {})()}), sort_keys=True),
            "source": {
                "kind": "shield_event",
                "locator": f"shield://{self.device_id}/{getattr(getattr(decision, 'event_ref', None), 'event_id', 'event')}",
                "agent_id": self.agent_id,
                "metadata": {"device_id": self.device_id, "agent_name": "xibalba-shield", "redacted": True},
            },
            "status": "candidate",
            "evidence_class": "observed_event",
            "idempotency_key": f"shield:{self.device_id}:{getattr(getattr(decision, 'event_ref', None), 'event_id', id(event))}",
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/memory/propositions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout):
            return


__all__ = ["CortexMemoryProvider"]
