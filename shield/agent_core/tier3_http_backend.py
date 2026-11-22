"""Generic HTTP Tier 3 provider adapter with fail-closed transport handling."""
from __future__ import annotations

import httpx

from shield.schemas.events import Decision, EscalationRequest, EscalationResponse
from shield.agent_core.tier3_backend import parse_verdict
from shield.agent_core.tier3_evidence import build_evidence


class HttpTier3Backend:
    """POST only bounded evidence; every transport or schema failure becomes uncertain."""
    def __init__(self, endpoint: str, *, timeout_seconds: float = 20.0, token: str = "") -> None:
        if not endpoint or timeout_seconds <= 0:
            raise ValueError("endpoint and positive timeout are required")
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.token = token

    def adjudicate(self, request: EscalationRequest) -> EscalationResponse:
        try:
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            response = httpx.post(self.endpoint, json=build_evidence(request), headers=headers,
                                  timeout=self.timeout_seconds)
            if response.status_code < 200 or response.status_code >= 300:
                return EscalationResponse(Decision("contain", tier="tier3"), verdict="uncertain", reason="http_error")
            body = response.json()
            if not isinstance(body, dict):
                raise ValueError("response must be an object")
            verdict = parse_verdict(body.get("verdict"))
            reason = body.get("reason", "") if isinstance(body.get("reason", ""), str) else ""
            result = EscalationResponse(Decision("contain", tier="tier3"), verdict=verdict, reason=reason[:512])
            process = getattr(request.event, "process", None)
            if process is not None and isinstance(getattr(process, "pid", None), int):
                result.pid = process.pid  # type: ignore[attr-defined]
                start = getattr(process, "start_time", 0)
                cgroup = getattr(process, "cgroup_id", 0)
                result.pid_identity = f"start:{start}:cgroup:{cgroup}"  # type: ignore[attr-defined]
            return result
        except Exception:  # noqa: BLE001 -- provider failure is fail-closed
            return EscalationResponse(Decision("contain", tier="tier3"), verdict="uncertain", reason="provider_unavailable")
