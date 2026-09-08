"""Device-side executor for authenticated exporter remediation jobs."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import DeviceConfig
from .config.tls import build_client_context

logger = logging.getLogger("shield.remediation_worker")


@dataclass(frozen=True)
class RemediationResult:
    claimed: bool
    request_id: int | None = None
    status: str | None = None


class RemediationWorker:
    """Claims at most one job per watchdog tick and reports its terminal result."""

    def __init__(self, *, device_config: DeviceConfig, exporter: Any, timeout: float = 2.0) -> None:
        self._config = device_config
        self._exporter = exporter
        self._timeout = timeout

    def run_once(self) -> RemediationResult:
        job = self._claim()
        if job is None:
            return RemediationResult(claimed=False)

        request_id = int(job["id"])
        try:
            detail = self._execute(str(job["action"]))
        except Exception as exc:  # noqa: BLE001 -- failure must be recorded remotely
            logger.exception("remediation request %s failed", request_id)
            self._complete(request_id, status="failed", detail={"error": str(exc)})
            return RemediationResult(claimed=True, request_id=request_id, status="failed")

        self._complete(request_id, status="completed", detail=detail)
        return RemediationResult(claimed=True, request_id=request_id, status="completed")

    def _execute(self, action: str) -> dict[str, Any]:
        if action == "retry":
            result = self._exporter.replay_pending()
            return _jsonable(result)
        if action == "flush":
            self._exporter.flush()
            result = self._exporter.replay_pending()
            return {"telemetry_flushed": True, "spool": _jsonable(result)}
        if action == "reconnect":
            # The exporter uses request-scoped HTTP calls, not a persistent socket. A
            # replay is therefore the real reconnect operation: it opens a fresh request.
            result = self._exporter.replay_pending()
            return {"fresh_transport_attempt": True, "spool": _jsonable(result)}
        raise ValueError(f"unsupported remediation action: {action}")

    def _claim(self) -> dict[str, Any] | None:
        query = urlencode({"tenant_id": self._config.tenant_id, "device_id": self._config.device_id})
        payload = self._request("GET", f"/api/shield/exporter-remediation/next?{query}")
        return payload.get("request")

    def _complete(self, request_id: int, *, status: str, detail: dict[str, Any]) -> None:
        self._request(
            "POST",
            "/api/shield/exporter-remediation/complete",
            {"tenant_id": self._config.tenant_id, "device_id": self._config.device_id,
             "request_id": request_id, "status": status, "detail": detail},
        )

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            f"{self._config.backend_url.rstrip('/')}{path}", data=data, method=method,
            headers={"Authorization": f"Bearer {self._config.device_token}", "Content-Type": "application/json"},
        )
        try:
            context = build_client_context(self._config)
            kwargs = {"context": context} if context is not None else {}
            with urlopen(request, timeout=self._timeout, **kwargs) as response:  # noqa: S310 -- configured control plane
                return json.load(response)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RuntimeError(f"remediation control-plane request failed: {exc}") from exc


def _jsonable(value: Any) -> dict[str, Any]:
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    if isinstance(value, dict):
        return value
    return {"result": str(value)}
