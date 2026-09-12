"""Best-effort publication of local Shield runtime health to the backend."""

from __future__ import annotations

import json
import logging
import queue
import threading
from typing import Any
from urllib.request import Request, urlopen

from .config import DeviceConfig
from .config.tls import build_client_context
from .device_assertion import device_auth_header

logger = logging.getLogger("shield.runtime_status")


class BackendEvidencePublisher:
    """Asynchronously publish local decisions/outcomes to the authenticated Shield UI.

    This is deliberately separate from Integrity/BCC export: a backend outage must never
    delay policy evaluation or OS containment, while a healthy local control plane should
    still receive real evidence immediately.
    """

    def __init__(self, device_config: DeviceConfig, *, queue_size: int = 2048, timeout: float = 0.5) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be positive")
        self.device_config = device_config
        self.timeout = timeout
        self._queue: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue(maxsize=queue_size)
        self._dropped = 0
        self._failures = 0
        threading.Thread(target=self._run, name="shield-backend-evidence", daemon=True).start()

    def publish_decision(self, decision: Any) -> None:
        self._enqueue("decisions", {"decision": decision.to_dict()})

    def publish_outcome(self, outcome: Any) -> None:
        self._enqueue("enforcement-outcomes", {"outcome": outcome.to_dict()})

    def health(self) -> dict[str, Any]:
        return {
            "queue_depth": self._queue.qsize(),
            "queue_dropped": self._dropped,
            "publish_failures": self._failures,
        }

    def _enqueue(self, endpoint: str, body: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait((endpoint, body))
        except queue.Full:
            self._dropped += 1
            logger.error("backend evidence queue full; dropping %s", endpoint)

    def _run(self) -> None:
        while True:
            endpoint, body = self._queue.get()
            try:
                self._post(endpoint, body)
            except Exception:  # noqa: BLE001 -- evidence publication never affects enforcement
                self._failures += 1
                logger.warning("backend evidence publication failed for %s", endpoint, exc_info=True)
            finally:
                self._queue.task_done()

    def _post(self, endpoint: str, body: dict[str, Any]) -> None:
        if not self.device_config.backend_url or not self.device_config.device_token:
            raise RuntimeError("backend URL/device token is not configured")
        payload = {
            "tenant_id": self.device_config.tenant_id,
            "device_id": self.device_config.device_id,
            **body,
        }
        request = Request(
            f"{self.device_config.backend_url.rstrip('/')}/api/shield/{endpoint}",
            data=json.dumps(payload, sort_keys=True).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": device_auth_header(
                    tenant_id=self.device_config.tenant_id,
                    device_id=self.device_config.device_id,
                    audience=self.device_config.backend_url.rstrip("/"),
                    device_token=self.device_config.device_token,
                ),
            },
            method="POST",
        )
        context = build_client_context(self.device_config)
        with urlopen(request, timeout=self.timeout, **({"context": context} if context else {})) as response:
            if not 200 <= getattr(response, "status", 200) < 300:
                raise OSError(f"backend returned HTTP {response.status}")


def publish_runtime_status(
    *,
    device_config: DeviceConfig,
    policy_status: dict[str, Any],
    opa_status: dict[str, Any],
    sensors_status: dict[str, Any] | None = None,
    exporter_status_detail: dict[str, Any] | None = None,
    did_preflight_detail: dict[str, Any] | None = None,
    responder_status: dict[str, Any] | None = None,
    settings_status: dict[str, Any] | None = None,
    timeout: float = 1.0,
) -> bool:
    """Publish status without ever affecting local enforcement or process exit."""
    if not device_config.backend_url or not device_config.device_token:
        return False
    status: dict[str, Any] = {"policy": policy_status, "opa": opa_status}
    if sensors_status is not None:
        status["sensors"] = sensors_status
    if exporter_status_detail is not None:
        status["exporter"] = exporter_status_detail
    if did_preflight_detail is not None:
        # A startup-time check (shield/integrity_exporter/preflight.py), not re-run every
        # tick -- DID load/reachability doesn't change on the timescale a watchdog tick
        # does, so this is the same value republished each tick rather than a fresh check.
        status["did_preflight"] = did_preflight_detail
    if responder_status is not None:
        status["responders"] = responder_status
    if settings_status is not None:
        status["settings"] = settings_status
    payload = {
        "tenant_id": device_config.tenant_id,
        "device_id": device_config.device_id,
        "status": status,
    }
    request = Request(
        f"{device_config.backend_url.rstrip('/')}/api/shield/exporter-status",
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": device_auth_header(
                tenant_id=device_config.tenant_id,
                device_id=device_config.device_id,
                audience=device_config.backend_url.rstrip("/"),
                device_token=device_config.device_token,
            ),
        },
        method="POST",
    )
    try:
        context = build_client_context(device_config)
        with urlopen(request, timeout=timeout, **({"context": context} if context else {})) as response:
            if not 200 <= getattr(response, "status", 200) < 300:
                raise OSError(f"backend returned HTTP {response.status}")
        return True
    except OSError as exc:
        logger.warning("runtime health publication failed: %s", exc)
        return False
