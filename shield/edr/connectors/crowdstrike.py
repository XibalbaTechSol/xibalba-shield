"""CrowdStrike Falcon connector built on the official ``crowdstrike-falconpy`` SDK.

falconpy is consumed as an optional dependency (``pip install 'xibalba-shield[crowdstrike]'``),
never vendored or forked. Credentials are read by the caller from the environment or a
secret store and passed in; this module never logs or returns them.

Status: written against falconpy 1.6.x documented operations (``Hosts.perform_action``,
``Hosts.get_device_details``, ``Alerts.query_alerts_v2`` / ``get_alerts_v2``) and tested
against recorded response shapes only. It has not yet been exercised against a live Falcon
tenant. Actions beyond host containment raise :class:`UnsupportedAction` until they are
implemented and verified.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..provider import ActionResult, Detection, EndpointProvider, Host, UnsupportedAction, normalize_severity
from ..response_gateway import ResponseIntent

CONSOLE_BASE = {
    "us-1": "https://falcon.crowdstrike.com",
    "us-2": "https://falcon.us-2.crowdstrike.com",
    "eu-1": "https://falcon.eu-1.crowdstrike.com",
    "us-gov-1": "https://falcon.laggar.gcw.crowdstrike.com",
}
_CONTAINMENT = {
    "normal": "normal",
    "contained": "contained",
    "containment_pending": "pending",
    "lift_containment_pending": "pending",
}
_ACTION_NAMES = {"contain_host": "contain", "lift_containment": "lift_containment"}


class CrowdStrikeError(RuntimeError):
    """A Falcon API call returned a non-success status."""


class CrowdStrikeConnector(EndpointProvider):
    vendor = "crowdstrike"

    def __init__(self, *, hosts: Any, alerts: Any, cloud: str = "us-1") -> None:
        """Construct from falconpy service objects (or test doubles with the same methods)."""
        if cloud not in CONSOLE_BASE:
            raise ValueError(f"cloud must be one of: {', '.join(sorted(CONSOLE_BASE))}")
        self._hosts = hosts
        self._alerts = alerts
        self._cloud = cloud

    @classmethod
    def from_credentials(cls, *, client_id: str, client_secret: str, cloud: str = "us-1") -> "CrowdStrikeConnector":
        try:
            from falconpy import Alerts, Hosts
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError("install the 'crowdstrike' extra to use the CrowdStrike connector") from exc
        auth = {"client_id": client_id, "client_secret": client_secret, "base_url": cloud}
        return cls(hosts=Hosts(**auth), alerts=Alerts(**auth), cloud=cloud)

    # -- reads -------------------------------------------------------------------------

    def list_detections(self, *, since: datetime, limit: int = 100) -> list[Detection]:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        stamp = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ids = _resources(
            self._alerts.query_alerts_v2(
                filter=f"created_timestamp:>'{stamp}'", sort="created_timestamp.desc", limit=max(1, min(limit, 1000))
            )
        )
        if not ids:
            return []
        return [self._detection(r) for r in _resources(self._alerts.get_alerts_v2(composite_ids=ids))]

    def get_detection(self, detection_id: str) -> Detection | None:
        rows = _resources(self._alerts.get_alerts_v2(composite_ids=[detection_id]))
        return self._detection(rows[0]) if rows else None

    def get_host(self, host_id: str) -> Host | None:
        rows = _resources(self._hosts.get_device_details(ids=[host_id]))
        if not rows:
            return None
        row = rows[0]
        return Host(
            vendor=self.vendor,
            host_id=str(row.get("device_id") or host_id),
            hostname=row.get("hostname"),
            platform=row.get("platform_name"),
            containment=_CONTAINMENT.get(str(row.get("status") or ""), "unknown"),
            console_url=self.console_url(host_id=host_id),
            raw=row,
        )

    def console_url(self, *, host_id: str | None = None, detection_id: str | None = None) -> str | None:
        # Console hosts per cloud are documented; the deep-link paths below are best-effort and
        # must be confirmed against a live tenant. Detections prefer the API's falcon_host_link.
        base = CONSOLE_BASE[self._cloud]
        if detection_id:
            return f"{base}/unified-detections/{detection_id}"
        if host_id:
            return f"{base}/host-management/hosts/{host_id}"
        return base

    # -- writes (only reachable through EndpointProvider.execute) ---------------------

    def _perform(self, intent: ResponseIntent) -> ActionResult:
        action_name = _ACTION_NAMES.get(intent.action)
        if action_name is None:
            raise UnsupportedAction(f"CrowdStrike connector does not implement {intent.action} yet")
        response = self._hosts.perform_action(action_name=action_name, ids=[intent.host_id])
        status = int(response.get("status_code", 0)) if isinstance(response, dict) else 0
        resources = _body(response).get("resources") or []
        if 200 <= status < 300:
            ref = str(resources[0].get("id")) if resources and isinstance(resources[0], dict) else None
            return ActionResult(self.vendor, intent.action, intent.host_id, "pending", vendor_reference=ref)
        return ActionResult(self.vendor, intent.action, intent.host_id, "failed", detail=_errors(response))

    def _detection(self, row: dict[str, Any]) -> Detection:
        device = row.get("device") or {}
        detection_id = str(row.get("composite_id") or row.get("id") or "")
        return Detection(
            vendor=self.vendor,
            detection_id=detection_id,
            host_id=device.get("device_id"),
            severity=normalize_severity(row.get("severity_name") or row.get("severity")),
            title=row.get("display_name") or row.get("name") or row.get("description"),
            created_at=row.get("created_timestamp"),
            console_url=row.get("falcon_host_link") or self.console_url(detection_id=detection_id),
            raw=row,
        )


def _body(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise CrowdStrikeError("unexpected Falcon API response type")
    body = response.get("body")
    return body if isinstance(body, dict) else {}


def _resources(response: Any) -> list[Any]:
    status = int(response.get("status_code", 0)) if isinstance(response, dict) else 0
    if not 200 <= status < 300:
        raise CrowdStrikeError(f"Falcon API returned {status}: {_errors(response)}")
    return list(_body(response).get("resources") or [])


def _errors(response: Any) -> str:
    try:
        errors = _body(response).get("errors") or []
    except CrowdStrikeError:
        return "unexpected response"
    messages = [str(e.get("message")) for e in errors if isinstance(e, dict) and e.get("message")]
    return "; ".join(messages) or "no error detail"


__all__ = ["CONSOLE_BASE", "CrowdStrikeConnector", "CrowdStrikeError"]
