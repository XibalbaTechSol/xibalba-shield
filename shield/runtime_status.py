"""Best-effort publication of local Shield runtime health to the backend."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.request import Request, urlopen

from .config import DeviceConfig

logger = logging.getLogger("shield.runtime_status")


def publish_runtime_status(
    *,
    device_config: DeviceConfig,
    policy_status: dict[str, Any],
    opa_status: dict[str, Any],
    timeout: float = 1.0,
) -> bool:
    """Publish status without ever affecting local enforcement or process exit."""
    if not device_config.backend_url or not device_config.device_token:
        return False
    payload = {
        "tenant_id": device_config.tenant_id,
        "device_id": device_config.device_id,
        "status": {"policy": policy_status, "opa": opa_status},
    }
    request = Request(
        f"{device_config.backend_url.rstrip('/')}/api/shield/exporter-status",
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {device_config.device_token}",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            if not 200 <= getattr(response, "status", 200) < 300:
                raise OSError(f"backend returned HTTP {response.status}")
        return True
    except OSError as exc:
        logger.warning("runtime health publication failed: %s", exc)
        return False
