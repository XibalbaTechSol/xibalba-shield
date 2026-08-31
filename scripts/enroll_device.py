#!/usr/bin/env python3
"""Enroll this host with the local Shield backend and write a 0600 device config."""

from __future__ import annotations

import argparse
import json
import os
import socket
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen


CANONICAL_TENANT = "did:integrity:68fed1331613937555a59398223e8e87520a87dd0305aac4fd7ecdc32a14a861"
DEFAULT_CONFIG = Path.home() / ".xibalba-shield" / "device.json"


def enroll(*, backend_url: str, admin_token: str, tenant_id: str, device_id: str, device_role: str, output: Path) -> dict:
    payload = json.dumps({
        "tenant_id": tenant_id,
        "device_id": device_id,
        "device_role": device_role,
        "agent_label": "xibalba-shield",
        "base_url": backend_url.rstrip("/"),
    }).encode("utf-8")
    request = Request(
        f"{backend_url.rstrip('/')}/api/shield/enroll",
        data=payload,
        headers={"Accept": "application/json", "Content-Type": "application/json", "Authorization": f"Bearer {admin_token}"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        if not 200 <= getattr(response, "status", 200) < 300:
            raise RuntimeError(f"backend returned HTTP {response.status}")
        result = json.loads(response.read().decode("utf-8"))
    config = result.get("device_config")
    if not isinstance(config, dict) or not config.get("device_token"):
        raise RuntimeError("backend enrollment response did not contain a device token")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="device.", suffix=".json", dir=output.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, output)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-url", default=os.environ.get("SHIELD_BACKEND_URL", "http://127.0.0.1:8765"))
    parser.add_argument("--admin-token", default=os.environ.get("SHIELD_BACKEND_TOKEN", "dev-shield-admin"))
    parser.add_argument("--tenant-id", default=os.environ.get("SHIELD_TENANT_ID", CANONICAL_TENANT))
    parser.add_argument("--device-id", default=os.environ.get("SHIELD_DEVICE_ID", socket.gethostname()))
    parser.add_argument("--device-role", default=os.environ.get("SHIELD_DEVICE_ROLE", "workstation"))
    parser.add_argument("--output", type=Path, default=Path(os.environ.get("SHIELD_DEVICE_CONFIG", str(DEFAULT_CONFIG))))
    args = parser.parse_args()
    config = enroll(backend_url=args.backend_url, admin_token=args.admin_token, tenant_id=args.tenant_id, device_id=args.device_id, device_role=args.device_role, output=args.output)
    print(json.dumps({"device_id": config["device_id"], "tenant_id": config["tenant_id"], "config": str(args.output), "token_written": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
