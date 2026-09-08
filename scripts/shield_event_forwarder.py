"""
Shield Local Event Forwarder

Continuously monitors ~/.xibalba-shield/decisions.jsonl and forwards new
decisions and enforcement outcomes to the local Shield control plane backend.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path

DECISIONS_PATH = Path.home() / ".xibalba-shield" / "decisions.jsonl"
BACKEND_URL = os.environ.get("SHIELD_BACKEND_URL", "http://127.0.0.1:8421").rstrip("/")
TENANTS = [t.strip() for t in os.environ.get("SHIELD_TENANTS", "tenant-a,dev-tenant").split(",") if t.strip()]
DEVICE_ID = os.environ.get("SHIELD_DEVICE_ID", "xibalba-desktop")
DEVICE_TOKEN = os.environ.get("SHIELD_DEVICE_TOKEN", "dev")


def post_json(endpoint: str, data: dict, tenant_id: str) -> bool:
    url = f"{BACKEND_URL}{endpoint}"
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {DEVICE_TOKEN}",
            "X-Shield-Tenant-ID": tenant_id,
            "X-Shield-Device-ID": DEVICE_ID,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status in (200, 201)
    except Exception as exc:
        print(f"Forwarder failed to post {endpoint} for {tenant_id}: {exc}")
        return False


def forward_decision(record: dict) -> None:
    rec_copy = dict(record)
    rec_copy["device_id"] = DEVICE_ID

    decision_info = rec_copy.get("decision", {})
    action = decision_info.get("action", "allow")
    event_ref = rec_copy.get("event_ref", {})
    event_id = event_ref.get("event_id", f"evt-{int(time.time()*1000)}")

    outcome = {
        "event_id": event_id,
        "device_id": DEVICE_ID,
        "action": action,
        "completed": True,
        "escalated": (action == "escalate"),
        "error": decision_info.get("reason", ""),
        "target": rec_copy.get("rule", {}).get("name", "Security Engine"),
        "time": rec_copy.get("time", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        "decision": action,
    }

    for tenant in TENANTS:
        post_json(
            "/api/shield/decisions",
            {
                "tenant_id": tenant,
                "device_id": DEVICE_ID,
                "decision": rec_copy,
            },
            tenant,
        )
        post_json(
            "/api/shield/enforcement-outcomes",
            {
                "tenant_id": tenant,
                "device_id": DEVICE_ID,
                "outcome": outcome,
            },
            tenant,
        )


def tail_events() -> None:
    print(f"Starting Shield event forwarder for {DEVICE_ID} -> {BACKEND_URL} ({TENANTS})...")
    if not DECISIONS_PATH.exists():
        DECISIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
        DECISIONS_PATH.touch()

    with open(DECISIONS_PATH, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                forward_decision(record)
                print(f"Forwarded decision {record.get('event_ref', {}).get('event_id')} ({record.get('decision', {}).get('action')})")
            except Exception as exc:
                print(f"Error parsing event: {exc}")


if __name__ == "__main__":
    tail_events()
