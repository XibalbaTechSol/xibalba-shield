from __future__ import annotations

import json
import threading
import urllib.request

from http.server import ThreadingHTTPServer

from shield.backend.api import make_handler
from shield.backend.settings import settings_version, validate_settings
from shield.backend.store import ShieldStore


def _request(url, *, method="GET", body=None, token="admin"):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    with urllib.request.urlopen(urllib.request.Request(url, data=data, method=method, headers=headers), timeout=5) as response:
        return response.status, json.loads(response.read())


def test_settings_validation_and_version_are_deterministic():
    settings = {"containmentMode": "approval", "approvalThreshold": 75, "guardrailToolCalls": True}
    assert validate_settings(settings) == settings
    assert settings_version(settings) == settings_version({"guardrailToolCalls": True, "approvalThreshold": 75, "containmentMode": "approval"})
    try:
        validate_settings({"unknown": True})
    except ValueError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("unknown settings must be rejected")


def test_change_request_approval_and_rollback_are_audited(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.put_tenant_settings(tenant_id="tenant-a", settings={"containmentMode": "audit"}, actor_id="seed")
    request = store.create_settings_change_request(
        tenant_id="tenant-a", category="containment", proposed_settings={"containmentMode": "approval"}, requested_by="operator"
    )
    assert request["status"] == "pending"
    approved = store.decide_settings_change_request(tenant_id="tenant-a", request_id=request["request_id"], approver_id="reviewer", approve=True)
    assert approved["status"] == "approved"
    assert store.get_tenant_settings(tenant_id="tenant-a")["containmentMode"] == "approval"
    rolled = store.rollback_settings_change_request(tenant_id="tenant-a", request_id=request["request_id"], actor_id="reviewer")
    assert rolled["status"] == "rolled_back"
    assert store.get_tenant_settings(tenant_id="tenant-a")["containmentMode"] == "audit"
    assert {entry["source"] for entry in store.list_tenant_settings_audit(tenant_id="tenant-a")} >= {"ui", "approval", "rollback"}


def test_authenticated_device_settings_distribution(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    handler = make_handler(store=store, admin_token="admin")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        _, enrolled = _request(f"{base}/api/shield/enroll", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-1"})
        _request(f"{base}/api/shield/settings", method="POST", body={"tenant_id": "tenant-a", "settings": {"sensorCadence": "25"}})
        status, payload = _request(
            f"{base}/api/shield/device-settings?tenant_id=tenant-a&device_id=dev-1", token=enrolled["device_token"]
        )
        assert status == 200
        assert payload["settings"] == {"sensorCadence": "25"}
        assert payload["settings_version"].startswith("sha256:")
    finally:
        server.shutdown()
        thread.join(timeout=2)
