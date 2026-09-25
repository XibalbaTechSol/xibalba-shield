from __future__ import annotations

import json
import threading
import urllib.request
import urllib.error

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


def test_hermes_agent_settings_are_bounded_and_analysis_only():
    settings = validate_settings({
        "hermesEnabled": True,
        "hermesAgentId": "did:integrity:hermes-shield",
        "hermesTransport": "local-spool",
        "hermesAnalysisOnly": True,
        "hermesRedactionMode": "strict",
        "hermesEventScope": "all",
        "hermesSpoolPath": "/var/lib/xibalba-shield/hermes",
        "hermesKeyPath": "/etc/xibalba-shield/secrets/hermes-spool.key",
        "hermesMaxBatch": 10,
        "hermesSpoolMaxBytes": 16 * 1024 * 1024,
        "hermesAutoRetry": True,
    })
    assert settings["hermesAnalysisOnly"] is True

    for invalid in ({"hermesAnalysisOnly": False}, {"hermesMaxBatch": 11}, {"hermesSpoolMaxBytes": 1024}):
        try:
            validate_settings(invalid)
        except ValueError:
            continue
        raise AssertionError("invalid Hermes settings must be rejected")


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


def test_authenticated_network_config_round_trip_is_validated(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    handler = make_handler(store=store, admin_token="admin")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    config = {
        "zones": [
            {"zone_id": "mgmt", "kind": "management", "protected": True},
            {"zone_id": "recovery", "kind": "recovery", "protected": True},
        ],
        "protected_paths": ["sha256:" + "1" * 64],
        "adapter_actions": {"lab": ["block_flow"]},
    }
    try:
        status, saved = _request(f"{base}/api/shield/network/config", method="POST", body={"tenant_id": "tenant-network", "config": config})
        assert status == 202
        request_id = saved["request"]["request_id"]
        status, approved = _request(f"{base}/api/shield/network/config/change-requests/{request_id}", method="POST", body={"tenant_id": "tenant-network", "action": "approve"})
        assert status == 200
        assert approved["status"] == "approved"
        status, payload = _request(f"{base}/api/shield/network/config?tenant_id=tenant-network")
        assert status == 200
        assert payload["config"] == config
        status, rolled = _request(f"{base}/api/shield/network/config/change-requests/{request_id}", method="POST", body={"tenant_id": "tenant-network", "action": "rollback"})
        assert status == 200
        assert rolled["status"] == "rolled_back"
        try:
            _request(f"{base}/api/shield/network/config", method="POST", body={"tenant_id": "tenant-network", "config": {"token": "secret"}})
        except urllib.error.HTTPError as exc:
            bad_status = exc.code
        else:
            bad_status = 200
        assert bad_status == 400
    finally:
        server.shutdown()
        thread.join(timeout=2)
