from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from shield.backend.api import make_handler
from shield.backend.store import ShieldStore


ADMIN = "test-admin-token"


def _start_backend(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    handler = make_handler(store=store, admin_token=ADMIN)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, store, f"http://127.0.0.1:{server.server_port}"


def _request(url, *, method="GET", body=None, token=ADMIN):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_backend_enrolls_device_and_serves_policy_to_existing_client_shape(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1", "device_role": "workstation"},
        )
        assert status == 201
        assert enrolled["device_config"]["tenant_policy_url"] == f"{base}/api/shield/policies/tenant-a/dev-1"
        assert enrolled["device_config"]["device_token"] == enrolled["device_token"]

        status, policy_meta = _request(
            f"{base}/api/shield/policies/tenant-a/dev-1",
            method="POST",
            body={"policy_version": "tenant-a-v1", "rules": []},
        )
        assert status == 200
        assert policy_meta["policy_hash"].startswith("sha256:")

        status, policy = _request(enrolled["device_config"]["tenant_policy_url"], token=enrolled["device_token"])
        assert status == 200
        assert policy["policy_version"] == "tenant-a-v1"
    finally:
        server.shutdown()
        store.close()


def test_backend_rejects_admin_api_without_admin_token(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        request = urllib.request.Request(f"{base}/api/shield/devices?tenant_id=tenant-a")
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("expected 401")
    finally:
        server.shutdown()
        store.close()


def test_backend_rejects_policy_distribution_without_device_token(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        _request(
            f"{base}/api/shield/policies/tenant-a/dev-1",
            method="POST",
            body={"policy_version": "tenant-a-v1", "rules": []},
        )
        request = urllib.request.Request(enrolled["device_config"]["tenant_policy_url"])
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("expected 401")
    finally:
        server.shutdown()
        store.close()


def test_backend_ingests_authenticated_decisions_and_metrics_for_dashboard(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        device_token = enrolled["device_token"]
        decision = {
            "class": "policy_decision",
            "device_id": "dev-1",
            "event_ref": {"class": "agent_event", "event_id": "evt-1"},
            "rule": {"rule_id": "deny-shadow", "name": "Deny", "version": "1.0.0"},
            "decision": {"action": "deny", "severity": "high", "reason": "demo"},
            "export": {"attempted": True, "decision_exported": True, "authorized": True},
            "synthetic": True,
        }

        status, decision_result = _request(
            f"{base}/api/shield/decisions",
            method="POST",
            token=device_token,
            body={"tenant_id": "tenant-a", "device_id": "dev-1", "decision": decision},
        )
        assert status == 201
        assert decision_result["id"] == 1

        status, metrics_result = _request(
            f"{base}/api/shield/metrics",
            method="POST",
            token=device_token,
            body={"tenant_id": "tenant-a", "device_id": "dev-1", "metrics": {"events_per_sec": 42, "max_rss_kb": 1024}},
        )
        assert status == 201
        assert metrics_result["id"] == 1

        _status, summary = _request(f"{base}/api/shield/dashboard-summary?tenant_id=tenant-a")
        assert summary["device_count"] == 1
        assert summary["decisions_by_action"] == {"deny": 1}
        assert summary["latest_decisions"][0]["decision"]["synthetic"] is True
        assert summary["latest_metrics"]["events_per_sec"] == 42
    finally:
        server.shutdown()
        store.close()


def test_backend_records_exporter_status_and_integrations(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        token = enrolled["device_token"]

        status, integration = _request(
            f"{base}/api/shield/integrations",
            method="POST",
            body={
                "tenant_id": "tenant-a",
                "integration_id": "splunk-main",
                "kind": "webhook",
                "config": {"url": "https://splunk.example/services/collector"},
            },
        )
        assert status == 201
        assert integration["integration_id"] == "splunk-main"

        status, _result = _request(
            f"{base}/api/shield/exporter-status",
            method="POST",
            token=token,
            body={
                "tenant_id": "tenant-a",
                "device_id": "dev-1",
                "status": {"did_registered": True, "oracle_readback": "ok"},
            },
        )
        assert status == 200

        _status, exporter_status = _request(f"{base}/api/shield/exporter-status?tenant_id=tenant-a")
        assert exporter_status["exporter_status"][0]["status"]["oracle_readback"] == "ok"

        _status, integrations = _request(f"{base}/api/shield/integrations?tenant_id=tenant-a")
        assert integrations["integrations"][0]["kind"] == "webhook"

        _status, summary = _request(f"{base}/api/shield/dashboard-summary?tenant_id=tenant-a")
        assert summary["exporter_status"][0]["status"]["did_registered"] is True
        assert summary["integrations"][0]["integration_id"] == "splunk-main"
    finally:
        server.shutdown()
        store.close()


def test_backend_demo_seed_populates_console_data(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        status, seeded = _request(f"{base}/api/shield/demo/seed", method="POST", body={"tenant_id": "demo-tenant"})
        assert status == 201
        assert seeded["seeded_decisions"] == 4
        assert seeded["policy_hash"].startswith("sha256:")

        _status, summary = _request(f"{base}/api/shield/dashboard-summary?tenant_id=demo-tenant")
        assert summary["device_count"] == 1
        assert summary["decisions_by_action"]["deny"] == 2
        assert summary["latest_metrics"]["synthetic"] is True
        assert summary["latest_decisions"][0]["decision"]["synthetic"] is True
    finally:
        server.shutdown()
        store.close()


def test_backend_device_token_is_tenant_scoped(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        request = urllib.request.Request(
            f"{base}/api/shield/metrics",
            data=json.dumps({"tenant_id": "tenant-b", "device_id": "dev-1", "metrics": {}}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {enrolled['device_token']}"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("expected tenant-scoped token rejection")
    finally:
        server.shutdown()
        store.close()


def test_backend_serves_xibalba_shield_console(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        with urllib.request.urlopen(f"{base}/xibalba-shield", timeout=5) as response:
            html = response.read().decode("utf-8")
        assert response.status == 200
        assert "Xibalba Shield" in html
        assert "Latest Decisions" in html
    finally:
        server.shutdown()
        store.close()
