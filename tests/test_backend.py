from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

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


def test_backend_evaluates_authenticated_transaction_intent_without_broadcasting(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-1"}
        )
        _request(
            f"{base}/api/shield/policies/tenant-a/dev-1",
            method="POST",
            body={
                "policy_version": "tx-v1",
                "transaction_policy": {
                    "allowed_chain_ids": [84532],
                    "allowed_contracts": ["0x1111111111111111111111111111111111111111"],
                    "allowed_function_selectors": ["0xa9059cbb"],
                    "max_token_amount": 1000,
                    "max_slippage_bps": 100,
                },
                "rules": [],
            },
        )
        status, result = _request(
            f"{base}/api/shield/transaction-intents",
            method="POST",
            token=enrolled["device_token"],
            body={
                "tenant_id": "tenant-a",
                "device_id": "dev-1",
                "agent_id": "agent-1",
                "request_id": "req-1",
                "chain_id": 84532,
                "to": "0x1111111111111111111111111111111111111111",
                "function_selector": "0xa9059cbb",
                "token_amount": 100,
                "slippage_bps": 50,
            },
        )
        assert status == 200
        assert result["decision"]["action"] == "allow"
        assert result["decision"]["execution"] == "not_broadcast"
    finally:
        server.shutdown()
        store.close()


def test_backend_simulates_only_after_policy_allows(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-1"}
        )
        _request(
            f"{base}/api/shield/policies/tenant-a/dev-1",
            method="POST",
            body={
                "policy_version": "tx-v1",
                "transaction_policy": {
                    "allowed_chain_ids": [84532],
                    "allowed_contracts": ["0x1111111111111111111111111111111111111111"],
                    "allowed_function_selectors": ["0xa9059cbb"],
                    "max_token_amount": 1000,
                },
                "rules": [],
            },
        )
        body = {
            "tenant_id": "tenant-a", "device_id": "dev-1", "agent_id": "agent-1", "request_id": "req-1",
            "chain_id": 84532, "to": "0x1111111111111111111111111111111111111111",
            "function_selector": "0xa9059cbb", "calldata": "0xa9059cbb" + "00" * 32,
        }
        with patch("shield.backend.api.simulate_transaction_intent") as simulate:
            simulate.return_value.as_dict.return_value = {
                "chain_id": 84532, "gas_estimate": 21000, "status": "simulated", "execution": "not_broadcast"
            }
            status, result = _request(
                f"{base}/api/shield/transaction-simulations", method="POST", token=enrolled["device_token"], body=body
            )
        assert status == 200
        assert result["decision"]["action"] == "allow"
        assert result["simulation"]["gas_estimate"] == 21000
        simulate.assert_called_once()
    finally:
        server.shutdown()
        store.close()


def test_backend_binds_human_approval_to_escalated_intent_hash(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-1"}
        )
        token = enrolled["device_token"]
        _request(
            f"{base}/api/shield/policies/tenant-a/dev-1",
            method="POST",
            body={
                "policy_version": "tx-v1",
                "transaction_policy": {
                    "allowed_chain_ids": [84532],
                    "allowed_contracts": ["0x1111111111111111111111111111111111111111"],
                    "allowed_function_selectors": ["0xa9059cbb"],
                    "max_token_amount": 1000,
                    "require_approval": True,
                },
                "rules": [],
            },
        )
        intent = {
            "tenant_id": "tenant-a", "device_id": "dev-1", "agent_id": "agent-1", "request_id": "req-approval",
            "chain_id": 84532, "to": "0x1111111111111111111111111111111111111111",
            "function_selector": "0xa9059cbb", "calldata": "0xa9059cbb" + "00" * 32,
        }
        _status, pending = _request(f"{base}/api/shield/transaction-intents", method="POST", token=token, body=intent)
        assert pending["decision"]["action"] == "escalate"
        approval_status, approval = _request(
            f"{base}/api/shield/transaction-approvals",
            method="POST",
            body={
                "tenant_id": "tenant-a", "device_id": "dev-1",
                "intent_hash": pending["decision"]["intent_hash"],
                "approver_id": "operator-1", "expires_at": "2099-01-01T00:00:00Z",
            },
        )
        assert approval_status == 201
        assert approval["intent_hash"] == pending["decision"]["intent_hash"]
        verify_status, verified = _request(
            f"{base}/api/shield/transaction-approvals/verify",
            method="POST", token=token,
            body={"tenant_id": "tenant-a", "device_id": "dev-1", "intent_hash": approval["intent_hash"]},
        )
        assert verify_status == 200
        assert verified["authorized"] is True
        consume_status, consumed = _request(
            f"{base}/api/shield/transaction-approvals/consume",
            method="POST",
            body={
                "tenant_id": "tenant-a", "device_id": "dev-1",
                "approval_id": approval["approval_id"], "intent_hash": approval["intent_hash"],
            },
        )
        assert consume_status == 200
        assert consumed["approval_id"] == approval["approval_id"]
        repeat = urllib.request.Request(
            f"{base}/api/shield/transaction-approvals/consume",
            data=json.dumps({
                "tenant_id": "tenant-a", "device_id": "dev-1",
                "approval_id": approval["approval_id"], "intent_hash": approval["intent_hash"],
            }).encode(), method="POST", headers={"Content-Type": "application/json", "Authorization": f"Bearer {ADMIN}"},
        )
        try:
            urllib.request.urlopen(repeat, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 409
        else:
            raise AssertionError("expected one-time approval consumption")
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


def test_backend_ingests_detection_quality_and_exposes_summary(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        token = enrolled["device_token"]

        status, result = _request(
            f"{base}/api/shield/detection-quality",
            method="POST",
            token=token,
            body={
                "tenant_id": "tenant-a",
                "device_id": "dev-1",
                "detection_quality": {
                    "samples": [
                        {
                            "event_id": "evt-mal-1",
                            "label": "malicious",
                            "label_source": "red_team",
                            "decision_action": "contain",
                            "first_observed_timestamp": "2026-08-13T10:00:00Z",
                            "containment_timestamp": "2026-08-13T10:00:03Z",
                            "export_attempted": True,
                            "export_success": True,
                        },
                        {
                            "event_id": "evt-mal-2",
                            "label": "malicious",
                            "label_source": "red_team",
                            "decision_action": "allow",
                            "export_attempted": True,
                            "export_success": False,
                        },
                        {
                            "event_id": "evt-benign-1",
                            "label": "benign",
                            "label_source": "operator_review",
                            "decision_action": "deny",
                            "export_attempted": True,
                            "export_success": True,
                        },
                    ]
                },
            },
        )
        assert status == 201
        assert result["id"] == 1

        _status, listed = _request(f"{base}/api/shield/detection-quality?tenant_id=tenant-a")
        quality = listed["detection_quality"][0]["quality"]
        assert quality["aggregate"]["shield_adr"] == 0.5
        assert quality["aggregate"]["precision"] == 0.5
        assert quality["aggregate"]["blocking_false_positive_rate"] == 1.0
        assert quality["aggregate"]["mean_time_to_contain_sec"] == 3.0
        assert quality["aggregate"]["evidence_export_success"] == 0.666667

        _status, summary = _request(f"{base}/api/shield/dashboard-summary?tenant_id=tenant-a")
        assert summary["latest_detection_quality"]["aggregate"]["shield_adr"] == 0.5
    finally:
        server.shutdown()
        store.close()


def test_backend_detection_quality_report_verifies_integrity_receipts(tmp_path):
    class VerifyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/v1/audit-log"):
                raw = json.dumps(
                    [
                        {
                            "id": "audit-1",
                            "agent_id": "did:integrity:test",
                            "source": "bcc_middleware",
                            "event_type": "bcc_intercept",
                            "decision": "allow",
                            "detail": "admitted to merkle batch index 0",
                            "created_at": "2026-08-13T10:00:00Z",
                        }
                    ]
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            valid = (
                self.path == "/v1/bcc/verify_token"
                and body.get("token") == "valid-token"
                and body.get("agent_id") == "did:integrity:test"
                and body.get("nonce") == 1
                and body.get("intended_state_hash") == "0x" + "a" * 64
            )
            raw = json.dumps({"valid": valid}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, _format, *_args):
            pass

    verify_server = ThreadingHTTPServer(("127.0.0.1", 0), VerifyHandler)
    verify_thread = threading.Thread(target=verify_server.serve_forever, daemon=True)
    verify_thread.start()
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        token = enrolled["device_token"]
        _request(
            f"{base}/api/shield/detection-quality",
            method="POST",
            token=token,
            body={
                "tenant_id": "tenant-a",
                "device_id": "dev-1",
                "detection_quality": {
                    "samples": [
                        {
                            "event_id": "evt-valid",
                            "label": "malicious",
                            "label_source": "red_team",
                            "decision_action": "deny",
                            "export_attempted": True,
                            "export_success": True,
                            "verification_token": "valid-token",
                            "batch_index": 0,
                            "agent_id": "did:integrity:test",
                            "nonce": 1,
                            "intended_state_hash": "0x" + "a" * 64,
                        },
                        {
                            "event_id": "evt-invalid",
                            "label": "malicious",
                            "label_source": "red_team",
                            "decision_action": "contain",
                            "export_attempted": True,
                            "export_success": True,
                            "verification_token": "invalid-token",
                            "batch_index": 1,
                            "agent_id": "did:integrity:test",
                            "nonce": 2,
                            "intended_state_hash": "0x" + "b" * 64,
                        },
                        {
                            "event_id": "evt-benign",
                            "label": "benign",
                            "label_source": "operator_review",
                            "decision_action": "allow",
                            "export_attempted": True,
                            "export_success": True,
                            "verification_token": "valid-token",
                            "batch_index": 0,
                            "agent_id": "did:integrity:test",
                            "nonce": 1,
                            "intended_state_hash": "0x" + "a" * 64,
                        },
                    ]
                },
            },
        )

        status, report = _request(
            f"{base}/api/shield/detection-quality/report",
            method="POST",
            body={
                "tenant_id": "tenant-a",
                "bcc_middleware_url": f"http://127.0.0.1:{verify_server.server_port}",
                "oracle_url": f"http://127.0.0.1:{verify_server.server_port}",
            },
        )

        assert status == 200
        assert report["raw_aggregate"]["shield_adr"] == 1.0
        assert report["receipt_backed_aggregate"]["shield_adr"] == 1.0
        assert report["receipt_backed_aggregate"]["labeled_malicious_events"] == 1
        assert report["all_adr_counted_security_decisions_have_verified_receipts"] is False
        assert report["all_adr_counted_security_decisions_have_oracle_audit_readback"] is False
        assert report["unverified_adr_counted_event_ids"] == ["evt-invalid"]
        receipt_by_event = {sample["event_id"]: sample["receipt_verified"] for sample in report["samples"]}
        assert receipt_by_event == {"evt-valid": True, "evt-invalid": False, "evt-benign": True}
        audit_by_event = {sample["event_id"]: sample["oracle_audit_readback"] for sample in report["samples"]}
        assert audit_by_event == {"evt-valid": True, "evt-invalid": False, "evt-benign": True}
    finally:
        server.shutdown()
        store.close()
        verify_server.shutdown()


def test_backend_rejects_malformed_detection_quality(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        request = urllib.request.Request(
            f"{base}/api/shield/detection-quality",
            data=json.dumps(
                {
                    "tenant_id": "tenant-a",
                    "device_id": "dev-1",
                    "detection_quality": {"samples": [{"event_id": "evt-1", "label": "malicious"}]},
                }
            ).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {enrolled['device_token']}"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
        else:
            raise AssertionError("expected malformed detection-quality rejection")
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


def test_backend_admin_auth_fails_closed_with_no_admin_token_configured(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    handler = make_handler(store=store, admin_token="")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        request = urllib.request.Request(
            f"{base}/api/shield/devices?tenant_id=tenant-a",
            headers={"Authorization": "Bearer anything"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("expected auth to fail closed when no admin token is configured")
    finally:
        server.shutdown()
        store.close()


def test_backend_tenant_scoped_admin_token_cannot_read_another_tenant(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        status, minted = _request(
            f"{base}/api/shield/admin-tokens",
            method="POST",
            body={"tenant_id": "tenant-a"},
        )
        assert status == 201
        tenant_token = minted["admin_token"]

        status, _ = _request(f"{base}/api/shield/devices?tenant_id=tenant-a", token=tenant_token)
        assert status == 200

        request = urllib.request.Request(
            f"{base}/api/shield/devices?tenant_id=tenant-b",
            headers={"Authorization": f"Bearer {tenant_token}"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("expected tenant-scoped admin token to be rejected for another tenant")
    finally:
        server.shutdown()
        store.close()


def test_backend_minting_admin_token_requires_super_admin_token(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        status, minted = _request(
            f"{base}/api/shield/admin-tokens",
            method="POST",
            body={"tenant_id": "tenant-a"},
        )
        tenant_token = minted["admin_token"]
        assert status == 201

        request = urllib.request.Request(
            f"{base}/api/shield/admin-tokens",
            data=json.dumps({"tenant_id": "tenant-b"}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {tenant_token}"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("expected a tenant-scoped token to be unable to mint another tenant's token")
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
