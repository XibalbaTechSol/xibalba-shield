from __future__ import annotations

import json
import base64
import threading
import urllib.error
import urllib.request
import pytest
import shield.backend.api as backend_api
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from shield.backend.api import load_or_create_admin_token, make_handler, run_server
from shield.backend.store import ShieldStore


ADMIN = "test-admin-token"


def test_backend_admin_token_is_generated_once_without_logging_value(tmp_path):
    path = tmp_path / "state" / "admin.token"
    first, created = load_or_create_admin_token(path)
    second, recreated = load_or_create_admin_token(path)
    assert created is True
    assert recreated is False
    assert first == second
    assert len(first) >= 32
    assert path.stat().st_mode & 0o777 == 0o600


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
        status, _ = _request(f"{base}/api/shield/policies/tenant-a/dev-1", method="POST", body={"policy_version": "tenant-a-v2", "rules": []})
        assert status == 200
        status, history = _request(f"{base}/api/shield/policy-history?tenant_id=tenant-a&device_id=dev-1")
        assert status == 200 and history["history"]
        status, rolled = _request(f"{base}/api/shield/policy-history/rollback", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-1", "history_id": history["history"][0]["id"]})
        assert status == 200 and rolled["ok"] is True
        status, policy = _request(enrolled["device_config"]["tenant_policy_url"], token=enrolled["device_token"])
        assert status == 200 and policy["policy_version"] == "tenant-a-v1"
        status, remediation = _request(f"{base}/api/shield/exporter-remediation", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-1", "action": "retry", "reason": "queue is stale"})
        assert status == 202 and remediation["status"] == "queued"
        status, requests = _request(f"{base}/api/shield/exporter-remediation?tenant_id=tenant-a&device_id=dev-1")
        assert status == 200 and requests["requests"][0]["action"] == "retry"
    finally:
        server.shutdown()
        store.close()


def test_backend_binds_integrity_agent_and_exposes_agent_workspace(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        _request(f"{base}/api/shield/enroll", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-1", "device_role": "workstation"})
        status, result = _request(f"{base}/api/shield/agents/register", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-1", "agent_id": "did:integrity:test", "oracle_url": "http://127.0.0.1:1"})
        assert status == 200
        assert result["registration"]["status"] == "pending_signature"
        assert result["agent"]["agent_id"] == "did:integrity:test"
        status, agents = _request(f"{base}/api/shield/agents?tenant_id=tenant-a")
        assert status == 200 and agents["agents"][0]["agent_id"] == "did:integrity:test"
    finally:
        server.shutdown(); server.server_close(); store.close()


def test_backend_binding_proof_requires_device_possession_and_agent_signature(tmp_path, monkeypatch):
    monkeypatch.setenv("INTEGRITY_DID_HOME", str(tmp_path / "did"))
    from integrity_sdk.did import load_or_create_did

    agent_id, keypair, _document = load_or_create_did("binding-agent")
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll", method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-proof", "device_role": "workstation"},
        )
        status, result = _request(
            f"{base}/api/shield/agents/register", method="POST",
            body={
                "tenant_id": "tenant-a", "device_id": "dev-proof", "agent_id": agent_id,
                "device_token": enrolled["device_token"], "oracle_url": "http://127.0.0.1:1",
                "agent_signature": base64.b64encode(keypair.sign(json.dumps({"schema": "xibalba.shield.device-agent-binding.v1", "tenant_id": "tenant-a", "device_id": "dev-proof", "agent_id": agent_id}, sort_keys=True, separators=(",", ":")).encode())).decode(),
                "agent_public_key": base64.b64encode(keypair.public_bytes()).decode(),
            },
        )
        assert status == 200
        binding = result["agent"]["device_agent_binding"]
        assert binding["status"] == "cryptographically_attested"
        assert binding["device_attested"] is True
        assert binding["agent_attested"] is True
    finally:
        server.shutdown(); server.server_close(); store.close()


def test_backend_cortex_memory_proxy_is_bound_to_device_agent_pair(tmp_path, monkeypatch):
    server, store, base = _start_backend(tmp_path)
    try:
        _request(f"{base}/api/shield/enroll", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-memory", "device_role": "workstation"})
        _request(f"{base}/api/shield/agents/register", method="POST", body={"tenant_id": "tenant-a", "device_id": "dev-memory", "agent_id": "did:integrity:memory"})
        monkeypatch.setattr(backend_api, "_read_cortex_agent_memories", lambda **kwargs: {"memories": [{"id": "m-1", "content_preview": "redacted event"}]})
        status, payload = _request(f"{base}/api/shield/cortex-memories?tenant_id=tenant-a&device_id=dev-memory&agent_id=did%3Aintegrity%3Amemory")
        assert status == 200
        assert payload["memory_namespace"] == "shield:did:integrity:memory"
        assert payload["memories"][0]["id"] == "m-1"
        try:
            _request(f"{base}/api/shield/cortex-memories?tenant_id=tenant-a&device_id=dev-memory&agent_id=did%3Aintegrity%3Aother")
        except urllib.error.HTTPError as exc:
            assert exc.code == 409
        else:
            raise AssertionError("unbound Cortex agent namespace was accepted")
    finally:
        server.shutdown(); server.server_close(); store.close()


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


def test_backend_records_and_lists_enforcement_outcomes(tmp_path):
    """`/api/shield/enforcement-outcomes` had no test coverage at all before this --
    it's the real backend endpoint the console's new Containment Outcomes panel
    (item 7) reads from, so its actual data contract needs to be verified, not assumed."""
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        token = enrolled["device_token"]

        status, _result = _request(
            f"{base}/api/shield/enforcement-outcomes",
            method="POST",
            token=token,
            body={
                "tenant_id": "tenant-a",
                "device_id": "dev-1",
                "outcome": {
                    "event_id": "evt-1", "device_id": "dev-1", "action": "contain",
                    "completed": False, "escalated": False, "error": "no such process: 4242",
                },
            },
        )
        assert status == 201

        _status, outcomes = _request(f"{base}/api/shield/enforcement-outcomes?tenant_id=tenant-a")
        assert outcomes["enforcement_outcomes"][0]["outcome"]["completed"] is False
        assert outcomes["enforcement_outcomes"][0]["outcome"]["error"] == "no such process: 4242"
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


def test_backend_dev_auth_bypass_allows_loopback_without_token(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    handler = make_handler(store=store, admin_token="", dev_disable_admin_auth=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _payload = _request(
            f"http://127.0.0.1:{server.server_port}/api/shield/devices?tenant_id=tenant-a"
        )
        assert status == 200
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_backend_dev_auth_bypass_rejects_non_loopback_browser_origin(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    handler = make_handler(store=store, admin_token="", dev_disable_admin_auth=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/api/shield/devices?tenant_id=tenant-a",
            headers={"Origin": "https://attacker.example"},
        )
        with pytest.raises(urllib.error.HTTPError) as failure:
            urllib.request.urlopen(request, timeout=5)
        assert failure.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_backend_dev_auth_bypass_rejects_non_loopback_listener(tmp_path):
    with pytest.raises(ValueError, match="loopback host"):
        run_server(
            host="0.0.0.0",
            port=0,
            db_path=tmp_path / "shield.sqlite3",
            admin_token="",
            dev_disable_admin_auth=True,
        )


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


def test_backend_rejects_legacy_dev_bypass_token(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        request = urllib.request.Request(
            f"{base}/api/shield/devices?tenant_id=tenant-a",
            headers={"Authorization": "Bearer dev"},
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("legacy dev token must not bypass authentication")
    finally:
        server.shutdown()
        store.close()


def test_backend_tls_requires_a_certificate_and_key_pair(tmp_path):
    try:
        run_server(host="127.0.0.1", port=0, db_path=tmp_path / "tls.sqlite3", admin_token=ADMIN, tls_cert=tmp_path / "server.crt")
    except ValueError as exc:
        assert "both --tls-cert and --tls-key" in str(exc)
    else:
        raise AssertionError("partial TLS configuration must fail closed")


def test_backend_dedicated_tls_port_requires_certificates(tmp_path):
    try:
        run_server(host="127.0.0.1", port=0, tls_port=0, db_path=tmp_path / "tls-port.sqlite3", admin_token=ADMIN)
    except ValueError as exc:
        assert "--tls-port" in str(exc)
    else:
        raise AssertionError("dedicated TLS listener must fail closed without certificates")


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
        # Device Health & Exporter Status panel (PRODUCTION_READINESS_PLAN.md §7 item 7) --
        # regression guard against silently dropping the exporter-status wiring; doesn't
        # execute the JS (no headless browser here), just confirms the fetch call, the
        # target element, and the did_preflight-vs-legacy-demo-field branch are present.
        assert 'id="exporterStatus"' in html
        assert "loadExporterStatus" in html
        assert "/api/shield/exporter-status" in html
        assert "did_preflight" in html
        # Containment Outcomes panel (item 7's "containment contracts" half) --
        # /api/shield/enforcement-outcomes existed as a real endpoint but was never
        # called from this console before this session.
        assert 'id="containmentOutcomes"' in html
        assert "loadContainmentOutcomes" in html
        assert "/api/shield/enforcement-outcomes" in html
    finally:
        server.shutdown()
        store.close()


def test_backend_exporter_status_carries_real_watchdog_fields_through_to_the_api(tmp_path):
    """Confirms the full real shape `shield.watchdog.Watchdog.tick()`/`publish_runtime_status`
    actually sends -- policy/sensors/exporter/did_preflight, including this session's new
    spool_pending/spool_oldest_age_seconds and check_did_preflight() fields -- round-trips
    through the store unmodified. The console's rendering of this shape is covered manually
    (browser-verified); this is the data-layer contract it depends on."""
    server, store, base = _start_backend(tmp_path)
    try:
        _status, enrolled = _request(
            f"{base}/api/shield/enroll",
            method="POST",
            body={"tenant_id": "tenant-a", "device_id": "dev-1"},
        )
        token = enrolled["device_token"]

        real_shaped_status = {
            "policy": {"healthy": True, "active_policy_hash": "sha256:abc"},
            "opa": {"healthy": True},
            "sensors": {"attached": True, "lost_events": 2, "last_event_at": "2026-09-06T00:00:00Z"},
            "exporter": {
                "export_failures": 1, "queue_depth": 3,
                "spool_pending": 1, "spool_oldest_age_seconds": 42.7,
            },
            "did_preflight": {
                "did": "did:integrity:abc123", "did_loaded": True,
                "bcc_middleware_reachable": True, "oracle_configured": True,
                "oracle_reachable": True, "oracle_registered": False,
            },
        }
        status, _result = _request(
            f"{base}/api/shield/exporter-status",
            method="POST",
            token=token,
            body={"tenant_id": "tenant-a", "device_id": "dev-1", "status": real_shaped_status},
        )
        assert status == 200

        _status, exporter_status = _request(f"{base}/api/shield/exporter-status?tenant_id=tenant-a")
        stored = exporter_status["exporter_status"][0]["status"]
        assert stored["exporter"]["spool_pending"] == 1
        assert stored["exporter"]["spool_oldest_age_seconds"] == 42.7
        assert stored["did_preflight"]["oracle_registered"] is False
        assert stored["sensors"]["lost_events"] == 2
    finally:
        server.shutdown()
        store.close()

def test_backend_account_signup_login_and_logout_revokes_session(tmp_path, monkeypatch):
    server, store, base = _start_backend(tmp_path)
    try:
        status, signup = _request(
            f"{base}/api/shield/auth/signup",
            method="POST",
            token="",
            body={"tenant_id": "account-tenant", "email": "operator@example.com", "password": "correct horse battery staple", "display_name": "Account Operator"},
        )
        assert status == 201
        assert signup["account"]["email"] == "operator@example.com"
        assert signup["session_expires_at"]
        token = signup["admin_token"]
        status, login = _request(
            f"{base}/api/shield/auth/login",
            method="POST",
            token="",
            body={"email": "operator@example.com", "password": "correct horse battery staple"},
        )
        assert status == 200
        assert login["tenant_id"] == "account-tenant"
        assert login["session_expires_at"]
        token = login["admin_token"]
        with store._conn:
            store._conn.execute("INSERT INTO tenants(tenant_id,created_at) VALUES(?,?)", ("second-tenant", "now"))
            store._conn.execute("INSERT INTO account_tenant_memberships(account_id,tenant_id,role,created_at) SELECT account_id,?,role,created_at FROM accounts WHERE email=?", ("second-tenant", "operator@example.com"))
        status, switched = _request(f"{base}/api/shield/auth/switch-tenant", method="POST", token=token, body={"current_tenant_id": "account-tenant", "target_tenant_id": "second-tenant", "email": "operator@example.com"})
        assert status == 200 and switched["tenant_id"] == "second-tenant"
        status, _ = _request(f"{base}/api/shield/dashboard-summary?tenant_id=account-tenant", token=token)
        assert status == 200
        status, audit = _request(f"{base}/api/shield/auth/events?tenant_id=account-tenant", token=token)
        assert status == 200 and any(event["event_type"] == "login_succeeded" for event in audit["events"])
        status, sessions = _request(f"{base}/api/shield/auth/sessions?tenant_id=account-tenant", token=token)
        assert status == 200 and sessions["sessions"][0]["last_used_at"]
        status, changed = _request(
            f"{base}/api/shield/auth/password",
            method="POST",
            token=token,
            body={"tenant_id": "account-tenant", "email": "operator@example.com", "current_password": "correct horse battery staple", "new_password": "new correct horse battery"},
        )
        assert status == 200 and changed["ok"] is True
        status, relogin = _request(f"{base}/api/shield/auth/login", method="POST", token="", body={"email": "operator@example.com", "password": "new correct horse battery"})
        assert status == 200
        token = relogin["admin_token"]
        monkeypatch.setenv("SHIELD_PASSWORD_RESET_URL", "https://shield.example/reset")
        with patch("shield.backend.email_delivery.send_email") as delivery:
            status, reset = _request(f"{base}/api/shield/auth/password-reset/request", method="POST", token="", body={"email": "operator@example.com"})
        assert status == 200 and reset == {"ok": True, "delivery": "email"}
        reset_token = delivery.call_args.args[2].split("token=", 1)[1].strip()
        status, confirmed = _request(f"{base}/api/shield/auth/password-reset/confirm", method="POST", token="", body={"reset_token": reset_token, "new_password": "reset correct horse battery"})
        assert status == 200 and confirmed["ok"] is True
        status, relogin = _request(f"{base}/api/shield/auth/login", method="POST", token="", body={"email": "operator@example.com", "password": "reset correct horse battery"})
        assert status == 200
        token = relogin["admin_token"]
        status, logged_out = _request(
            f"{base}/api/shield/auth/logout",
            method="POST",
            token=token,
            body={"tenant_id": "account-tenant"},
        )
        assert status == 200 and logged_out["ok"] is True
        try:
            _request(f"{base}/api/shield/dashboard-summary?tenant_id=account-tenant", token=token)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("revoked account session was accepted")
    finally:
        server.shutdown()
        server.server_close()
        store.close()

def test_backend_account_auth_rate_limits_repeated_attempts(tmp_path):
    server, store, base = _start_backend(tmp_path)
    try:
        statuses = []
        for _ in range(9):
            try:
                status, _ = _request(
                    f"{base}/api/shield/auth/login",
                    method="POST",
                    token="",
                    body={"email": "rate@example.com", "password": "wrong password"},
                )
                statuses.append(status)
            except urllib.error.HTTPError as exc:
                statuses.append(exc.code)
        assert statuses[-1] == 429
    finally:
        server.shutdown(); server.server_close(); store.close()

def test_account_failed_logins_lock_account_and_record_audit(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    try:
        store.create_account(tenant_id="lock-tenant", email="lock@example.com", password="correct horse battery staple", display_name="Lock User")
        for _ in range(5):
            assert store.authenticate_account(email="lock@example.com", password="wrong password") is None
        assert store.authenticate_account(email="lock@example.com", password="correct horse battery staple") is None
        events = store._conn.execute("SELECT event_type, detail FROM auth_events WHERE email=? ORDER BY id", ("lock@example.com",)).fetchall()
        assert events[-1]["event_type"] == "login_blocked"
        assert any(row["detail"] == "locked" for row in events)
    finally:
        store.close()
