from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from shield.agent_core.eventlog import EventLog
from shield.config import ConfigError, DeviceConfig, fetch_tenant_policy, load_device_config, load_policy_bundle
from shield.content_classifier import classify_metadata
from shield.integrations.siem import export_decision_log_to_jsonl, post_decision_log_to_webhook
from shield.schemas.events import Activity, EventRef, PolicyDecision, ProcessActivity, ProcessInfo, RuleRef, Decision


def _decision(action: str = "allow") -> PolicyDecision:
    return PolicyDecision(
        device_id="dev-1",
        event_ref=EventRef(klass="process_activity", event_id="event-1"),
        rule=RuleRef(rule_id="_no_match", name="Default allow", version="builtin"),
        decision=Decision(action=action, reason="test"),
    )


def _serve(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}/policy"


def test_fetch_tenant_policy_validates_and_writes_atomically(tmp_path):
    seen_headers = {}
    bundle = {"policy_version": "tenant-v1", "rules": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen_headers["device"] = self.headers.get("X-Shield-Device-ID")
            seen_headers["authorization"] = self.headers.get("Authorization")
            body = json.dumps(bundle).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    server, url = _serve(Handler)
    try:
        config = DeviceConfig(device_id="dev-1", tenant_id="tenant-a", tenant_policy_url=url, device_token="device-secret")
        result = fetch_tenant_policy(device_config=config, destination=tmp_path / "policy.json")
    finally:
        server.shutdown()

    assert seen_headers["device"] == "dev-1"
    assert seen_headers["authorization"] == "Bearer device-secret"
    assert result.bundle.version == "tenant-v1"
    assert load_policy_bundle(tmp_path / "policy.json").hash == result.bundle.hash


def test_fetch_tenant_policy_rejects_untrusted_hash(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"rules":[]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    server, url = _serve(Handler)
    try:
        config = DeviceConfig(device_id="dev-1", tenant_policy_url=url, trusted_policy_hashes=["sha256:not-it"])
        with pytest.raises(ConfigError, match="not trusted"):
            fetch_tenant_policy(device_config=config, destination=tmp_path / "policy.json")
    finally:
        server.shutdown()

    assert not (tmp_path / "policy.json").exists()


def test_load_device_config_accepts_tenant_policy_url(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1", "tenant_policy_url": "https://tenant.example/policy"}))

    assert load_device_config(path).tenant_policy_url == "https://tenant.example/policy"


def test_tamper_evident_event_log_detects_modified_rows(tmp_path):
    key = tmp_path / "log.key"
    key.write_bytes(b"test-secret")
    log_path = tmp_path / "decisions.jsonl"
    log = EventLog(log_path, integrity_key_path=key)
    log.append(_decision())

    assert log.verify()["ok"] is True

    row = json.loads(log_path.read_text().splitlines()[0])
    row["decision"]["action"] = "deny"
    log_path.write_text(json.dumps(row) + "\n")

    result = log.verify()
    assert result["ok"] is False
    assert "mismatch" in result["reason"]


def test_content_classifier_uses_metadata_without_raw_content():
    classification = classify_metadata(
        file_paths=("/home/a/.ssh/id_rsa",),
        data_sources=("clinical-ehr",),
        model_endpoint="https://api.example/model",
    )

    assert classification.risk_level == "critical"
    assert classification.categories == ["external_model", "phi", "secret"]


def test_siem_jsonl_export_adds_portable_fields(tmp_path):
    source = tmp_path / "decisions.jsonl"
    destination = tmp_path / "siem.jsonl"
    source.write_text(json.dumps(_decision("deny").to_dict()) + "\n")

    result = export_decision_log_to_jsonl(source, destination)
    row = json.loads(destination.read_text())

    assert result.exported == 1
    assert row["event.module"] == "xibalba-shield"
    assert row["event.kind"] == "alert"


def test_siem_jsonl_export_supports_splunk_profile(tmp_path):
    source = tmp_path / "decisions.jsonl"
    destination = tmp_path / "siem.jsonl"
    source.write_text(json.dumps(_decision("deny").to_dict()) + "\n")

    result = export_decision_log_to_jsonl(source, destination, profile="splunk")
    row = json.loads(destination.read_text())

    assert result.exported == 1
    assert row["sourcetype"] == "xibalba_shield_decision"
    assert row["source"] == "xibalba:shield:decision"


def test_siem_webhook_posts_each_decision(tmp_path):
    received = []
    source = tmp_path / "decisions.jsonl"
    source.write_text(json.dumps(_decision().to_dict()) + "\n")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format, *_args):
            pass

    server, url = _serve(Handler)
    try:
        result = post_decision_log_to_webhook(source, url)
    finally:
        server.shutdown()

    assert result.exported == 1
    assert result.failed == 0
    assert received[0]["class"] == "policy_decision"


def test_tcp_connect_root_verifier_reports_blocked_without_root():
    import os

    if os.geteuid() == 0:
        pytest.skip("non-root behavior only")

    proc = subprocess.run(
        [sys.executable, "scripts/verify_tcp_connect_root.py"],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
    )
    doc = json.loads(proc.stdout)

    assert proc.returncode == 2
    assert doc["status"] == "blocked"
    assert doc["requires_root"] is True



def test_pilot_gate_report_blocks_without_external_artifacts():
    proc = subprocess.run(
        [sys.executable, "scripts/pilot_gate_report.py", "--json"],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
    )
    doc = json.loads(proc.stdout)

    assert proc.returncode == 0
    assert {gate["status"] for gate in doc["gates"]} == {"BLOCKED"}
    assert {gate["name"] for gate in doc["gates"]} >= {
        "TCP-connect eBPF target-kernel verification",
        "live DID oracle readback",
        "Windows native sensors",
        "macOS native sensors",
        "root/admin resistance hardening",
        "installer/updater signing",
        "multi-day burn-in",
    }


def test_pilot_gate_report_fails_invalid_artifact(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not-json", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "scripts/pilot_gate_report.py", "--tcp-artifact", str(bad), "--json"],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
    )
    doc = json.loads(proc.stdout)

    assert proc.returncode == 1
    tcp_gate = next(gate for gate in doc["gates"] if gate["name"].startswith("TCP-connect"))
    assert tcp_gate["status"] == "FAIL"
    assert "invalid JSON" in tcp_gate["detail"]


def test_pilot_gate_report_accepts_realistic_pass_artifacts(tmp_path):
    tcp = tmp_path / "tcp.json"
    tcp.write_text(json.dumps({"status": "pass", "reason": "observed real localhost TCP connect"}), encoding="utf-8")
    did = tmp_path / "did.json"
    did.write_text(json.dumps({"status": "ok", "detail": "registered DID resolved"}), encoding="utf-8")
    windows = tmp_path / "windows.json"
    windows.write_text(json.dumps({"status": "pass", "detail": "ETW events normalized"}), encoding="utf-8")
    macos = tmp_path / "macos.json"
    macos.write_text(json.dumps({"status": "pass", "detail": "EndpointSecurity events normalized"}), encoding="utf-8")
    burn = tmp_path / "burn.json"
    burn.write_text(
        json.dumps({"status": "pass", "duration_sec": 48 * 3600, "false_positive_reviewed": 20, "false_positive_rate": 0.01}),
        encoding="utf-8",
    )
    hardening = tmp_path / "hardening.txt"
    hardening.write_text("secure_boot=true\ntpm_or_mdm=true\nservice_protection=true\nlog_key_protection=true\n", encoding="utf-8")
    installer = tmp_path / "installer.txt"
    installer.write_text("artifact_sha256=abc\nsignature=sig\nservice_manager=systemd\nrollback=true\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/pilot_gate_report.py",
            "--tcp-artifact",
            str(tcp),
            "--did-artifact",
            str(did),
            "--windows-artifact",
            str(windows),
            "--macos-artifact",
            str(macos),
            "--burn-in-artifact",
            str(burn),
            "--hardening-attestation",
            str(hardening),
            "--installer-attestation",
            str(installer),
            "--json",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
    )
    doc = json.loads(proc.stdout)

    assert proc.returncode == 0
    assert {gate["status"] for gate in doc["gates"]} == {"PASS"}
