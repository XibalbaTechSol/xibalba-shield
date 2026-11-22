"""
Comprehensive test suite for Xibalba Shield Sentry Defense Subsystem:
- Phase 1: Ingress Taint Tracking, Zero-Width Canary Traps, and Secret/PII Scrubbers
- Phase 2: Proof-of-Justification (PoJ) Tool Gating & Execution Tickets
- Phase 3: OCSF Class 6003 SIEM Exporters & Encrypted Tenant Enclaves
- Backend API endpoints and persistence integration
"""

from __future__ import annotations

import json
import sqlite3
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import pytest

from shield.sentry import (
    TaintLevel,
    TaintRecord,
    TaintLatticeTracker,
    CanaryTrap,
    CanaryManager,
    SecretScrubber,
    scrub_secrets_and_pii,
    ToolRiskLevel,
    ToolRiskPolicy,
    ExecutionTicket,
    ProofOfJustificationEngine,
    PoJAuthorizationError,
    OCSFActivityId,
    OCSFSeverityId,
    OCSFEventBuilder,
    TenantEnclave,
    EnclaveError,
    SentryDefenseStore,
)
from shield.guardrail_hooks import (
    SentryGatingError,
    guard_sentry_tool_call,
)
from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.policy_engine.engine import PolicyEngine
from shield.backend.store import ShieldStore
from shield.backend.api import make_server
from tests.pack_test_support import install_fake_opa


@pytest.fixture(autouse=True)
def mock_opa(monkeypatch):
    return install_fake_opa(monkeypatch)


# =====================================================================
# Phase 1 Tests: Taint Tracking, Canaries, and Scrubbers
# =====================================================================

def test_taint_lattice_ordering_and_join():
    t_axiom = TaintLevel.TRUSTED_AXIOM
    t_inference = TaintLevel.AGENT_INFERENCE
    t_ingest = TaintLevel.UNTRUSTED_INGEST

    # Ordering
    assert t_axiom < t_inference < t_ingest

    # Lattice join (least upper bound = max risk)
    assert t_axiom.join(t_inference) == t_inference
    assert t_axiom.join(t_ingest) == t_ingest
    assert t_inference.join(t_ingest) == t_ingest
    assert t_axiom.join(t_axiom) == t_axiom

    # Lattice meet (greatest lower bound = min risk)
    assert t_axiom.meet(t_ingest) == t_axiom
    assert t_inference.meet(t_ingest) == t_inference

    # Clearance checks
    assert t_axiom.allows_clearance(TaintLevel.TRUSTED_AXIOM) is True
    assert t_ingest.allows_clearance(TaintLevel.TRUSTED_AXIOM) is False
    assert t_ingest.allows_clearance(TaintLevel.UNTRUSTED_INGEST) is True


def test_taint_propagation_and_decontamination():
    tracker = TaintLatticeTracker()

    rec_axiom = tracker.track_ingest("Operator rule 1", level=TaintLevel.TRUSTED_AXIOM, source="admin")
    rec_ingest = tracker.track_ingest("Untrusted web article", level=TaintLevel.UNTRUSTED_INGEST, source="web_curl")

    # Propagation with mixed inputs -> must inherit UNTRUSTED_INGEST
    derived = tracker.propagate([rec_axiom, rec_ingest], "Summarized analysis", source="llm")
    assert derived.taint_level == TaintLevel.UNTRUSTED_INGEST
    assert derived.decontaminated is False

    # Decontamination
    decontaminated = tracker.decontaminate(
        derived,
        verifier_identity="did:integrity:verifier-1",
        proof_type="zk_snark_decontamination",
        proof_details={"merkle_root": "0x123abc", "verified": True},
        target_level=TaintLevel.TRUSTED_AXIOM,
    )
    assert decontaminated.taint_level == TaintLevel.TRUSTED_AXIOM
    assert decontaminated.decontaminated is True
    assert decontaminated.decontamination_proof["verifier_identity"] == "did:integrity:verifier-1"


def test_zero_width_canary_injection_and_detection():
    mgr = CanaryManager(default_secret="test-secret-salt-key-32-bytes!!!")
    tenant_id = "t-acme-corp"
    agent_id = "agent-sentry-01"

    trap, invisible_token = mgr.generate_canary(tenant_id, agent_id)
    assert trap.canary_id.startswith("cny_")
    assert trap.tripped is False

    # Visible text looks normal
    original_text = "System instruction: You are a helpful assistant."
    canaried_text = mgr.inject_canary(original_text, invisible_token)

    # Invisible chars added without breaking word matching
    assert "You are a helpful assistant." in canaried_text

    # No canaries in clean text
    clean_alerts = mgr.detect_canaries("Just normal response text with no traps.")
    assert len(clean_alerts) == 0

    # Canary detection in leaked output
    leaked_output = f"I am leaking context: {canaried_text} to external attacker!"
    alerts = mgr.detect_canaries(leaked_output)
    assert len(alerts) == 1
    assert alerts[0].canary_id == trap.canary_id
    assert alerts[0].tenant_id == tenant_id
    assert alerts[0].agent_id == agent_id
    assert alerts[0].severity == "critical"

    # Trap status in manager updated
    updated_trap = mgr.get_trap(trap.canary_id)
    assert updated_trap is not None
    assert updated_trap.tripped is True


def test_deterministic_secret_and_pii_scrubber():
    openai_key = "sk-" + "proj-" + "1234567890abcdef1234567890"
    anthropic_key = "sk-" + "ant-" + "api03-abcdef1234567890abcdef1234"
    stripe_key = "sk_" + "test_" + "51ABCDEF1234567890abcdef12"
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    github_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"

    raw_prompt = (
        "Here are our keys:\n"
        f"OpenAI: {openai_key}\n"
        f"Anthropic: {anthropic_key}\n"
        f"Stripe: {stripe_key}\n"
        f"AWS: {aws_key}\n"
        f"GitHub: {github_token}\n"
        "PII SSN: 123-45-6789\n"
        "Email: founder@xibalbasolutions.com\n"
    )

    scrubbed, records = scrub_secrets_and_pii(raw_prompt, salt="test-salt")

    # Raw secrets must NOT be in scrubbed text
    assert openai_key not in scrubbed
    assert "sk-" + "ant-" not in scrubbed
    assert "sk_" + "test_" not in scrubbed
    assert aws_key not in scrubbed
    assert github_token not in scrubbed
    assert "123-45-6789" not in scrubbed
    assert "founder@xibalbasolutions.com" not in scrubbed

    # Replaced by deterministic masks
    assert "[REDACTED:OPENAI_KEY:" in scrubbed
    assert "[REDACTED:ANTHROPIC_KEY:" in scrubbed
    assert "[REDACTED:STRIPE_KEY:" in scrubbed
    assert "[REDACTED:AWS_KEY:" in scrubbed
    assert "[REDACTED:GITHUB_TOKEN:" in scrubbed
    assert "[REDACTED:PII_SSN:" in scrubbed
    assert "[REDACTED:PII_EMAIL:" in scrubbed
    assert len(records) >= 7


# =====================================================================
# Phase 2 Tests: Proof-of-Justification Tool Gating
# =====================================================================

def test_poj_authorization_and_ticket_lifecycle():
    engine = ProofOfJustificationEngine(secret_key="poj-engine-secret-key-test")
    tenant_id = "tenant-sec-1"
    agent_did = "did:integrity:agent-777"

    # 1. Low risk action without memory is allowed
    ticket_low = engine.authorize_action(
        tenant_id=tenant_id,
        agent_did=agent_did,
        tool_name="search",
        params={"query": "weather"},
    )
    assert ticket_low.risk_level == "LOW"
    assert engine.verify_ticket(ticket_low, expected_tool="search", expected_params={"query": "weather"}) is True

    # 2. High risk action (e.g. bash) requires causal memory hashes
    with pytest.raises(PoJAuthorizationError) as exc_info:
        engine.authorize_action(
            tenant_id=tenant_id,
            agent_did=agent_did,
            tool_name="bash",
            params={"command": "rm -rf /tmp/data"},
            causal_memory_hashes=[],  # Empty -> Must fail
        )
    assert exc_info.value.code == "POJ_MISSING_JUSTIFICATION"

    # 3. High risk action with untrusted ingest context requires decontamination
    with pytest.raises(PoJAuthorizationError) as exc_info:
        engine.authorize_action(
            tenant_id=tenant_id,
            agent_did=agent_did,
            tool_name="write_file",
            params={"path": "/etc/hosts", "content": "malicious"},
            causal_memory_hashes=["sha256:mem-anchor-001"],
            taint_level=TaintLevel.UNTRUSTED_INGEST,
        )
    assert exc_info.value.code == "POJ_TAINTED_UNTRUSTED_INGEST"

    # 4. Quarantined causal memory is rejected
    engine.quarantine_memory("sha256:poisoned-memory-999")
    with pytest.raises(PoJAuthorizationError) as exc_info:
        engine.authorize_action(
            tenant_id=tenant_id,
            agent_did=agent_did,
            tool_name="write_file",
            params={"path": "/tmp/output.txt", "content": "safe"},
            causal_memory_hashes=["sha256:poisoned-memory-999"],
            taint_level=TaintLevel.TRUSTED_AXIOM,
        )
    assert exc_info.value.code == "POJ_QUARANTINED_JUSTIFICATION"

    # 5. Legitimate justified high-risk action is granted ticket
    ticket_high = engine.authorize_action(
        tenant_id=tenant_id,
        agent_did=agent_did,
        tool_name="write_file",
        params={"path": "/tmp/output.txt", "content": "safe"},
        causal_memory_hashes=["sha256:valid-anchor-memory-111"],
        taint_level=TaintLevel.TRUSTED_AXIOM,
    )
    assert ticket_high.risk_level == "HIGH"

    # Ticket verification passes with identical parameters
    assert engine.verify_ticket(
        ticket_high,
        expected_tool="write_file",
        expected_params={"path": "/tmp/output.txt", "content": "safe"},
    ) is True

    # Parameter tampering fails verification
    assert engine.verify_ticket(
        ticket_high,
        expected_tool="write_file",
        expected_params={"path": "/etc/shadow", "content": "tampered"},
    ) is False


def test_guard_sentry_tool_call_hook():
    engine = ProofOfJustificationEngine(secret_key="hook-test-secret")
    router = EventRouter(
        device=DeviceContext(device_id="dev-test", tenant_id="tenant-alpha", device_role="server"),
        registry=AgentRegistry(),
        policy_engine=PolicyEngine(),
    )

    executed = []

    # Successful call
    res, ticket = guard_sentry_tool_call(
        router,
        engine,
        agent_id="agent-01",
        agent_name="TestAgent",
        tool_name="write_file",
        params={"file": "report.pdf"},
        causal_memory_hashes=["sha256:mem-123"],
        taint_level=TaintLevel.TRUSTED_AXIOM,
        call=lambda: executed.append(1) or "done",
    )
    assert res == "done"
    assert executed == [1]
    assert ticket.tool_name == "write_file"

    # Blocked call due to untrusted ingest taint
    with pytest.raises(SentryGatingError) as exc_info:
        guard_sentry_tool_call(
            router,
            engine,
            agent_id="agent-01",
            agent_name="TestAgent",
            tool_name="bash",
            params={"command": "reboot"},
            causal_memory_hashes=["sha256:mem-123"],
            taint_level=TaintLevel.UNTRUSTED_INGEST,
            call=lambda: executed.append(2),
        )
    assert "POJ_TAINTED_UNTRUSTED_INGEST" in exc_info.value.code
    assert executed == [1]  # Not executed!


# =====================================================================
# Phase 3 Tests: OCSF 6003 SIEM Export & Encrypted Tenant Enclaves
# =====================================================================

def test_ocsf_class_6003_event_serialization_and_profiles():
    event = OCSFEventBuilder.build_event(
        activity_id=OCSFActivityId.CANARY_TRIP,
        severity_id=OCSFSeverityId.CRITICAL,
        tenant_id="tenant-finance",
        agent_did="did:integrity:quant-bot-01",
        tool_name="external_http_egress",
        taint_level="UNTRUSTED_INGEST",
        message="Canary trap tripped in external egress payload",
        details={"canary_id": "cny_abc123", "exfil_attempt": True},
    )

    assert event.class_uid == 6003
    assert event.class_name == "AI Activity"
    assert event.category_uid == 6
    assert event.activity_id == int(OCSFActivityId.CANARY_TRIP)
    assert event.severity_id == int(OCSFSeverityId.CRITICAL)

    # JSONL Export
    jsonl = OCSFEventBuilder.export_jsonl([event])
    assert '"class_uid": 6003' in jsonl
    assert '"canary_id": "cny_abc123"' in jsonl

    # SIEM Profile Formats
    splunk_fmt = OCSFEventBuilder.format_for_siem(event, profile="splunk")
    assert splunk_fmt["sourcetype"] == "ocsf:ai_activity"
    assert splunk_fmt["event"]["class_uid"] == 6003

    elastic_fmt = OCSFEventBuilder.format_for_siem(event, profile="elastic")
    assert "@timestamp" in elastic_fmt
    assert elastic_fmt["ecs.version"] == "8.11.0"

    datadog_fmt = OCSFEventBuilder.format_for_siem(event, profile="datadog")
    assert datadog_fmt["ddsource"] == "xibalba-shield"
    assert datadog_fmt["service"] == "agent-sentry"


def test_encrypted_tenant_enclave_aes256_gcm():
    master_secret = "master-enclave-key-32-bytes-long!"
    tenant_a = "tenant-healthcare-a"
    tenant_b = "tenant-healthcare-b"

    enclave_a = TenantEnclave(tenant_a, master_secret)
    enclave_b = TenantEnclave(tenant_b, master_secret)

    secret_data = {"patient_id": "P-98765", "diagnosis": "classified", "key": "ed25519-priv-data"}

    # Encrypt with Tenant A
    envelope = enclave_a.encrypt(secret_data)
    assert envelope.tenant_id == tenant_a
    assert envelope.schema == "xibalba.shield.enclave.v1"
    assert envelope.ciphertext != ""

    # Decrypt with Tenant A succeeds
    decrypted = enclave_a.decrypt(envelope, as_json=True)
    assert decrypted["patient_id"] == "P-98765"
    assert decrypted["diagnosis"] == "classified"

    # Tenant B enclave cannot decrypt Tenant A's envelope
    with pytest.raises(EnclaveError):
        enclave_b.decrypt(envelope, as_json=True)


# =====================================================================
# Sentry Store & End-to-End API Integration Tests
# =====================================================================

def test_sentry_store_persistence():
    conn = sqlite3.connect(":memory:")
    store = SentryDefenseStore(conn)
    store.init_schema()

    # 1. Canary persistence
    trap = CanaryTrap(
        canary_id="cny_test_01",
        tenant_id="t-1",
        agent_id="a-1",
        secret_key="secret",
        created_at="2026-11-22T00:00:00Z",
    )
    store.record_canary(trap)
    fetched = store.get_canary("cny_test_01")
    assert fetched is not None
    assert fetched["tripped"] is False

    store.trip_canary("cny_test_01", "leaked snippet text")
    fetched_after = store.get_canary("cny_test_01")
    assert fetched_after["tripped"] is True
    assert fetched_after["tripped_context"] == "leaked snippet text"

    # 2. Execution Ticket persistence and single-use consumption
    ticket = ExecutionTicket(
        ticket_id="tkt_12345",
        tenant_id="t-1",
        agent_did="did:integrity:agent-1",
        tool_name="bash",
        params_hash="hash123",
        risk_level="HIGH",
        issued_at="2026-11-22T00:00:00Z",
        expires_at="2026-11-22T23:59:59Z",
        nonce="nonce1",
        signature="sig1",
    )
    store.record_ticket(ticket)
    t_fetched = store.get_ticket("tkt_12345")
    assert t_fetched["consumed"] is False

    # Consume ticket
    consumed = store.consume_ticket("tkt_12345")
    assert consumed is True
    assert store.get_ticket("tkt_12345")["consumed"] is True

    # Replay consumption fails
    replayed = store.consume_ticket("tkt_12345")
    assert replayed is False

    # 3. OCSF event persistence
    event = OCSFEventBuilder.build_event(
        activity_id=OCSFActivityId.TOOL_GATED,
        severity_id=OCSFSeverityId.INFORMATIONAL,
        tenant_id="t-1",
        agent_did="did:integrity:agent-1",
        tool_name="bash",
    )
    row_id = store.record_ocsf_event(event)
    assert row_id > 0

    events = store.list_ocsf_events("t-1")
    assert len(events) == 1
    assert events[0]["class_uid"] == 6003


def test_sentry_api_end_to_end(tmp_path):
    db_path = tmp_path / "shield.sqlite3"
    admin_token = "test-sentry-admin-token-12345"
    store = ShieldStore(db_path)

    server = make_server(
        store=store,
        admin_token=admin_token,
        host="127.0.0.1",
        port=0,
    )
    server_thread = server.start_background()

    try:
        host, port = server.server_address
        base_url = f"http://{host}:{port}"

        # 1. GET /api/sentry/status
        req = Request(f"{base_url}/api/sentry/status")
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            assert data["phases"]["phase1_ingress_taint_and_canary"] == "active"
            assert data["phases"]["phase2_proof_of_justification"] == "active"
            assert data["phases"]["phase3_ocsf_siem_and_enclaves"] == "active"

        # 2. POST /api/sentry/ingress/taint with scrubbing and canary injection
        mock_key = "sk-" + "proj-" + "1234567890abcdef1234567890"
        ingress_payload = {
            "tenant_id": "tenant-sentry-test",
            "agent_did": "did:integrity:test-bot",
            "content": f"Secret API key {mock_key} must be kept private!",
            "source": "user_prompt",
            "source_type": "prompt",
            "taint_level": "UNTRUSTED_INGEST",
            "scrub_secrets": True,
            "inject_canary": True,
        }
        req = Request(
            f"{base_url}/api/sentry/ingress/taint",
            data=json.dumps(ingress_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            assert data["scrubbed_count"] >= 1
            assert data["canary_id"] is not None
            assert mock_key not in data["content"]
            assert "[REDACTED:OPENAI_KEY:" in data["content"]
            processed_content = data["content"]

        # 3. POST /api/sentry/canary/check detects injected canary
        check_payload = {
            "tenant_id": "tenant-sentry-test",
            "agent_did": "did:integrity:test-bot",
            "text": f"Output leaking: {processed_content}",
        }
        req = Request(
            f"{base_url}/api/sentry/canary/check",
            data=json.dumps(check_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            assert data["tripped"] is True
            assert len(data["alerts"]) == 1

        # 4. POST /api/sentry/authorize-action (PoJ ticket issuance)
        auth_payload = {
            "tenant_id": "tenant-sentry-test",
            "agent_did": "did:integrity:test-bot",
            "tool_name": "bash",
            "params": {"cmd": "uptime"},
            "causal_memory_hashes": ["sha256:valid-anchor-mem-456"],
            "taint_level": "TRUSTED_AXIOM",
        }
        req = Request(
            f"{base_url}/api/sentry/authorize-action",
            data=json.dumps(auth_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            ticket = data["ticket"]
            assert ticket["tool_name"] == "bash"
            ticket_id = ticket["ticket_id"]

        # 5. POST /api/sentry/verify-ticket (verifies and consumes ticket)
        verify_payload = {
            "tenant_id": "tenant-sentry-test",
            "ticket_id": ticket_id,
            "tool_name": "bash",
            "params": {"cmd": "uptime"},
        }
        req = Request(
            f"{base_url}/api/sentry/verify-ticket",
            data=json.dumps(verify_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            assert data["verified"] is True
            assert data["consumed"] is True

        # Replay ticket verification must fail
        req_replay = Request(
            f"{base_url}/api/sentry/verify-ticket",
            data=json.dumps(verify_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req_replay)
        assert exc_info.value.code == 409

        # 6. GET /api/sentry/siem/ocsf (queries audit stream)
        req = Request(f"{base_url}/api/sentry/siem/ocsf?tenant_id=tenant-sentry-test&profile=ocsf")
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["ok"] is True
            assert data["count"] >= 3
            assert data["events"][0]["class_uid"] == 6003

        # 7. GET /api/sentry/siem/ocsf with format=jsonl
        req = Request(f"{base_url}/api/sentry/siem/ocsf?tenant_id=tenant-sentry-test&format=jsonl")
        with urlopen(req) as resp:
            lines = resp.read().decode("utf-8").strip().splitlines()
            assert len(lines) >= 3
            first_ev = json.loads(lines[0])
            assert first_ev["class_uid"] == 6003

    finally:
        server.shutdown()
        server.server_close()
        store.close()
