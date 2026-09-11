from __future__ import annotations

from shield.backend.store import ShieldStore
from shield.codex_agent import redact_event
from shield.agent_core.cortex_memory import CortexMemoryProvider
from types import SimpleNamespace
import json


def test_device_agent_binding_history_is_atomic_and_auditable(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.enroll_device(base_url="http://backend", tenant_id="tenant-a", device_id="dev-1", device_role="worker")
    first = store.bind_integrity_agent(
        tenant_id="tenant-a", device_id="dev-1", agent_id="agent-a", registration_status="pending_signature"
    )
    second = store.bind_integrity_agent(
        tenant_id="tenant-a", device_id="dev-1", agent_id="agent-b", registration_status="registered"
    )
    assert first["integrity_agent_id"] == "agent-a"
    assert second["integrity_agent_id"] == "agent-b"
    history = store.list_device_agent_bindings(tenant_id="tenant-a", device_id="dev-1")
    assert [item["agent_id"] for item in history] == ["agent-b", "agent-a"]
    assert history[0]["unbound_at"] is None
    # v4 permits multiple active agents on one device; uniqueness is per pair.
    assert history[1]["unbound_at"] is None
    store.close()


def test_redaction_covers_secrets_and_pii_inside_text_values():
    result = redact_event(
        {
            "class": "agent_event",
            "message": "Authorization: Bearer abc.def-123; contact alice@example.com; key sk-test_123456789012345",
        }
    )
    message = result["message"]
    assert "abc.def-123" not in message
    assert "alice@example.com" not in message
    assert "sk-test_123456789012345" not in message
    assert "<redacted>" in message or "<redacted-token>" in message


def test_device_agent_binding_compare_and_swap_rejects_stale_reassignment(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.enroll_device(base_url="http://backend", tenant_id="tenant-a", device_id="dev-1", device_role="worker")
    store.bind_integrity_agent(tenant_id="tenant-a", device_id="dev-1", agent_id="agent-a", registration_status="registered")
    try:
        store.bind_integrity_agent(
            tenant_id="tenant-a", device_id="dev-1", agent_id="agent-c",
            registration_status="registered", expected_agent_id="agent-stale",
        )
    except ValueError as exc:
        assert "concurrently" in str(exc)
    else:
        raise AssertionError("stale reassignment was accepted")
    assert store.get_device(tenant_id="tenant-a", device_id="dev-1")["integrity_agent_id"] == "agent-a"
    store.close()


def test_cortex_outbox_allowlist_and_dead_letter_metric(tmp_path):
    provider = CortexMemoryProvider(
        base_url="http://127.0.0.1:1", token="token", agent_id="did:integrity:agent-a",
        device_id="device-a", outbox_path=tmp_path / "outbox.sqlite3", max_attempts=1,
    )
    event = SimpleNamespace(to_dict=lambda: {
        "class": "agent_event", "event_id": "evt-1", "device_id": "device-a",
        "secret_pii": "must-not-leave", "process": {"name": "python", "secret": "no"},
    })
    decision = SimpleNamespace(
        to_dict=lambda: {"action": "allow", "decision_secret": "must-not-leave"},
        event_ref=SimpleNamespace(event_id="evt-1"),
    )
    provider.remember_event(event, decision)
    with provider._connect_outbox() as conn:
        payload = json.loads(conn.execute("SELECT payload_json FROM cortex_outbox").fetchone()[0])
    assert "secret_pii" not in payload["content"]
    assert "decision_secret" not in payload["content"]
    assert "redacted" not in payload["source"]["metadata"]
    assert payload["source"]["metadata"]["redaction_proof"]
    assert provider.status()["dead_letter"] == 1
    assert provider.metrics()["dead_letter_total"] == 1
