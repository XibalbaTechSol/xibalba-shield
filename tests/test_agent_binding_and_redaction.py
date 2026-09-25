from __future__ import annotations

import shield.agent_core.cortex_memory as cortex_memory
from shield.backend.store import ShieldStore
from shield.codex_agent import redact_event
from shield.agent_core.cortex_memory import CortexMemoryProvider
from types import SimpleNamespace
import json
import time


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


def test_cortex_outbox_preserves_frozen_correlation_fields(tmp_path):
    provider = CortexMemoryProvider(
        base_url="http://127.0.0.1:1", token="token", agent_id="did:integrity:agent-a",
        device_id="device-a", outbox_path=tmp_path / "outbox.sqlite3", max_attempts=1,
    )
    event = SimpleNamespace(to_dict=lambda: {
        "class": "agent_event", "event_id": "evt-correlation", "device_id": "device-a",
        "invocation_id": "018f3f62-9ca4-7db5-8a7a-6c26c9f9d820",
        "reporting_window": "2026-09-24T00:00:00Z/2026-09-24T23:59:59Z",
        "provenance": {"source_kind": "shield_event", "locator": "shield://device-a/evt-correlation"},
        "privacy": {"redacted": True, "proof": "sha256:fixture"},
        "message": "not allowlisted",
    })
    decision = SimpleNamespace(
        to_dict=lambda: {"invocation_id": "018f3f62-9ca4-7db5-8a7a-6c26c9f9d820", "action": "log_only"},
        event_ref=SimpleNamespace(event_id="evt-correlation"),
    )
    provider.remember_event(event, decision)
    with provider._connect_outbox() as conn:
        payload = json.loads(conn.execute("SELECT payload_json FROM cortex_outbox").fetchone()[0])
    metadata = payload["source"]["metadata"]
    assert metadata["event_id"] == "evt-correlation"
    assert metadata["invocation_id"] == "018f3f62-9ca4-7db5-8a7a-6c26c9f9d820"
    assert metadata["reporting_window"] == "2026-09-24T00:00:00Z/2026-09-24T23:59:59Z"
    assert metadata["provenance"]["locator"].endswith("evt-correlation")
    assert "message" not in payload["content"]


def test_cortex_outbox_ignores_unsafe_parallelism_and_batch_size(tmp_path, monkeypatch):
    provider = CortexMemoryProvider(
        base_url="http://127.0.0.1:1", token="token", agent_id="agent-a",
        device_id="device-a", outbox_path=tmp_path / "outbox.sqlite3",
    )
    for index in range(25):
        provider._enqueue({"content": str(index)}, f"event-{index}")
    monkeypatch.setenv("XIBALBA_CORTEX_OUTBOX_WORKERS", "32")
    monkeypatch.setattr(provider, "_publish", lambda row: True)
    result = provider.flush(limit=1000)
    assert result["attempted"] == 10
    assert result["delivered"] == 10


def test_cortex_outbox_worker_flush_can_skip_unbounded_counts(tmp_path):
    provider = CortexMemoryProvider(
        base_url="http://127.0.0.1:1", token="token", agent_id="agent-a",
        device_id="device-a", outbox_path=tmp_path / "outbox.sqlite3",
    )
    provider._enqueue({"content": "bounded"}, "event-1")
    provider._publish = lambda row: True

    result = provider.flush(limit=10, include_counts=False)

    assert result == {"attempted": 1, "delivered": 1, "pending": None, "dead_letter": None}


def test_cortex_outbox_uses_orderable_due_index_and_prunes_only_old_sent_rows(tmp_path):
    provider = CortexMemoryProvider(
        base_url="http://127.0.0.1:1", token="token", agent_id="agent-a",
        device_id="device-a", outbox_path=tmp_path / "outbox.sqlite3",
    )
    with provider._connect_outbox() as conn:
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM cortex_outbox "
            "WHERE status='pending' AND next_attempt_at<=? "
            "ORDER BY next_attempt_at, created_at LIMIT ?", (time.time(), 10),
        ).fetchall()
        assert all("TEMP B-TREE" not in str(row[3]).upper() for row in plan)
        conn.execute("INSERT INTO cortex_outbox(id,payload_json,status,created_at,sent_at) VALUES('old','{}','sent',0,0)")
        conn.execute("INSERT INTO cortex_outbox(id,payload_json,status,created_at) VALUES('pending','{}','pending',0)")
    assert provider._prune_sent(now=time.time() + 2 * 86400) == 1
    with provider._connect_outbox() as conn:
        assert conn.execute("SELECT status FROM cortex_outbox WHERE id='pending'").fetchone()[0] == "pending"
        assert conn.execute("SELECT COUNT(*) FROM cortex_outbox WHERE id='old'").fetchone()[0] == 0


def test_cortex_outbox_rejects_oversize_payloads(tmp_path):
    provider = CortexMemoryProvider(
        base_url="http://127.0.0.1:1", token="token", agent_id="agent-a",
        device_id="device-a", outbox_path=tmp_path / "outbox.sqlite3",
    )
    provider._enqueue({"content": "x" * 70000}, "oversize")
    assert provider.status()["pending"] == 0
    assert provider.metrics()["oversize_dropped_total"] == 1


def test_cortex_outbox_honors_demo_payload_and_pending_limits(tmp_path):
    provider = CortexMemoryProvider(
        base_url="http://127.0.0.1:1", token="token", agent_id="agent-a",
        device_id="device-a", outbox_path=tmp_path / "outbox.sqlite3",
        max_payload_bytes=128, max_pending_rows=2,
    )
    provider._enqueue({"content": "x" * 129}, "oversize")
    provider._enqueue({"content": "one"}, "one")
    provider._enqueue({"content": "two"}, "two")
    provider._enqueue({"content": "three"}, "three")
    assert provider.status()["pending"] == 2
    assert provider.metrics()["oversize_dropped_total"] == 1
    assert provider.metrics()["pending_depth_dropped_total"] == 1


def test_cortex_outbox_rejects_when_storage_ceiling_is_reached(tmp_path, monkeypatch):
    provider = CortexMemoryProvider(
        base_url="http://127.0.0.1:1", token="token", agent_id="agent-a",
        device_id="device-a", outbox_path=tmp_path / "outbox.sqlite3",
    )
    monkeypatch.setattr(
        cortex_memory, "_OUTBOX_MAX_BYTES", provider._outbox_size_bytes() + 1,
    )
    provider._enqueue({"content": "bounded"}, "capacity")
    assert provider.status()["pending"] == 0
    assert provider.metrics()["capacity_dropped_total"] == 1
