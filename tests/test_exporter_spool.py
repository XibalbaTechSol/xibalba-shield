"""Coverage for `shield/integrity_exporter/spool.py` -- real SQLite against `tmp_path`
(durability across a simulated restart is the point being tested, so this isn't mocked),
with only `bcc.submit_commitment`/network calls mocked. Mirrors
`integrity-core/bcc_middleware/tests/test_spool.py`'s conventions for consistency."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from shield.integrity_exporter import spool


def test_enqueue_then_status_reports_one_pending(tmp_path):
    db_path = tmp_path / "spool.db"
    assert spool.status(db_path) == {"pending": 0, "oldest_age_seconds": None}

    spool.enqueue(db_path, kind="decision", payload={"agent_id": "did:test", "nonce": 1}, error="timeout")

    status = spool.status(db_path)
    assert status["pending"] == 1
    assert status["oldest_age_seconds"] is not None and status["oldest_age_seconds"] >= 0


def test_retry_cycle_delivers_and_removes_row(tmp_path):
    db_path = tmp_path / "spool.db"
    spool.enqueue(db_path, kind="decision", payload={"agent_id": "did:test", "nonce": 1}, error="timeout")

    submit = MagicMock(return_value={"authorized": True})
    result = spool.run_retry_cycle(db_path, submit)

    assert result.delivered == 1
    assert result.still_pending == 0
    assert spool.status(db_path) == {"pending": 0, "oldest_age_seconds": None}
    submit.assert_called_once_with({"agent_id": "did:test", "nonce": 1})


def test_retry_cycle_delivers_regardless_of_returned_verdict(tmp_path):
    """A completed round-trip is "delivered" even if bcc_middleware's own verdict is a
    denial (e.g. BCC_NONCE_REPLAY for a commitment it already processed) -- the spool's
    job is guaranteeing the evidence arrived, not re-litigating the verdict. See
    spool.py's module docstring."""
    db_path = tmp_path / "spool.db"
    spool.enqueue(db_path, kind="decision", payload={"agent_id": "did:test", "nonce": 1}, error="timeout")

    submit = MagicMock(return_value={"authorized": False, "reason": "BCC_NONCE_REPLAY: ..."})
    result = spool.run_retry_cycle(db_path, submit)

    assert result.delivered == 1
    assert spool.status(db_path)["pending"] == 0


def test_retry_cycle_reschedules_on_continued_failure(tmp_path):
    import time

    db_path = tmp_path / "spool.db"
    spool.enqueue(db_path, kind="decision", payload={"agent_id": "did:test", "nonce": 1}, error="timeout")

    submit = MagicMock(side_effect=RuntimeError("still unreachable"))
    now = time.time()
    result = spool.run_retry_cycle(db_path, submit, now=now)

    assert result.delivered == 0
    assert result.still_pending == 1
    status = spool.status(db_path)
    assert status["pending"] == 1

    # An immediate re-poll before the backoff window elapses must not retry again yet.
    result_immediate = spool.run_retry_cycle(db_path, submit, now=now + 1)
    assert result_immediate.still_pending == 0
    assert result_immediate.delivered == 0
    assert submit.call_count == 1

    # After the backoff window, it retries and can now succeed.
    submit.side_effect = None
    submit.return_value = {"authorized": True}
    result_later = spool.run_retry_cycle(db_path, submit, now=now + 3600)
    assert result_later.delivered == 1
    assert spool.status(db_path)["pending"] == 0


def test_retry_cycle_on_empty_spool_never_touches_disk(tmp_path):
    db_path = tmp_path / "spool.db"
    result = spool.run_retry_cycle(db_path, MagicMock())
    assert result == spool.RetryCycleResult(delivered=0, still_pending=0)
    assert not db_path.exists()


@patch("shield.integrity_exporter.exporter.IntegrityClient")
@patch("shield.integrity_exporter.exporter.sdk_did.load_or_create_did")
@patch("shield.integrity_exporter.exporter.bcc")
def test_replay_pending_delivers_a_previously_failed_decision(mock_bcc, mock_load_did, mock_client_cls, tmp_path):
    """End-to-end through IntegrityExporter: a failed export_decision spools, and a
    later replay_pending() (what Watchdog.tick() calls) delivers it and clears the spool."""
    from shield.schemas.events import Activity, Decision, EventRef, PolicyDecision, RuleRef

    mock_load_did.return_value = ("did:test:agent", object(), {})
    mock_bcc.NonceStore.return_value = MagicMock(next=MagicMock(return_value="nonce-1"))
    mock_bcc.build_bcc_commitment.return_value = {
        "agent_id": "did:test:agent", "nonce": "nonce-1", "intended_state_hash": "h",
    }
    mock_bcc.submit_commitment.side_effect = RuntimeError("bcc_middleware unreachable")
    mock_client_cls.return_value = MagicMock(_batcher=None)

    from shield.integrity_exporter import IntegrityExporter

    exporter = IntegrityExporter(bcc_middleware_url="http://unused", spool_db_path=tmp_path / "spool.db")
    decision = PolicyDecision(
        device_id="dev-test",
        event_ref=EventRef(klass="network_flow", event_id="evt-test-1"),
        rule=RuleRef(rule_id="test-rule", name="test", version="1.0.0"),
        decision=Decision(action="deny", reason="test decision", severity="medium"),
    )

    exporter.export_decision(decision)
    assert exporter.health()["spool_pending"] == 1

    mock_bcc.submit_commitment.side_effect = None
    mock_bcc.submit_commitment.return_value = {"authorized": True}
    result = exporter.replay_pending()

    assert result.delivered == 1
    assert exporter.health()["spool_pending"] == 0
