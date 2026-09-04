"""Unit coverage for IntegrityExporter.health() -- deliberately NOT gated behind a live
bcc_middleware (unlike test_integrity_exporter.py's end-to-end test), since this only
exercises the local failure-counter/queue-depth bookkeeping, not a real network path.
Identity creation and the telemetry client are mocked out so this doesn't touch disk or
require network either."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from shield.schemas.events import Activity, Decision, EventRef, PolicyDecision, RuleRef


def _decision() -> PolicyDecision:
    return PolicyDecision(
        device_id="dev-test",
        event_ref=EventRef(klass="network_flow", event_id="evt-test-1"),
        rule=RuleRef(rule_id="test-rule", name="test", version="1.0.0"),
        decision=Decision(action="deny", reason="test decision", severity="medium"),
    )


@patch("shield.integrity_exporter.exporter.IntegrityClient")
@patch("shield.integrity_exporter.exporter.sdk_did.load_or_create_did")
@patch("shield.integrity_exporter.exporter.bcc")
def test_health_starts_at_zero_failures(mock_bcc, mock_load_did, mock_client_cls):
    from shield.integrity_exporter import IntegrityExporter

    mock_load_did.return_value = ("did:test:agent", object(), {})
    mock_bcc.NonceStore.return_value = MagicMock()
    mock_client_cls.return_value = MagicMock(_batcher=None)

    exporter = IntegrityExporter(bcc_middleware_url="http://unused")

    assert exporter.health() == {"export_failures": 0, "queue_depth": None}


@patch("shield.integrity_exporter.exporter.IntegrityClient")
@patch("shield.integrity_exporter.exporter.sdk_did.load_or_create_did")
@patch("shield.integrity_exporter.exporter.bcc")
def test_health_counts_export_failures_without_raising(mock_bcc, mock_load_did, mock_client_cls):
    from shield.integrity_exporter import IntegrityExporter

    mock_load_did.return_value = ("did:test:agent", object(), {})
    mock_bcc.NonceStore.return_value = MagicMock(next=MagicMock(return_value="nonce-1"))
    mock_bcc.build_bcc_commitment.return_value = {
        "agent_id": "did:test:agent", "nonce": "nonce-1", "intended_state_hash": "h",
    }
    mock_bcc.submit_commitment.side_effect = RuntimeError("bcc_middleware unreachable")
    mock_client_cls.return_value = MagicMock(_batcher=MagicMock(queue_depth=MagicMock(return_value=2)))

    exporter = IntegrityExporter(bcc_middleware_url="http://unused")

    result = exporter.export_decision(_decision())

    assert result["authorized"] is False
    assert exporter.health() == {"export_failures": 1, "queue_depth": 2}

    exporter.export_decision(_decision())
    assert exporter.health()["export_failures"] == 2


@patch("shield.integrity_exporter.exporter.IntegrityClient")
@patch("shield.integrity_exporter.exporter.sdk_did.load_or_create_did")
@patch("shield.integrity_exporter.exporter.bcc")
def test_health_never_calls_the_consuming_drain_api(mock_bcc, mock_load_did, mock_client_cls):
    """health() must read queue_depth() only -- drain_dropped_count() is a consuming read
    the SDK's own flush_telemetry relies on being the sole caller of (see exporter.py's
    health() docstring). A regression here would silently steal/undercount that metric."""
    from shield.integrity_exporter import IntegrityExporter

    mock_load_did.return_value = ("did:test:agent", object(), {})
    mock_bcc.NonceStore.return_value = MagicMock()
    batcher = MagicMock(queue_depth=MagicMock(return_value=0))
    mock_client_cls.return_value = MagicMock(_batcher=batcher)

    exporter = IntegrityExporter(bcc_middleware_url="http://unused")
    exporter.health()

    batcher.drain_dropped_count.assert_not_called()
