"""Chaos and adversarial test coverage for docs/PRODUCTION_READINESS_PLAN.md §7 item 6 /
workstream I ("Chaos tests for service kill, sensor unload, network loss, disk exhaustion,
key loss, policy rollback, and clock skew" / "Adversarial tests for prompt/tool abuse, policy
bypass, replay, downgrade, event flooding, PID reuse, and containment failure").

This file adds ONLY the scenarios not already covered elsewhere -- see
docs/design/threat-model-matrix-2026-09-06.md for the full 14-scenario map, including which
of these are covered by pre-existing tests (test_hot_reload.py for downgrade/rollback,
test_config_signing.py for tampered/expired/untrusted signatures, test_guardrail_hooks.py for
prompt/tool abuse, test_agent_core.py's test_router_exports_telemetry_for_every_decision for
policy-bypass visibility, test_exporter_spool.py for network-loss/outage resilience) and which
are NOT independently tested here (PID reuse -- kernel-side eBPF map correlation, disclosed as
an architectural limitation, not fabricated as a test that doesn't actually exercise it).
"""

from __future__ import annotations

import os
import stat
from unittest.mock import MagicMock, patch

import pytest

from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.integrity_exporter import spool
from shield.policy_engine.engine import PolicyEngine
from shield.schemas.events import Activity, EnforcementOutcome, ProcessActivity, ProcessInfo
from shield.watchdog import Watchdog


def _router(**kwargs) -> EventRouter:
    device = DeviceContext(device_id="dev-1", tenant_id="t", device_role="workstation")
    return EventRouter(
        device=device,
        registry=kwargs.get("registry", AgentRegistry()),
        policy_engine=kwargs.get("policy_engine", PolicyEngine()),
        exporter=kwargs.get("exporter"),
        action_broker=kwargs.get("action_broker"),
        event_log=kwargs.get("event_log"),
        enforcement_outcome_sink=kwargs.get("enforcement_outcome_sink"),
    )


def _force_action(engine, action):
    original = engine.evaluate

    def _evaluate(event, context):
        decision = original(event, context)
        decision.decision.action = action
        return decision

    engine.evaluate = _evaluate
    return engine


# --- Adversarial: containment failure -------------------------------------------------


def test_containment_failure_reports_a_truthful_enforcement_outcome():
    """A real, common containment failure: the target process already exited between
    the sensor observing it and ActionBroker.contain() acting on its pid
    (ProcessLookupError, a real errno-ESRCH OSError subclass -- not a fabricated
    exception type). The router must not crash, and the enforcement-outcome sink must
    receive `completed=False` with the real error, not silently report success or drop
    the outcome entirely."""

    class _RaisingBroker:
        def contain(self, pid, **kwargs):
            raise ProcessLookupError(f"no such process: {pid}")

    outcomes: list[EnforcementOutcome] = []
    engine = _force_action(PolicyEngine(), "contain")
    router = _router(policy_engine=engine, action_broker=_RaisingBroker(), enforcement_outcome_sink=outcomes.append)

    decision = router.handle(ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=4242, name="bash"),
        activity=Activity(type="launch"),
    ))

    assert decision is not None  # did not raise
    assert len(outcomes) == 1
    assert outcomes[0].completed is False
    assert outcomes[0].action == "contain"
    assert "no such process" in outcomes[0].error


# --- Adversarial: replay (local nonce monotonicity) ------------------------------------


@patch("shield.integrity_exporter.exporter.IntegrityClient")
@patch("shield.integrity_exporter.exporter.sdk_did.load_or_create_did")
def test_sequential_exports_use_strictly_increasing_nonces(mock_load_did, mock_client_cls, tmp_path, monkeypatch):
    """Real (non-mocked) `bcc.NonceStore` and a real Ed25519 keypair -- only
    `bcc.submit_commitment`/network is mocked -- proves the local replay-protection
    wiring actually produces a strictly increasing sequence across real, sequential
    exports, not just that a NonceStore class exists somewhere. bcc_middleware's own
    server-side monotonic check (app/nonce_store.py) is this defense in depth's other
    half, out of this repo. INTEGRITY_DID_HOME is redirected to tmp_path so the real
    NonceStore file this test exercises doesn't touch the developer's actual
    ~/.integrity state."""
    from integrity_sdk.did import Keypair

    from shield.integrity_exporter import IntegrityExporter
    from shield.schemas.events import Decision, EventRef, PolicyDecision, RuleRef

    monkeypatch.setenv("INTEGRITY_DID_HOME", str(tmp_path / "did-home"))
    mock_load_did.return_value = ("did:test:agent", Keypair.generate(), {})
    mock_client_cls.return_value = MagicMock(_batcher=None)

    captured_nonces = []

    def _fake_submit(commitment, url):
        captured_nonces.append(commitment["nonce"])
        return {"authorized": True}

    exporter = IntegrityExporter(bcc_middleware_url="http://unused", spool_db_path=tmp_path / "spool.db")

    with patch("shield.integrity_exporter.exporter.bcc.submit_commitment", side_effect=_fake_submit):
        for i in range(5):
            exporter.export_decision(PolicyDecision(
                device_id="dev-test",
                event_ref=EventRef(klass="network_flow", event_id=f"evt-{i}"),
                rule=RuleRef(rule_id="test-rule", name="test", version="1.0.0"),
                decision=Decision(action="deny", reason="test", severity="medium"),
            ))

    assert len(captured_nonces) == 5
    assert captured_nonces == sorted(captured_nonces)
    assert len(set(captured_nonces)) == 5  # no repeats


# --- Adversarial: event flooding --------------------------------------------------------


def test_router_survives_and_records_a_burst_of_events_without_silent_loss():
    """A burst of events (event-flooding scenario) must not crash the router or
    silently drop decisions at the software layer -- eBPF ring-buffer-level loss under
    real kernel load is a separate, already-covered concern
    (test_lost_events_counter_reflects_bcc_lost_cb)."""
    router = _router()
    decisions = [
        router.handle(ProcessActivity(
            device_id="dev-1",
            process=ProcessInfo(pid=1000 + i, name="burst.exe"),
            activity=Activity(type="launch"),
        ))
        for i in range(500)
    ]

    assert len(decisions) == 500
    assert all(d is not None for d in decisions)
    assert len({d.event_ref.event_id for d in decisions}) == 500  # every event distinctly identified


# --- Chaos: disk exhaustion (spool write failure) ---------------------------------------


def test_spool_enqueue_survives_an_unwritable_path_without_raising(tmp_path):
    """Simulates disk exhaustion / a read-only filesystem: the spool's own directory
    cannot be created. `enqueue()` must log and return, never raise -- a real disk
    failure during containment/export must not also crash the enforcement path that
    was trying to record it."""
    unwritable_parent = tmp_path / "readonly"
    unwritable_parent.mkdir()
    unwritable_parent.chmod(stat.S_IREAD | stat.S_IEXEC)  # read+execute, no write
    db_path = unwritable_parent / "nested" / "spool.db"

    try:
        spool.enqueue(db_path, kind="decision", payload={"agent_id": "did:test", "nonce": 1}, error="disk full")
        # No exception -- the whole point of this test. status() also degrades cleanly:
        # the db file was never created, so this reads as "nothing pending" rather than
        # erroring, which is the honest answer given the write never happened.
        assert spool.status(db_path) == {"pending": 0, "oldest_age_seconds": None}
    finally:
        unwritable_parent.chmod(stat.S_IRWXU)  # restore so tmp_path cleanup can remove it


@patch("shield.integrity_exporter.exporter.IntegrityClient")
@patch("shield.integrity_exporter.exporter.sdk_did.load_or_create_did")
@patch("shield.integrity_exporter.exporter.bcc")
def test_export_decision_still_returns_a_clean_failure_when_disk_is_also_full(mock_bcc, mock_load_did, mock_client_cls, tmp_path):
    """Compound failure: bcc_middleware is unreachable AND the spool write also fails
    (disk exhaustion during an outage -- the worst case these two chaos scenarios
    combine into). export_decision() must still return its normal failure dict, not
    raise a second, unrelated exception that masks the original submission failure."""
    from shield.integrity_exporter import IntegrityExporter
    from shield.schemas.events import Activity as EvActivity, Decision, EventRef, PolicyDecision, RuleRef

    mock_load_did.return_value = ("did:test:agent", object(), {})
    mock_bcc.NonceStore.return_value = MagicMock(next=MagicMock(return_value="nonce-1"))
    mock_bcc.build_bcc_commitment.return_value = {"agent_id": "did:test:agent", "nonce": "nonce-1", "intended_state_hash": "h"}
    mock_bcc.submit_commitment.side_effect = RuntimeError("bcc_middleware unreachable")
    mock_client_cls.return_value = MagicMock(_batcher=None)

    unwritable_parent = tmp_path / "readonly"
    unwritable_parent.mkdir()
    unwritable_parent.chmod(stat.S_IREAD | stat.S_IEXEC)

    exporter = IntegrityExporter(bcc_middleware_url="http://unused", spool_db_path=unwritable_parent / "nested" / "spool.db")
    try:
        result = exporter.export_decision(PolicyDecision(
            device_id="dev-test",
            event_ref=EventRef(klass="network_flow", event_id="evt-1"),
            rule=RuleRef(rule_id="test-rule", name="test", version="1.0.0"),
            decision=Decision(action="deny", reason="test", severity="medium"),
        ))
        assert result["authorized"] is False
        assert "submission failed" in result["reason"]
    finally:
        unwritable_parent.chmod(stat.S_IRWXU)


# --- Chaos: sensor unload (watchdog resilience) -----------------------------------------


@patch("shield.watchdog.publish_runtime_status")
def test_tick_still_publishes_when_sensor_health_itself_raises(mock_publish):
    """A dead/unloaded sensor whose own health() call raises (not just returns
    attached=False) must not abort the entire watchdog tick before publish_runtime_status
    runs -- previously it did, meaning the dashboard kept showing stale "healthy" data
    during exactly the failure this watchdog exists to catch."""
    policy_engine = MagicMock()
    policy_engine.health_status.return_value = {"healthy": True}
    sensor = MagicMock()
    sensor.health.side_effect = RuntimeError("BPF program no longer attached")

    watchdog = Watchdog(
        interval=1.0,
        device_config=MagicMock(),
        policy_engine=policy_engine,
        reloader=None,
        opa_supervisor=None,
        exporter=None,
        sensor=sensor,
    )

    watchdog.tick()  # must not raise

    mock_publish.assert_called_once()
    _, kwargs = mock_publish.call_args
    assert kwargs["sensors_status"]["attached"] is False
    assert "BPF program no longer attached" in kwargs["sensors_status"]["error"]


@patch("shield.watchdog.publish_runtime_status")
def test_tick_still_publishes_when_exporter_replay_pending_raises(mock_publish):
    """Same resilience contract for the exporter side: a spool/replay failure must not
    prevent the tick from publishing whatever status IS available."""
    policy_engine = MagicMock()
    policy_engine.health_status.return_value = {"healthy": True}
    sensor = MagicMock()
    sensor.health.return_value = {"attached": True}
    exporter = MagicMock()
    exporter.replay_pending.side_effect = RuntimeError("spool db is locked")
    exporter.health.return_value = {"export_failures": 0}

    watchdog = Watchdog(
        interval=1.0,
        device_config=MagicMock(),
        policy_engine=policy_engine,
        reloader=None,
        opa_supervisor=None,
        exporter=exporter,
        sensor=sensor,
    )

    watchdog.tick()  # must not raise

    mock_publish.assert_called_once()
    _, kwargs = mock_publish.call_args
    assert kwargs["exporter_status_detail"] == {"export_failures": 0}


# --- Chaos: key loss (corrupted signing key file) ---------------------------------------


def test_sign_policy_reports_a_clean_error_for_a_corrupted_key_file(tmp_path, capsys):
    from shield.cli import main

    key_path = tmp_path / "signing.key"
    key_path.write_bytes(b"this is not a real PEM-encoded Ed25519 key")
    input_path = tmp_path / "policy.json"
    input_path.write_text('{"rules": []}')
    output_path = tmp_path / "signed.json"

    code = main(["sign-policy", "--key", str(key_path), "--in", str(input_path), "--out", str(output_path)])

    assert code == 1
    err = capsys.readouterr().err
    assert "cannot load existing key" in err
    assert "Traceback" not in err
    assert not output_path.exists()


# --- Chaos: service kill / restart recovery (durable spool across a fresh instance) -----


@patch("shield.integrity_exporter.exporter.IntegrityClient")
@patch("shield.integrity_exporter.exporter.sdk_did.load_or_create_did")
@patch("shield.integrity_exporter.exporter.bcc")
def test_a_fresh_exporter_instance_after_restart_delivers_what_the_old_one_spooled(mock_bcc, mock_load_did, mock_client_cls, tmp_path):
    """Simulates `systemctl restart` / a crash-and-respawn: the OLD IntegrityExporter
    instance is discarded (as a process restart would discard it) and a NEW one is
    constructed pointed at the same durable spool path -- the real continuity guarantee
    a durable, disk-backed spool exists to provide."""
    from shield.integrity_exporter import IntegrityExporter
    from shield.schemas.events import Activity as EvActivity, Decision, EventRef, PolicyDecision, RuleRef

    mock_load_did.return_value = ("did:test:agent", object(), {})
    mock_bcc.NonceStore.return_value = MagicMock(next=MagicMock(return_value="nonce-1"))
    mock_bcc.build_bcc_commitment.return_value = {"agent_id": "did:test:agent", "nonce": "nonce-1", "intended_state_hash": "h"}
    mock_bcc.submit_commitment.side_effect = RuntimeError("bcc_middleware unreachable")
    mock_client_cls.return_value = MagicMock(_batcher=None)

    spool_path = tmp_path / "spool.db"
    old_exporter = IntegrityExporter(bcc_middleware_url="http://unused", spool_db_path=spool_path)
    old_exporter.export_decision(PolicyDecision(
        device_id="dev-test",
        event_ref=EventRef(klass="network_flow", event_id="evt-1"),
        rule=RuleRef(rule_id="test-rule", name="test", version="1.0.0"),
        decision=Decision(action="deny", reason="test", severity="medium"),
    ))
    assert spool.status(spool_path)["pending"] == 1
    del old_exporter  # simulates the process exiting

    mock_bcc.submit_commitment.side_effect = None
    mock_bcc.submit_commitment.return_value = {"authorized": True}
    new_exporter = IntegrityExporter(bcc_middleware_url="http://unused", spool_db_path=spool_path)
    result = new_exporter.replay_pending()

    assert result.delivered == 1
    assert spool.status(spool_path)["pending"] == 0
