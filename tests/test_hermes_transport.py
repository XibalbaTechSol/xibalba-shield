from __future__ import annotations

from shield.hermes_contract import build_event
from shield.hermes_transport import HermesSpool
from shield.schemas.events import Activity, Decision, EventRef, PolicyDecision, ProcessActivity, ProcessInfo, RuleRef


def _payload(tmp_path):
    event = ProcessActivity(device_id="device", tenant_id="tenant", process=ProcessInfo(pid=2, name="init"), activity=Activity(type="exec"))
    decision = PolicyDecision(device_id="device", event_ref=EventRef(klass="process_activity", event_id="evt-1"), rule=RuleRef(rule_id="r1", name="observed", version="1"), decision=Decision(action="log_only"))
    return build_event(event, decision, sensor="linux-ebpf-process")


def test_spool_authenticates_acknowledges_and_replays_safely(tmp_path):
    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32)
    payload = _payload(tmp_path)
    assert spool.publish(payload, delivery_id="delivery-1") == "delivery-1"
    seen = []
    assert spool.consume_once(seen.append) == {"processed": 1, "acknowledged": 1, "malformed": 0, "failed": 0, "replayed": 0}
    assert seen[0]["event_id"] == "evt-1"
    assert spool.status()["pending"] == 0


def test_spool_rejects_tampering_and_counts_malformed(tmp_path):
    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32)
    payload = _payload(tmp_path)
    spool.publish(payload, delivery_id="delivery-2")
    path = next((tmp_path / "spool" / "pending").glob("*.json"))
    text = path.read_text().replace("evt-1", "evt-tampered")
    path.write_text(text)
    result = spool.consume_once(lambda _: None)
    assert result["malformed"] == 1
    assert spool.metrics()["malformed_total"] == 1


def test_spool_capacity_is_bounded(tmp_path):
    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32, max_bytes=64 * 1024)
    payload = _payload(tmp_path)
    accepted = [spool.publish(payload, delivery_id=f"delivery-{index}") for index in range(100)]
    assert any(item is None for item in accepted)
    assert spool.metrics()["capacity_dropped_total"] > 0


def test_inspect_status_is_read_only_and_reports_dead_letters(tmp_path):
    root = tmp_path / "spool"
    spool = HermesSpool(root, key=b"k" * 32)
    payload = _payload(tmp_path)
    spool.publish(payload, delivery_id="delivery-status")
    status = HermesSpool.inspect_status(root)
    assert status["pending"] == 1
    assert status["dead_letters"] == 0
    assert status["configured"] is True
    assert status["spool_depth"] == 1
    spool.consume_once(lambda _: None)
    status = HermesSpool.inspect_status(root)
    assert status["acknowledgements"] == 1
    assert status["spool_depth"] == 0
    assert not (root / "pending" / "state.sqlite3").exists()


def test_default_spool_refuses_group_access(tmp_path):
    import os
    import pytest
    from shield.hermes_transport import HermesTransportError

    root = tmp_path / "spool"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o750)
    with pytest.raises(HermesTransportError):
        HermesSpool(root, key=b"k" * 32)


def test_group_shared_spool_sets_group_modes_under_strict_umask(tmp_path):
    # The sensor unit runs with UMask=0077; group_shared must still leave the envelope
    # group-readable and the state database group-writable for the analyst account.
    import os
    import stat

    old_umask = os.umask(0o077)
    try:
        spool = HermesSpool(tmp_path / "spool", key=b"k" * 32, group_shared=True)
        spool.publish(_payload(tmp_path), delivery_id="delivery-g")
    finally:
        os.umask(old_umask)
    root_mode = stat.S_IMODE((tmp_path / "spool").stat().st_mode)
    assert root_mode == 0o2770
    envelope = next((tmp_path / "spool" / "pending").glob("*.json"))
    assert stat.S_IMODE(envelope.stat().st_mode) == 0o640
    assert stat.S_IMODE(spool.state_path.stat().st_mode) == 0o660


def test_group_shared_spool_still_refuses_world_access(tmp_path):
    import os
    import pytest
    from shield.hermes_transport import HermesTransportError

    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32, group_shared=True)
    os.chmod(spool.root, 0o2775)
    # Owner re-applies 2770 on open, so simulate a foreign-owned world-readable dir by
    # checking the guard directly after the chmod the owner would perform is skipped.
    spool._chmod_if_owner = lambda path, mode: None  # type: ignore[method-assign]
    with pytest.raises(HermesTransportError):
        spool._ensure_dirs()
