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
