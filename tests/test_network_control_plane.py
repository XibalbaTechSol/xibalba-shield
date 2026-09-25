from datetime import datetime, timezone

from shield.hermes_transport import HermesSpool
from shield.network_control_plane import NetworkControlPlane
from shield.network_adapters import DisposableMemoryAdapter, NetworkActionExecutor
from shield.network_ingestion import NetworkEventIngestor
from shield.network_policy import NetworkActionRequest, NetworkIdentity
from shield.network_policy_engine import NetworkPolicyEngine


def test_control_plane_evaluates_before_redacted_durable_delivery(tmp_path):
    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32)
    ingestor = NetworkEventIngestor(spool, ref_key=b"r" * 32)
    plane = NetworkControlPlane(policy_engine=NetworkPolicyEngine.from_dicts([
        {"rule_id": "new-destination", "action": "escalate", "reason_code": "NEW_DESTINATION", "match": {"flow.destination_class": "new"}, "require_approval": True}
    ]), ingestor=ingestor)
    observed = {"class": "flow", "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "flow": {"destination_class": "new", "dst_ip": "203.0.113.10", "dst_port": 443, "protocol": "tcp"}}
    result = plane.handle(observed, network_id="corp", segment_id="users", observation_point="endpoint", sensor_id="sensor-a", device_id="device-a", sequence=1)
    assert result.decision.action == "escalate"
    rows = []
    assert spool.consume_network_once(rows.append)["acknowledged"] == 1
    assert rows[0]["policy"]["rule_id"] == "new-destination"
    assert rows[0]["policy"]["human_review_required"] is True
    assert "203.0.113.10" not in str(rows[0])


def test_control_plane_enforces_locally_and_records_ack_without_hermes_dependency(tmp_path):
    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32)
    ingestor = NetworkEventIngestor(spool, ref_key=b"r" * 32, clock=lambda: 100.0)
    adapter = DisposableMemoryAdapter(clock=lambda: 100.0)
    plane = NetworkControlPlane(
        policy_engine=NetworkPolicyEngine.from_dicts([]),
        ingestor=ingestor,
        action_executor=NetworkActionExecutor([adapter], clock=lambda: 100.0),
    )
    observed = {"class": "flow", "observed_at": datetime.fromtimestamp(100.0, timezone.utc).isoformat().replace("+00:00", "Z"), "flow": {"dst_port": 443, "protocol": "tcp"}}
    request = NetworkActionRequest("block_flow", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64, dry_run=False)
    result = plane.enforce(
        observed,
        request,
        NetworkIdentity("sha256:" + "1" * 64, "enrollment", "known", 1.0, 1),
        adapter_ref=adapter.adapter_ref,
        network_id="corp",
        segment_id="users",
        observation_point="endpoint",
        sensor_id="sensor-a",
        device_id="device-a",
        sequence=1,
    )
    assert result.adapter_result.status == "completed"
    rows = []
    assert spool.consume_network_once(rows.append)["acknowledged"] == 1
    assert rows[0]["enforcement"]["status"] == "completed"
