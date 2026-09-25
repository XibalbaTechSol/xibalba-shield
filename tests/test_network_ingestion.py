from datetime import datetime, timezone

import pytest

from shield.hermes_transport import HermesSpool
from shield.network_ingestion import NetworkEventIngestor, NetworkIngestionError


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ingestor(tmp_path):
    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32)
    return NetworkEventIngestor(spool, ref_key=b"r" * 32), spool


def _event(sequence=1, event_id=None):
    value = {"class": "flow", "observed_at": _now(), "flow": {"dst_ip": "203.0.113.9", "dst_port": 443, "protocol": "tcp"}}
    if event_id:
        value["event_id"] = event_id
    return value


def _identity(sequence=1):
    return {"network_id": "corp", "segment_id": "users", "observation_point": "endpoint", "sensor_id": "sensor-a", "device_id": "device-a", "sequence": sequence}


def test_ingestion_publishes_redacted_event_and_consumes_separately(tmp_path):
    ingestor, spool = _ingestor(tmp_path)
    delivery_id = ingestor.ingest(_event(1), **_identity(1))
    received = []
    assert delivery_id
    assert spool.consume_network_once(received.append)["acknowledged"] == 1
    assert received[0]["schema"] == "xibalba.shield.hermes.network_event"
    assert spool.consume_once(lambda _: received.append("endpoint"))["processed"] == 0


def test_replay_and_duplicate_are_bounded(tmp_path):
    ingestor, _ = _ingestor(tmp_path)
    ingestor.ingest(_event(1, "net-1"), **_identity(1))
    with pytest.raises(NetworkIngestionError, match="strictly increasing"):
        ingestor.ingest(_event(2, "net-2"), **_identity(1))
    assert ingestor.ingest(_event(2, "net-1"), **_identity(2)) is None
    assert ingestor.metrics()["replay_dropped_total"] == 1
    assert ingestor.metrics()["duplicate_dropped_total"] == 1


def test_clock_skew_and_capacity_are_rejected(tmp_path):
    ingestor, _ = _ingestor(tmp_path)
    with pytest.raises(NetworkIngestionError, match="clock-skew"):
        ingestor.ingest({**_event(1), "observed_at": "2000-01-01T00:00:00Z"}, **_identity(1))
    assert ingestor.metrics()["clock_skew_dropped_total"] == 1
