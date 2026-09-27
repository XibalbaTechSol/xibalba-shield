from datetime import datetime, timezone

import pytest

from shield.hermes_network_consumer import HermesNetworkConsumer
from shield.hermes_transport import HermesSpool
from shield.network_ingestion import NetworkEventIngestor


def test_consumer_receives_authenticated_redacted_events_as_advisories(tmp_path):
    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32)
    ingestor = NetworkEventIngestor(spool, ref_key=b"r" * 32)
    ingestor.ingest({"class": "flow", "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "flow": {"dst_ip": "203.0.113.8", "dst_port": 443}}, network_id="n", segment_id="s", observation_point="endpoint", sensor_id="sensor", device_id="d", sequence=1)
    consumer = HermesNetworkConsumer(spool, lambda payload: {"classification": payload["event"]["class"], "confidence": 0.8, "recommendation": "observe", "evidence_refs": [payload["event_id"]]})
    result, advisories = consumer.consume_once()
    assert result["acknowledged"] == 1
    assert advisories[0]["classification"] == "flow"


def test_consumer_rejects_command_like_analysis(tmp_path):
    spool = HermesSpool(tmp_path / "spool", key=b"k" * 32)
    ingestor = NetworkEventIngestor(spool, ref_key=b"r" * 32)
    ingestor.ingest({"class": "flow", "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}, network_id="n", segment_id="s", observation_point="endpoint", sensor_id="sensor", device_id="d", sequence=1)
    consumer = HermesNetworkConsumer(spool, lambda _: {"command": "nft flush ruleset"})
    result, advisories = consumer.consume_once()
    assert result["failed"] == 1
    assert advisories == []
