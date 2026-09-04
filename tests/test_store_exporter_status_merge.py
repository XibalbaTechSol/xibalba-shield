"""upsert_exporter_status must merge, not replace -- a real device's watchdog publish
(policy/opa/sensors/exporter) and the demo-seed path (did_registered/bcc_middleware/
oracle_readback/synthetic/endpoint_posture) write into the same status document, and
neither writer knows the other's full key set."""

from __future__ import annotations

from shield.backend.store import ShieldStore


def test_upsert_exporter_status_merges_new_keys_over_existing(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.enroll_device(tenant_id="tenant-a", device_id="dev-1", base_url="http://backend")

    store.upsert_exporter_status(
        tenant_id="tenant-a",
        device_id="dev-1",
        status={"did_registered": True, "bcc_middleware": "connected"},
    )
    store.upsert_exporter_status(
        tenant_id="tenant-a",
        device_id="dev-1",
        status={"opa": {"healthy": True}, "sensors": {"attached": True, "lost_events": 0}},
    )

    [row] = store.list_exporter_status(tenant_id="tenant-a")
    assert row["status"]["did_registered"] is True
    assert row["status"]["bcc_middleware"] == "connected"
    assert row["status"]["opa"] == {"healthy": True}
    assert row["status"]["sensors"] == {"attached": True, "lost_events": 0}


def test_upsert_exporter_status_new_write_overrides_same_key(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.enroll_device(tenant_id="tenant-a", device_id="dev-1", base_url="http://backend")

    store.upsert_exporter_status(tenant_id="tenant-a", device_id="dev-1", status={"opa": {"healthy": True}})
    store.upsert_exporter_status(tenant_id="tenant-a", device_id="dev-1", status={"opa": {"healthy": False}})

    [row] = store.list_exporter_status(tenant_id="tenant-a")
    assert row["status"]["opa"] == {"healthy": False}
