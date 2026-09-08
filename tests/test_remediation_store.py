import pytest

from shield.backend.remediation import claim_next, complete, list_attempts
from shield.backend.store import ShieldStore


def _store(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.enroll_device(base_url="http://backend", tenant_id="tenant-a", device_id="dev-1", device_role="worker")
    return store


def test_claim_and_complete_are_device_scoped_and_audited(tmp_path):
    store = _store(tmp_path)
    request = store.request_exporter_remediation(tenant_id="tenant-a", device_id="dev-1", action="retry")
    claimed = claim_next(store, tenant_id="tenant-a", device_id="dev-1")
    assert claimed["id"] == request["id"] and claimed["status"] == "running"
    assert claim_next(store, tenant_id="tenant-a", device_id="dev-1") is None
    result = complete(store, tenant_id="tenant-a", device_id="dev-1", request_id=request["id"], status="completed", detail={"delivered": 2})
    assert result["status"] == "completed"
    assert list_attempts(store, tenant_id="tenant-a") == [{
        "request_id": request["id"], "tenant_id": "tenant-a", "device_id": "dev-1",
        "started_at": claimed["started_at"], "completed_at": result["completed_at"],
        "status": "completed", "detail_json": '{"delivered": 2}', "detail": {"delivered": 2},
    }]


def test_cannot_complete_unclaimed_or_wrong_device_job(tmp_path):
    store = _store(tmp_path)
    request = store.request_exporter_remediation(tenant_id="tenant-a", device_id="dev-1", action="flush")
    with pytest.raises(KeyError):
        complete(store, tenant_id="tenant-a", device_id="dev-1", request_id=request["id"], status="completed", detail={})
