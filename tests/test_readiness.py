from datetime import datetime, timezone
import json

import pytest

from shield.agent_core.readiness import BASE_PROOFS, ProductionReadiness


def test_readiness_artifact_is_device_bound_and_fresh(tmp_path):
    path = tmp_path / "proof.json"
    proofs = {key: True for key in BASE_PROOFS}
    proofs.update(kill_runtime_tested=True, cgroup_runtime_tested=True, network_runtime_tested=True)
    path.write_text(json.dumps({
        "schema": "xibalba.responder-readiness.v1",
        "device_id": "dev-1",
        "generated_at": "2026-09-08T12:00:00Z",
        "proofs": proofs,
        "details": {"kill_runtime_tested": "disposable pid 42"},
    }))
    path.chmod(0o600)
    ready = ProductionReadiness.from_artifact(
        path, device_id="dev-1", now=datetime(2026, 9, 8, 12, 1, tzinfo=timezone.utc)
    )
    assert all(ready.as_dict()["ready"].values())

    with pytest.raises(ValueError, match="different device"):
        ProductionReadiness.from_artifact(path, device_id="dev-2")


def test_readiness_artifact_expires(tmp_path):
    path = tmp_path / "proof.json"
    path.write_text(json.dumps({
        "schema": "xibalba.responder-readiness.v1",
        "device_id": "dev-1",
        "generated_at": "2026-09-01T12:00:00Z",
        "proofs": {},
    }))
    path.chmod(0o600)
    with pytest.raises(ValueError, match="expired"):
        ProductionReadiness.from_artifact(
            path, device_id="dev-1", max_age_seconds=60,
            now=datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc),
        )


def test_readiness_artifact_rejects_writable_proof(tmp_path):
    path = tmp_path / "proof.json"
    path.write_text(json.dumps({
        "schema": "xibalba.responder-readiness.v1",
        "device_id": "dev-1",
        "generated_at": "2026-09-08T12:00:00Z",
        "proofs": {},
    }))
    path.chmod(0o666)
    with pytest.raises(ValueError, match="must not be group/other writable"):
        ProductionReadiness.from_artifact(
            path, device_id="dev-1",
            now=datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc),
        )
