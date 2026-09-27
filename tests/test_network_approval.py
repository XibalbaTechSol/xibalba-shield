import pytest

from shield.network_approval import NetworkApprovalError, NetworkApprovalStore
from shield.network_policy import NetworkActionRequest


def _action(**changes):
    values = {"action": "isolate_device", "target_ref": "sha256:" + "2" * 64, "duration_seconds": 60, "idempotency_ref": "sha256:" + "3" * 64, "requested_by": "hermes-network"}
    values.update(changes)
    return NetworkActionRequest(**values)


def test_approval_is_bound_to_intent_and_one_time(tmp_path):
    store = NetworkApprovalStore(tmp_path / "approvals.sqlite3")
    action = _action()
    pending = store.request(action)
    assert pending.status == "pending"
    with pytest.raises(NetworkApprovalError, match="role"):
        store.approve(pending.approval_id, action, operator="alice", role="observer")
    approved = store.approve(pending.approval_id, action, operator="alice", role="network_approver")
    assert approved.status == "approved"
    with pytest.raises(NetworkApprovalError, match="intent"):
        store.consume(pending.approval_id, _action(duration_seconds=120))
    assert store.consume(pending.approval_id, action).status == "consumed"
    with pytest.raises(NetworkApprovalError, match="consumable"):
        store.consume(pending.approval_id, action)


def test_pending_approval_can_be_rejected(tmp_path):
    store = NetworkApprovalStore(tmp_path / "approvals.sqlite3")
    pending = store.request(_action())
    rejected = store.reject(pending.approval_id, reason="protected recovery path")
    assert rejected.status == "rejected"
    assert rejected.reason == "protected recovery path"
