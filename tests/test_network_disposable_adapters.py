"""Contract coverage for the disposable memory adapter; no packets or devices are touched."""

import pytest

from shield.network_adapters import DisposableMemoryAdapter, NetworkActionExecutor
from shield.network_approval import NetworkApprovalStore
from shield.network_policy import NetworkActionRequest, NetworkGateConfig, NetworkIdentity, authorize_network_action


IDENTITY = NetworkIdentity("sha256:" + "1" * 64, "enrollment", "known", 1.0, 1)


@pytest.mark.parametrize("action", ["block_flow", "block_domain", "isolate_device", "rate_limit", "restore_access"])
def test_disposable_adapter_contract_actions_are_bounded(action, tmp_path):
    adapter = DisposableMemoryAdapter(clock=lambda: 100.0)
    request = NetworkActionRequest(action, "sha256:" + "2" * 64, duration_seconds=30 if action != "restore_access" else 0, idempotency_ref="sha256:" + ("3" if action != "restore_access" else "4") * 64, dry_run=False)
    approval_store = None
    if action in {"isolate_device", "restore_access"}:
        approval_store = NetworkApprovalStore(tmp_path / f"{action}.sqlite3")
        pending = approval_store.request(request)
        approved = approval_store.approve(pending.approval_id, request, operator="lab-operator", role="network_approver")
        request = NetworkActionRequest(**{**request.__dict__, "approval_ref": approved.approval_id})
    decision = authorize_network_action(IDENTITY, request, NetworkGateConfig(require_approval_for=frozenset()))
    result = NetworkActionExecutor([adapter], clock=lambda: 100.0, approval_store=approval_store).apply(request, decision, adapter_ref=adapter.adapter_ref)
    assert result.status == "completed"
    assert result.adapter_ref == "disposable-memory"
    if action != "restore_access":
        assert result.expires_at == 130.0


def test_disposable_adapter_rollback_is_explicit():
    adapter = DisposableMemoryAdapter()
    request = NetworkActionRequest("block_flow", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64, dry_run=False)
    decision = authorize_network_action(IDENTITY, request)
    executor = NetworkActionExecutor([adapter])
    executor.apply(request, decision, adapter_ref=adapter.adapter_ref)
    assert executor.rollback(request, adapter_ref=adapter.adapter_ref).action == "restore_access"
