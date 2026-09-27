"""Disposable-lab integration coverage for the local network enforcement boundary.

This deliberately exercises only the in-memory adapter. It provides an executable lab
contract for the action lifecycle without creating packets, changing DNS, or touching a
gateway/controller.
"""

from __future__ import annotations

import pytest

from shield.network_adapters import DisposableMemoryAdapter, NetworkActionExecutor
from shield.network_approval import NetworkApprovalStore
from shield.network_policy import NetworkActionRequest, NetworkGateConfig, NetworkIdentity, authorize_network_action


IDENTITY = NetworkIdentity("sha256:" + "1" * 64, "enrollment", "known", 1.0, 1)
TARGET = "sha256:" + "2" * 64
APPROVAL_REQUIRED = frozenset({"isolate_device", "move_segment", "revoke_access", "restore_access"})


def _request(action: str, suffix: str, *, approval_ref: str | None = None) -> NetworkActionRequest:
    return NetworkActionRequest(
        action,
        TARGET,
        duration_seconds=60 if action != "restore_access" else 0,
        idempotency_ref="sha256:" + suffix * 64,
        approval_ref=approval_ref,
        dry_run=False,
    )


def _approved_request(store: NetworkApprovalStore, request: NetworkActionRequest) -> NetworkActionRequest:
    pending = store.request(request)
    approved = store.approve(pending.approval_id, request, operator="lab-operator", role="network_approver")
    return NetworkActionRequest(**{**request.__dict__, "approval_ref": approved.approval_id})


@pytest.mark.parametrize(
    ("action", "suffix"),
    [("block_domain", "3"), ("block_flow", "4"), ("isolate_device", "5"), ("move_segment", "6"), ("revoke_access", "7"), ("rate_limit", "8")],
)
def test_disposable_lab_actions_acknowledge_and_restore(action: str, suffix: str, tmp_path) -> None:
    now = [100.0]
    adapter = DisposableMemoryAdapter(clock=lambda: now[0])
    approvals = NetworkApprovalStore(tmp_path / f"{action}.sqlite3")
    executor = NetworkActionExecutor([adapter], clock=lambda: now[0], approval_store=approvals)
    request = _request(action, suffix)
    if action in APPROVAL_REQUIRED:
        request = _approved_request(approvals, request)
    decision = authorize_network_action(
        IDENTITY,
        request,
        NetworkGateConfig(require_approval_for=APPROVAL_REQUIRED),
    )

    result = executor.apply(request, decision, adapter_ref=adapter.adapter_ref)

    assert result.status == "completed"
    assert result.expires_at == 160.0
    assert adapter.state[TARGET] == action
    assert executor.apply(request, decision, adapter_ref=adapter.adapter_ref) == result
    assert adapter.applied == [request.idempotency_ref]

    restore = _request("restore_access", "a", approval_ref=None)
    restore = _approved_request(approvals, restore)
    restore_decision = authorize_network_action(
        IDENTITY,
        restore,
        NetworkGateConfig(require_approval_for=APPROVAL_REQUIRED),
    )
    assert executor.apply(restore, restore_decision, adapter_ref=adapter.adapter_ref).status == "completed"
    assert TARGET not in adapter.state


def test_disposable_lab_expiry_is_bounded_and_rollback_is_explicit() -> None:
    now = [100.0]
    adapter = DisposableMemoryAdapter(clock=lambda: now[0])
    executor = NetworkActionExecutor([adapter], clock=lambda: now[0])
    request = _request("block_flow", "8")
    decision = authorize_network_action(IDENTITY, request)

    result = executor.apply(request, decision, adapter_ref=adapter.adapter_ref)
    assert result.expires_at == 160.0

    now[0] = 160.0
    assert executor.rollback(request, adapter_ref=adapter.adapter_ref).status == "completed"
    assert TARGET not in adapter.state
