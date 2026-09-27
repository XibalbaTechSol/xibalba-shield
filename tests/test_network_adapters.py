import pytest

from shield.network_adapters import AuthenticatedTransportAdapter, AdapterExecutionError, DisposableMemoryAdapter, NetworkActionExecutor
from shield.network_approval import NetworkApprovalStore
from shield.network_policy import NetworkActionRequest, NetworkGateConfig, NetworkIdentity, authorize_network_action


class _MismatchedAcknowledgementAdapter(DisposableMemoryAdapter):
    def apply(self, request):
        result = super().apply(request)
        return result.__class__(result.action, result.status, result.adapter_ref, "sha256:" + "f" * 64)


def test_executor_is_dry_run_by_default():
    adapter = DisposableMemoryAdapter()
    executor = NetworkActionExecutor([adapter])
    request = NetworkActionRequest("block_flow", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64)
    identity = NetworkIdentity("sha256:" + "1" * 64, "enrollment", "known", 1.0, 1)
    decision = authorize_network_action(identity, request)
    result = executor.apply(request, decision, adapter_ref=adapter.adapter_ref)
    assert result.status == "preview"
    assert adapter.applied == []


def test_executor_deduplicates_and_rolls_back_explicitly():
    adapter = DisposableMemoryAdapter()
    executor = NetworkActionExecutor([adapter])
    request = NetworkActionRequest("block_flow", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64, dry_run=False)
    identity = NetworkIdentity("sha256:" + "1" * 64, "enrollment", "known", 1.0, 1)
    decision = authorize_network_action(identity, request,)
    first = executor.apply(request, decision, adapter_ref=adapter.adapter_ref)
    second = executor.apply(request, decision, adapter_ref=adapter.adapter_ref)
    assert first == second
    assert adapter.applied == [request.idempotency_ref]
    assert executor.rollback(request, adapter_ref=adapter.adapter_ref).status == "completed"


def test_executor_rejects_unregistered_or_unsupported_adapter():
    request = NetworkActionRequest("block_flow", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64, dry_run=False)
    identity = NetworkIdentity("sha256:" + "1" * 64, "enrollment", "known", 1.0, 1)
    decision = authorize_network_action(identity, request)
    executor = NetworkActionExecutor([])
    with pytest.raises(AdapterExecutionError):
        executor.apply(request, decision, adapter_ref="missing")


def test_executor_consumes_approval_before_wide_or_destructive_action(tmp_path):
    adapter = DisposableMemoryAdapter()
    approvals = NetworkApprovalStore(tmp_path / "approvals.sqlite3")
    request = NetworkActionRequest("isolate_device", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64, dry_run=False, requested_by="operator")
    identity = NetworkIdentity("sha256:" + "1" * 64, "enrollment", "known", 1.0, 1)
    decision = authorize_network_action(identity, request, config=NetworkGateConfig(require_approval_for=frozenset()))
    executor = NetworkActionExecutor([adapter], approval_store=approvals)
    with pytest.raises(AdapterExecutionError, match="approval"):
        executor.apply(request, decision, adapter_ref=adapter.adapter_ref)
    pending = approvals.request(request)
    approved = approvals.approve(pending.approval_id, request, operator="alice", role="network_approver")
    approved_request = NetworkActionRequest(**{**request.__dict__, "approval_ref": approved.approval_id})
    approved_decision = authorize_network_action(identity, approved_request, config=NetworkGateConfig(require_approval_for=frozenset()))
    assert executor.apply(approved_request, approved_decision, adapter_ref=adapter.adapter_ref).status == "completed"


def test_executor_rejects_mismatched_adapter_acknowledgement():
    adapter = _MismatchedAcknowledgementAdapter()
    executor = NetworkActionExecutor([adapter])
    request = NetworkActionRequest("block_flow", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64, dry_run=False)
    identity = NetworkIdentity("sha256:" + "1" * 64, "enrollment", "known", 1.0, 1)
    decision = authorize_network_action(identity, request)
    with pytest.raises(AdapterExecutionError, match="acknowledgement"):
        executor.apply(request, decision, adapter_ref=adapter.adapter_ref)


def test_authenticated_transport_adapter_enforces_scope_timeout_and_expiry():
    calls = []

    def apply_transport(request, timeout_seconds):
        calls.append((request.action, timeout_seconds))
        return {"status": "completed", "adapter_ref": "authorized-dns", "idempotency_ref": request.idempotency_ref, "expires_at": 130.0}

    adapter = AuthenticatedTransportAdapter(
        adapter_ref="authorized-dns",
        authorization_ref="change-ticket-123",
        supported_actions=frozenset({"block_domain"}),
        apply_transport=apply_transport,
        rollback_transport=lambda request, timeout: {"status": "completed", "adapter_ref": "authorized-dns", "idempotency_ref": request.idempotency_ref},
        timeout_seconds=2.5,
        clock=lambda: 100.0,
    )
    request = NetworkActionRequest("block_domain", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64, dry_run=False)

    result = adapter.apply(request)

    assert result.status == "completed"
    assert calls == [("block_domain", 2.5)]
    assert adapter.rollback(request).action == "restore_access"


def test_authenticated_transport_adapter_rejects_timeout_and_unbounded_ack():
    request = NetworkActionRequest("block_flow", "sha256:" + "2" * 64, duration_seconds=30, idempotency_ref="sha256:" + "3" * 64, dry_run=False)
    timed_out = AuthenticatedTransportAdapter(
        adapter_ref="authorized-flow",
        authorization_ref="change-ticket-456",
        supported_actions=frozenset({"block_flow"}),
        apply_transport=lambda request, timeout: (_ for _ in ()).throw(TimeoutError()),
        rollback_transport=lambda request, timeout: {},
    )
    assert timed_out.apply(request).error_code == "ADAPTER_TIMEOUT"

    missing_expiry = AuthenticatedTransportAdapter(
        adapter_ref="authorized-flow",
        authorization_ref="change-ticket-456",
        supported_actions=frozenset({"block_flow"}),
        apply_transport=lambda request, timeout: {"status": "completed", "adapter_ref": "authorized-flow", "idempotency_ref": request.idempotency_ref},
        rollback_transport=lambda request, timeout: {},
    )
    assert missing_expiry.apply(request).error_code == "EXPIRY_ACK_REQUIRED"
