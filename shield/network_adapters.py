"""Narrow network-action adapter boundary.

Adapters are intentionally injected objects. This module contains no shell, SSH, router,
firewall, DNS, NAC, or controller command execution. Production adapters must implement their
own authenticated API boundary and return an authoritative acknowledgement.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from .network_policy import NetworkActionRequest, NetworkGateDecision


@dataclass(frozen=True)
class AdapterResult:
    action: str
    status: str
    adapter_ref: str
    idempotency_ref: str
    expires_at: float | None = None
    error_code: str | None = None


class NetworkAdapter(Protocol):
    adapter_ref: str
    supported_actions: frozenset[str]

    def apply(self, request: NetworkActionRequest) -> AdapterResult:
        """Apply one already-authorized request and return an adapter acknowledgement."""

    def rollback(self, request: NetworkActionRequest) -> AdapterResult:
        """Restore the prior state for one already-applied request."""


class AuthenticatedTransport(Protocol):
    """Narrow, already-authenticated API transport supplied by a deployment adapter."""

    def __call__(self, request: NetworkActionRequest, timeout_seconds: float) -> Mapping[str, Any]:
        """Perform one bounded API call; the transport must enforce the timeout."""


class AdapterExecutionError(RuntimeError):
    pass


class AuthenticatedTransportAdapter:
    """Production adapter boundary for an explicitly authorized API transport.

    The transport owns TLS/authentication and vendor-specific API details. Shield supplies no
    shell, SSH, root, or controller-admin implementation here. Registration requires a
    deployment authorization reference and an explicit action allowlist.
    """

    def __init__(
        self,
        *,
        adapter_ref: str,
        authorization_ref: str,
        supported_actions: frozenset[str],
        apply_transport: AuthenticatedTransport,
        rollback_transport: AuthenticatedTransport,
        timeout_seconds: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not adapter_ref or not authorization_ref:
            raise ValueError("adapter_ref and authorization_ref are required")
        if not supported_actions:
            raise ValueError("at least one least-privilege action must be authorized")
        if not 0.1 <= timeout_seconds <= 30.0:
            raise ValueError("adapter timeout must be between 0.1 and 30 seconds")
        self.adapter_ref = adapter_ref
        self.authorization_ref = authorization_ref
        self.supported_actions = frozenset(supported_actions)
        self._apply_transport = apply_transport
        self._rollback_transport = rollback_transport
        self._timeout_seconds = timeout_seconds
        self._clock = clock

    def apply(self, request: NetworkActionRequest) -> AdapterResult:
        if request.action not in self.supported_actions:
            return AdapterResult(request.action, "failed", self.adapter_ref, request.idempotency_ref, error_code="ACTION_NOT_AUTHORIZED")
        try:
            raw = self._apply_transport(request, self._timeout_seconds)
        except TimeoutError:
            return AdapterResult(request.action, "failed", self.adapter_ref, request.idempotency_ref, error_code="ADAPTER_TIMEOUT")
        return self._acknowledgement(request, raw)

    def rollback(self, request: NetworkActionRequest) -> AdapterResult:
        try:
            raw = self._rollback_transport(request, self._timeout_seconds)
        except TimeoutError:
            return AdapterResult("restore_access", "failed", self.adapter_ref, request.idempotency_ref, error_code="ROLLBACK_TIMEOUT")
        result = self._acknowledgement(request, raw, rollback=True)
        if result.action != "restore_access":
            return AdapterResult("restore_access", "failed", self.adapter_ref, request.idempotency_ref, error_code="INVALID_ROLLBACK_ACK")
        return result

    def _acknowledgement(self, request: NetworkActionRequest, raw: Mapping[str, Any], *, rollback: bool = False) -> AdapterResult:
        action = "restore_access" if rollback else request.action
        expires_at = raw.get("expires_at")
        if expires_at is not None:
            expires_at = float(expires_at)
        if request.duration_seconds and expires_at is None:
            return AdapterResult(action, "failed", self.adapter_ref, request.idempotency_ref, error_code="EXPIRY_ACK_REQUIRED")
        if expires_at is not None and expires_at > self._clock() + request.duration_seconds:
            return AdapterResult(action, "failed", self.adapter_ref, request.idempotency_ref, error_code="EXPIRY_ACK_EXCEEDS_REQUEST")
        return AdapterResult(
            action,
            str(raw.get("status", "failed")),
            str(raw.get("adapter_ref", self.adapter_ref)),
            str(raw.get("idempotency_ref", request.idempotency_ref)),
            expires_at,
            raw.get("error_code"),
        )


class NetworkActionExecutor:
    """Dispatch only to explicitly registered adapters; duplicate requests are idempotent."""

    def __init__(self, adapters: list[NetworkAdapter], *, clock: callable = time.time, approval_store: object | None = None) -> None:
        self._adapters = {adapter.adapter_ref: adapter for adapter in adapters}
        self._clock = clock
        self._approval_store = approval_store
        self._completed: dict[str, AdapterResult] = {}

    def apply(self, request: NetworkActionRequest, decision: NetworkGateDecision, *, adapter_ref: str) -> AdapterResult:
        if not decision.allowed or decision.status not in {"approved", "preview"}:
            raise AdapterExecutionError("network action was not approved by the local policy gate")
        if request.dry_run:
            return AdapterResult(request.action, "preview", adapter_ref, request.idempotency_ref)
        adapter = self._adapters.get(adapter_ref)
        if adapter is None:
            raise AdapterExecutionError("adapter is not registered")
        if request.action not in adapter.supported_actions:
            raise AdapterExecutionError("adapter does not support requested action")
        if request.idempotency_ref in self._completed:
            return self._completed[request.idempotency_ref]
        if request.scope != "device" or request.action in {"isolate_device", "move_segment", "revoke_access", "restore_access"}:
            if self._approval_store is None or not request.approval_ref:
                raise AdapterExecutionError("explicit approval is required before this network action")
            try:
                self._approval_store.consume(request.approval_ref, request)
            except Exception as exc:  # noqa: BLE001 -- normalize store boundary failures
                raise AdapterExecutionError(f"network approval was not consumable: {exc}") from exc
        if request.idempotency_ref in self._completed:
            return self._completed[request.idempotency_ref]
        result = adapter.apply(request)
        if result.status != "completed":
            raise AdapterExecutionError(result.error_code or "adapter did not acknowledge completion")
        if result.adapter_ref != adapter_ref or result.idempotency_ref != request.idempotency_ref:
            raise AdapterExecutionError("adapter acknowledgement does not match the requested operation")
        if result.expires_at is not None and result.expires_at <= self._clock():
            raise AdapterExecutionError("adapter acknowledgement is already expired")
        self._completed[request.idempotency_ref] = result
        return result

    def rollback(self, request: NetworkActionRequest, *, adapter_ref: str) -> AdapterResult:
        adapter = self._adapters.get(adapter_ref)
        if adapter is None:
            raise AdapterExecutionError("adapter is not registered")
        result = adapter.rollback(request)
        if result.status != "completed":
            raise AdapterExecutionError(result.error_code or "adapter did not acknowledge rollback")
        if result.adapter_ref != adapter_ref or result.idempotency_ref != request.idempotency_ref:
            raise AdapterExecutionError("rollback acknowledgement does not match the requested operation")
        self._completed.pop(request.idempotency_ref, None)
        return result


class DisposableMemoryAdapter:
    """Test-only adapter; it changes memory, not network state."""

    adapter_ref = "disposable-memory"
    supported_actions = frozenset({"block_flow", "block_domain", "isolate_device", "move_segment", "revoke_access", "rate_limit", "restore_access"})

    def __init__(self, *, clock: callable = time.time) -> None:
        self._clock = clock
        self.applied: list[str] = []
        self.state: dict[str, str] = {}

    def apply(self, request: NetworkActionRequest) -> AdapterResult:
        self.applied.append(request.idempotency_ref)
        if request.action == "restore_access":
            self.state.pop(request.target_ref, None)
        else:
            self.state[request.target_ref] = request.action
        expiry = self._clock() + request.duration_seconds if request.duration_seconds else None
        return AdapterResult(request.action, "completed", self.adapter_ref, request.idempotency_ref, expiry)

    def rollback(self, request: NetworkActionRequest) -> AdapterResult:
        self.state.pop(request.target_ref, None)
        return AdapterResult("restore_access", "completed", self.adapter_ref, request.idempotency_ref)


__all__ = ["AuthenticatedTransport", "AuthenticatedTransportAdapter", "AdapterExecutionError", "AdapterResult", "DisposableMemoryAdapter", "NetworkActionExecutor", "NetworkAdapter"]
