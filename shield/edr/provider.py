"""Vendor-neutral EDR provider contract with a single, guarded execution path.

Shield owns this interface; vendors plug in as connectors (``shield.edr.connectors``). The
only way to make a provider change endpoint state is :meth:`EndpointProvider.execute`, which
re-derives the intent hash from the intent it is about to perform and refuses to proceed
unless an :class:`ExecutionAuthorization` for exactly that hash is presented.

The authorization object is produced by the store's atomic, single-use consume step. The
in-process checks here are a second line of defence against wiring mistakes (wrong intent,
wrong vendor, a deny/escalate decision passed through as if allowed); they are not a
substitute for the store's consume, which is what makes an approval single-use.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from .response_gateway import ResponseIntent

SEVERITIES = ("informational", "low", "medium", "high", "critical")


class AuthorizationError(PermissionError):
    """Raised when execute() is called without a valid authorization for the exact intent."""


class UnsupportedAction(NotImplementedError):
    """Raised when a connector does not (yet) implement a response action."""


@dataclass(frozen=True)
class Host:
    vendor: str
    host_id: str
    hostname: str | None = None
    platform: str | None = None
    containment: str | None = None  # vendor-normalized: normal | contained | pending | unknown
    console_url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class Detection:
    vendor: str
    detection_id: str
    host_id: str | None
    severity: str
    title: str | None = None
    created_at: str | None = None
    console_url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class ActionResult:
    vendor: str
    action: str
    host_id: str
    status: str  # succeeded | failed | pending
    vendor_reference: str | None = None
    detail: str | None = None
    simulated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExecutionAuthorization:
    """Proof that an intent may execute: a policy ``allow`` or a consumed escalation."""

    intent_hash: str
    decision: dict[str, Any]
    approvals: tuple[dict[str, Any], ...] = ()
    consumed_at: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ExecutionAuthorization":
        return cls(
            intent_hash=str(raw["intent_hash"]),
            decision=dict(raw["decision"]),
            approvals=tuple(dict(a) for a in raw.get("approvals", ())),
            consumed_at=raw.get("consumed_at"),
        )

    def check(self, intent: ResponseIntent) -> None:
        computed = intent.intent_hash()
        if self.intent_hash != computed or self.decision.get("intent_hash") != computed:
            raise AuthorizationError("authorization does not match the intent being executed")
        if not self.consumed_at:
            raise AuthorizationError("authorization has not been consumed")
        verdict = self.decision.get("action")
        if verdict == "allow":
            return
        if verdict != "escalate":
            raise AuthorizationError(f"decision {verdict!r} does not authorize execution")
        required = int(self.decision.get("required_approvals") or 1)
        approvers = {
            str(a.get("approver_id"))
            for a in self.approvals
            if a.get("verdict") == "approve" and a.get("intent_hash") == computed
        }
        approvers.discard(intent.actor_id)
        if len(approvers) < required:
            raise AuthorizationError(f"escalated intent needs {required} distinct approver(s), has {len(approvers)}")


class EndpointProvider(ABC):
    """Base class for EDR connectors. Subclasses implement the ``_``-prefixed hooks."""

    vendor: str = ""

    @abstractmethod
    def list_detections(self, *, since: datetime, limit: int = 100) -> list[Detection]: ...

    @abstractmethod
    def get_detection(self, detection_id: str) -> Detection | None: ...

    @abstractmethod
    def get_host(self, host_id: str) -> Host | None: ...

    @abstractmethod
    def console_url(self, *, host_id: str | None = None, detection_id: str | None = None) -> str | None: ...

    @abstractmethod
    def _perform(self, intent: ResponseIntent) -> ActionResult: ...

    def execute(self, intent: ResponseIntent, authorization: ExecutionAuthorization) -> ActionResult:
        """The only state-changing entry point. Do not override in connectors."""
        if intent.vendor != self.vendor:
            raise AuthorizationError(f"intent targets vendor {intent.vendor!r}, provider is {self.vendor!r}")
        authorization.check(intent)
        return self._perform(intent)


def normalize_severity(value: Any) -> str:
    """Map vendor severity (name or 0-100 score) onto Shield's five-level scale."""
    if isinstance(value, str):
        name = value.strip().lower()
        if name in SEVERITIES:
            return name
        if name in {"info", "informational"}:
            return "informational"
        try:
            value = int(name)
        except ValueError:
            return "informational"
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "informational"
    score = float(value)
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


__all__ = [
    "ActionResult",
    "AuthorizationError",
    "Detection",
    "EndpointProvider",
    "ExecutionAuthorization",
    "Host",
    "SEVERITIES",
    "UnsupportedAction",
    "normalize_severity",
]
