"""
Shield Sentry Client SDK — Frictionless Drop-in Agent Security Middleware.

Provides unified ingress taint tracking, secret/PII redaction, steganographic
canary trap injection, Proof-of-Justification (PoJ) tool execution ticket gating,
Human-in-the-Loop (HITL) cryptographic approval pipelines, and OCSF SIEM auditing.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import logging
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, Mapping, Sequence, TypeVar

from .canary import CanaryManager
from .enclave import TenantEnclave
from .justification import (
    ExecutionTicket,
    PoJAuthorizationError,
    ProofOfJustificationEngine,
    ToolRiskLevel,
    ToolRiskPolicy,
)
from .ocsf import OCSFActivityId, OCSFEventBuilder, OCSFSeverityId
from .scrubber import scrub_secrets_and_pii
from .store import SentryDefenseStore
from .taint import TaintLatticeTracker, TaintLevel

logger = logging.getLogger(__name__)

T = TypeVar("T")


class SentryClientError(Exception):
    """Base exception for Shield Sentry Client errors."""


class SentryDeniedError(SentryClientError):
    """Raised when an action is denied by Sentry security policies."""


@dataclass(frozen=True)
class IngressResult:
    """Result of prompt ingress inspection and protection."""

    clean_content: str
    original_content: str
    taint_level: TaintLevel
    canary_token: str | None = None
    redacted_count: int = 0
    redacted_types: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "clean_content": self.clean_content,
            "original_content": self.original_content,
            "taint_level": self.taint_level.name,
            "canary_token": self.canary_token,
            "redacted_count": self.redacted_count,
            "redacted_types": list(self.redacted_types),
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CanaryCheckResult:
    """Result of agent response canary audit."""

    tripped: bool
    clean_text: str
    leaked_canaries: list[dict[str, Any]] = field(default_factory=list)
    alert_event: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tripped": self.tripped,
            "clean_text": self.clean_text,
            "leaked_canaries": list(self.leaked_canaries),
            "alert_event": self.alert_event,
        }


@dataclass
class ActionExecutionResult(Generic[T]):
    """Result of a guarded tool invocation."""

    success: bool
    tool_name: str
    result: T | None = None
    error: str | None = None
    ticket_id: str | None = None
    denied: bool = False
    risk_level: str | None = None


class ShieldSentryClient:
    """
    Unified client for Xibalba Shield Sentry Defense.

    Supports both in-process embedded operation and remote HTTP API client mode.
    Wraps tools, models, and agent loops in 3 lines of code.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_token: str | None = None,
        tenant_id: str = "default",
        agent_did: str = "did:integrity:agent",
        store: SentryDefenseStore | None = None,
        canary_manager: CanaryManager | None = None,
        taint_tracker: TaintLatticeTracker | None = None,
        poj_engine: ProofOfJustificationEngine | None = None,
        enclave: TenantEnclave | None = None,
        secret_key: str | bytes = "shield-client-secret",
        require_human_approval_for_critical: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/") if base_url else None
        self.api_token = api_token
        self.default_tenant_id = tenant_id
        self.default_agent_did = agent_did

        # Embedded / Local components (used if base_url is None)
        if store is not None:
            self.store = store
        else:
            conn = sqlite3.connect(":memory:")
            self.store = SentryDefenseStore(conn)
            self.store.init_schema()
        self.canary_manager = canary_manager or CanaryManager(default_secret=secret_key)
        self.taint_tracker = taint_tracker or TaintLatticeTracker()
        self.poj_engine = poj_engine or ProofOfJustificationEngine(
            secret_key=secret_key,
            require_human_approval_for_critical=require_human_approval_for_critical,
        )
        sec_bytes = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        enclave_sec = hashlib.sha256(sec_bytes).digest() if len(sec_bytes) < 16 else sec_bytes
        self.enclave = enclave or TenantEnclave(self.default_tenant_id, enclave_sec)

    def _http_request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Performs a synchronous HTTP request to the Shield Sentry API."""
        if not self.base_url:
            raise SentryClientError("HTTP request attempted but base_url is not configured")

        url = f"{self.base_url}{path}"
        if params:
            query_str = urllib.parse.urlencode(params)
            url = f"{url}?{query_str}"

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                resp_bytes = resp.read()
                return json.loads(resp_bytes.decode("utf-8")) if resp_bytes else {}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(err_body)
                msg = err_json.get("error") or err_json.get("message") or err_body
            except Exception:
                msg = err_body
            if exc.code in (401, 403, 409):
                raise SentryDeniedError(f"HTTP {exc.code}: {msg}") from exc
            raise SentryClientError(f"HTTP {exc.code}: {msg}") from exc
        except Exception as exc:
            raise SentryClientError(f"Network error calling {url}: {exc}") from exc

    def intercept_prompt(
        self,
        content: str,
        *,
        source_type: str = "user_input",
        inject_canary: bool = True,
        tenant_id: str | None = None,
        agent_did: str | None = None,
    ) -> IngressResult:
        """
        Inspects incoming prompt text, scrubs secrets/PII, tracks taint, and injects canary traps.
        """
        tid = tenant_id or self.default_tenant_id
        adid = agent_did or self.default_agent_did

        if self.base_url:
            resp = self._http_request(
                "POST",
                "/api/sentry/ingress/taint",
                body={
                    "tenant_id": tid,
                    "agent_did": adid,
                    "content": content,
                    "source_type": source_type,
                    "inject_canary": inject_canary,
                },
            )
            clean_content = resp.get("content") or resp.get("clean_content") or content
            taint_str = resp.get("taint_level") or "TRUSTED_AXIOM"
            canary_id = resp.get("canary_id")
            scrubbed_count = resp.get("scrubbed_count") or 0
            return IngressResult(
                clean_content=clean_content,
                original_content=content,
                taint_level=TaintLevel.from_str(taint_str),
                canary_token=canary_id,
                redacted_count=scrubbed_count,
                redacted_types=[],
            )

        # In-process path
        clean_text, matches = scrub_secrets_and_pii(content)
        redacted_types = list({m.kind for m in matches})

        canary_token: str | None = None
        if inject_canary:
            canary_trap, invisible_token = self.canary_manager.generate_canary(
                tenant_id=tid,
                agent_id=adid,
            )
            clean_text = self.canary_manager.inject_canary(clean_text, invisible_token)
            self.store.record_canary(canary_trap)
            canary_token = canary_trap.canary_id

        record = self.taint_tracker.track_ingest(
            clean_text,
            source=source_type,
            source_type=source_type,
            level=TaintLevel.UNTRUSTED_INGEST,
            canary_ids=[canary_token] if canary_token else (),
        )

        self.store.record_ocsf_event(
            OCSFEventBuilder.build_event(
                activity_id=OCSFActivityId.INPUT_INGEST,
                severity_id=OCSFSeverityId.INFORMATIONAL,
                tenant_id=tid,
                agent_did=adid,
                taint_level=record.taint_level.name,
                message=f"Prompt intercepted from source {source_type}",
                details={
                    "source_type": source_type,
                    "taint_level": record.taint_level.name,
                    "redacted_count": len(matches),
                    "canary_injected": bool(canary_token),
                },
            ),
            event_type="ingress_taint",
        )

        return IngressResult(
            clean_content=clean_text,
            original_content=content,
            taint_level=record.taint_level,
            canary_token=canary_token,
            redacted_count=len(matches),
            redacted_types=redacted_types,
        )

    def audit_response(
        self,
        text: str,
        *,
        tenant_id: str | None = None,
        agent_did: str | None = None,
        sanitize: bool = True,
    ) -> CanaryCheckResult:
        """
        Audits an agent's response for leaked canary traps.
        If a canary is detected, quarantines the session/memory and triggers a security alert.
        """
        tid = tenant_id or self.default_tenant_id
        adid = agent_did or self.default_agent_did

        if self.base_url:
            resp = self._http_request(
                "POST",
                "/api/sentry/canary/check",
                body={
                    "tenant_id": tid,
                    "agent_did": adid,
                    "text": text,
                    "sanitize": sanitize,
                },
            )
            alerts = resp.get("alerts") or resp.get("tripped_canaries") or []
            clean_text = resp.get("clean_text") or (
                self.canary_manager.strip_canaries(text) if (alerts and sanitize) else text
            )
            return CanaryCheckResult(
                tripped=bool(resp.get("tripped")),
                clean_text=clean_text,
                leaked_canaries=list(alerts),
                alert_event=resp.get("alert_event"),
            )

        # In-process path
        tripped_alerts = self.canary_manager.detect_canaries(text)
        if not tripped_alerts:
            return CanaryCheckResult(tripped=False, clean_text=text, leaked_canaries=[])

        tripped_canaries = [
            {
                "canary_id": a.canary_id,
                "tenant_id": a.tenant_id,
                "agent_id": a.agent_id,
                "detection_time": a.detection_time,
                "snippet": a.snippet,
                "severity": a.severity,
            }
            for a in tripped_alerts
        ]
        for a in tripped_alerts:
            self.store.trip_canary(a.canary_id, a.snippet)
            self.poj_engine.quarantine_memory(a.canary_id)

        alert_event = OCSFEventBuilder.build_event(
            activity_id=OCSFActivityId.CANARY_TRIP,
            severity_id=OCSFSeverityId.CRITICAL,
            tenant_id=tid,
            agent_did=adid,
            message="CANARY TRAP TRIPPED: Zero-width honeytoken leaked in agent response",
            details={
                "tripped_canaries": tripped_canaries,
                "count": len(tripped_canaries),
            },
        )
        self.store.record_ocsf_event(alert_event, event_type="canary_tripped")

        clean_text = self.canary_manager.strip_canaries(text) if sanitize else text
        return CanaryCheckResult(
            tripped=True,
            clean_text=clean_text,
            leaked_canaries=tripped_canaries,
            alert_event=alert_event.to_dict(),
        )

    def authorize_action(
        self,
        tool_name: str,
        params: Any = None,
        *,
        causal_memory_hashes: Sequence[str] = (),
        taint_level: TaintLevel | str = TaintLevel.TRUSTED_AXIOM,
        decontamination_proof: Mapping[str, Any] | None = None,
        human_approval: Mapping[str, Any] | None = None,
        require_human_approval: bool | None = None,
        ttl_seconds: int | None = None,
        tenant_id: str | None = None,
        agent_did: str | None = None,
    ) -> ExecutionTicket:
        """
        Evaluates justification policies and requests a cryptographic execution ticket.
        """
        tid = tenant_id or self.default_tenant_id
        adid = agent_did or self.default_agent_did
        p_dict = params if params is not None else {}
        t_str = taint_level.name if isinstance(taint_level, TaintLevel) else str(taint_level)

        if self.base_url:
            body: dict[str, Any] = {
                "tenant_id": tid,
                "agent_did": adid,
                "tool_name": tool_name,
                "params": p_dict,
                "causal_memory_hashes": list(causal_memory_hashes),
                "taint_level": t_str,
                "decontamination_proof": decontamination_proof,
                "human_approval": human_approval,
                "require_human_approval": require_human_approval,
            }
            if ttl_seconds is not None:
                body["ttl_seconds"] = ttl_seconds

            resp = self._http_request("POST", "/api/sentry/authorize-action", body=body)
            ticket_data = resp.get("ticket") or {}
            return ExecutionTicket.from_dict(ticket_data)

        # In-process path
        try:
            ticket = self.poj_engine.authorize_action(
                tenant_id=tid,
                agent_did=adid,
                tool_name=tool_name,
                params=p_dict,
                causal_memory_hashes=causal_memory_hashes,
                taint_level=taint_level,
                decontamination_proof=decontamination_proof,
                human_approval=human_approval,
                require_human_approval=require_human_approval,
                ttl_seconds=ttl_seconds,
            )
        except PoJAuthorizationError as exc:
            self.store.record_ocsf_event(
                OCSFEventBuilder.build_event(
                    activity_id=OCSFActivityId.POLICY_VIOLATION,
                    severity_id=OCSFSeverityId.HIGH,
                    tenant_id=tid,
                    agent_did=adid,
                    tool_name=tool_name,
                    taint_level=t_str,
                    message=f"Action authorization rejected: {exc.code}",
                    details=exc.details,
                ),
                event_type="poj_denied",
            )
            raise SentryDeniedError(str(exc)) from exc

        self.store.record_ticket(ticket)
        self.store.record_ocsf_event(
            OCSFEventBuilder.build_event(
                activity_id=OCSFActivityId.TOOL_GATED,
                severity_id=OCSFSeverityId.INFORMATIONAL,
                tenant_id=tid,
                agent_did=adid,
                tool_name=tool_name,
                taint_level=t_str,
                message=f"Action authorization granted for {tool_name}",
                details={"ticket_id": ticket.ticket_id, "risk_level": ticket.risk_level},
            ),
            event_type="poj_granted",
        )
        return ticket

    def verify_and_consume_ticket(
        self,
        ticket_id: str,
        tool_name: str,
        params: Any = None,
    ) -> bool:
        """
        Verifies and consumes a single-use execution ticket, preventing replay attacks.
        """
        p_dict = params if params is not None else {}

        if self.base_url:
            resp = self._http_request(
                "POST",
                "/api/sentry/verify-ticket",
                body={
                    "ticket_id": ticket_id,
                    "tool_name": tool_name,
                    "params": p_dict,
                },
            )
            return bool(resp.get("consumed"))

        # In-process path
        ticket_data = self.store.get_ticket(ticket_id)
        if not ticket_data:
            raise SentryClientError(f"Ticket '{ticket_id}' not found")
        if ticket_data.get("consumed"):
            raise SentryDeniedError(f"Ticket '{ticket_id}' has already been consumed (replay attack rejected)")

        if not self.poj_engine.verify_ticket(ticket_data, expected_tool=tool_name, expected_params=p_dict):
            raise SentryDeniedError(f"Ticket '{ticket_id}' signature or parameter verification failed")

        consumed = self.store.consume_ticket(ticket_id)
        if not consumed:
            raise SentryDeniedError(f"Failed to atomically consume ticket '{ticket_id}'")
        return True

    def request_human_approval(
        self,
        approver_id: str,
        tool_name: str,
        params: Any = None,
        *,
        ttl_seconds: int = 300,
        reason: str = "Approved by operator",
    ) -> dict[str, Any]:
        """
        Mints a cryptographic Human-in-the-Loop (HITL) approval receipt.
        """
        p_dict = params if params is not None else {}

        if self.base_url:
            resp = self._http_request(
                "POST",
                "/api/sentry/hitl/approve",
                body={
                    "approver_id": approver_id,
                    "tool_name": tool_name,
                    "params": p_dict,
                    "ttl_seconds": ttl_seconds,
                    "reason": reason,
                },
            )
            return dict(resp.get("approval") or {})

        return self.poj_engine.mint_human_approval(
            approver_id=approver_id,
            tool_name=tool_name,
            params=p_dict,
            ttl_seconds=ttl_seconds,
            reason=reason,
        )

    def execute_guarded(
        self,
        tool_func: Callable[..., T],
        tool_name: str | None = None,
        params: dict[str, Any] | None = None,
        *,
        causal_memory_hashes: Sequence[str] = (),
        taint_level: TaintLevel | str = TaintLevel.TRUSTED_AXIOM,
        decontamination_proof: Mapping[str, Any] | None = None,
        human_approval: Mapping[str, Any] | None = None,
        require_human_approval: bool | None = None,
        tenant_id: str | None = None,
        agent_did: str | None = None,
    ) -> ActionExecutionResult[T]:
        """
        Fully guards an execution: authorizes, verifies & consumes ticket, runs function.
        """
        name = tool_name or getattr(tool_func, "__name__", "anonymous_tool")
        p = params if params is not None else {}

        try:
            ticket = self.authorize_action(
                tool_name=name,
                params=p,
                causal_memory_hashes=causal_memory_hashes,
                taint_level=taint_level,
                decontamination_proof=decontamination_proof,
                human_approval=human_approval,
                require_human_approval=require_human_approval,
                tenant_id=tenant_id,
                agent_did=agent_did,
            )
            self.verify_and_consume_ticket(ticket.ticket_id, name, p)
        except SentryDeniedError as exc:
            return ActionExecutionResult(
                success=False,
                tool_name=name,
                error=str(exc),
                denied=True,
            )
        except Exception as exc:
            return ActionExecutionResult(
                success=False,
                tool_name=name,
                error=str(exc),
                denied=False,
            )

        try:
            res = tool_func(**p)
            return ActionExecutionResult(
                success=True,
                tool_name=name,
                result=res,
                ticket_id=ticket.ticket_id,
                risk_level=ticket.risk_level,
            )
        except Exception as exc:
            return ActionExecutionResult(
                success=False,
                tool_name=name,
                error=f"Execution error: {exc}",
                ticket_id=ticket.ticket_id,
                risk_level=ticket.risk_level,
            )

    def wrap_tool(
        self,
        tool_name: str | None = None,
        *,
        causal_memory_hashes: Sequence[str] = (),
        taint_level: TaintLevel | str = TaintLevel.TRUSTED_AXIOM,
        require_human_approval: bool | None = None,
        tenant_id: str | None = None,
        agent_did: str | None = None,
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """
        Decorator to guard a tool function with Sentry Defense authorization and ticket middleware.
        """

        def decorator(fn: Callable[..., T]) -> Callable[..., T]:
            name = tool_name or getattr(fn, "__name__", "anonymous_tool")

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> T:
                # Extract sentry-specific kwargs before binding against fn signature
                kw = dict(kwargs)
                approval = kw.pop("_sentry_human_approval", None)
                decon = kw.pop("_sentry_decontamination_proof", None)
                memories = kw.pop("_sentry_causal_memory_hashes", causal_memory_hashes)

                # Resolve parameters mapping
                sig = inspect.signature(fn)
                bound = sig.bind_partial(*args, **kw)
                bound.apply_defaults()
                call_params = dict(bound.arguments)

                def runner(**p: Any) -> T:
                    return fn(**p)

                res = self.execute_guarded(
                    runner,
                    tool_name=name,
                    params=call_params,
                    causal_memory_hashes=memories,
                    taint_level=taint_level,
                    decontamination_proof=decon,
                    human_approval=approval,
                    require_human_approval=require_human_approval,
                    tenant_id=tenant_id,
                    agent_did=agent_did,
                )
                if not res.success:
                    raise SentryDeniedError(f"Action '{name}' denied by Sentry: {res.error}")
                return res.result  # type: ignore[return-value]

            wrapper.__sentry_guarded__ = True  # type: ignore[attr-defined]
            return wrapper

        return decorator

    def get_siem_events(
        self,
        tenant_id: str | None = None,
        limit: int = 100,
        profile: str = "ocsf",
    ) -> list[dict[str, Any]]:
        """Retrieves formatted SIEM events."""
        tid = tenant_id or self.default_tenant_id

        if self.base_url:
            resp = self._http_request(
                "GET",
                "/api/sentry/siem/ocsf",
                params={"tenant_id": tid, "limit": str(limit), "profile": profile},
            )
            return list(resp.get("events") or [])

        events = self.store.list_ocsf_events(tid, limit=limit)
        return [
            OCSFEventBuilder.format_for_siem(ev["payload"], profile=profile)
            for ev in events
        ]

    def get_audit_summary(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Retrieves audit telemetry summary for Sentry security operations."""
        tid = tenant_id or self.default_tenant_id

        if self.base_url:
            resp = self._http_request(
                "GET",
                "/api/sentry/audit/summary",
                params={"tenant_id": tid},
            )
            return dict(resp.get("summary") or {})

        return self.store.get_audit_summary(tid)
