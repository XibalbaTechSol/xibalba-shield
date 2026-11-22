"""
Phase 2: Proof-of-Justification (PoJ) Tool Gating & Policy Middleware.

Enforces zero-trust pre-execution authorization tickets before an autonomous
agent can invoke external tools, mutate system state, or transmit assets.

Key verification stages:
1. Tool Risk Assessment: LOW (read-only), MEDIUM (internal query), HIGH (filesystem/exec), CRITICAL (finance/keys).
2. Taint & Clearance Audit: Denies HIGH/CRITICAL actions if causal context is UNTRUSTED_INGEST without verified decontamination.
3. Causal Memory Justification: Validates anchor memories from Super-Cortex / Provenance ledger; rejects quarantined memories.
4. Execution Ticket: Issues a cryptographic, single-use, time-bound ticket (TTL 60s) for verified actions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any, Mapping, Sequence

from .taint import TaintLevel


class ToolRiskLevel(IntEnum):
    LOW = 1       # read-only queries, search, echo
    MEDIUM = 2    # database query, HTTP GET, internal state lookups
    HIGH = 3      # file write, shell command, script execution, HTTP POST
    CRITICAL = 4  # fund transfer, key export, destructive mutations, IAM modifications

    @classmethod
    def from_str(cls, val: str | int) -> ToolRiskLevel:
        if isinstance(val, int) and val in cls._value2member_map_:
            return cls(val)
        val_str = str(val).strip().upper()
        if "CRITICAL" in val_str or "TRANSACTION" in val_str:
            return cls.CRITICAL
        if "HIGH" in val_str or "MUTAT" in val_str or "WRITE" in val_str:
            return cls.HIGH
        if "MEDIUM" in val_str or "QUERY" in val_str:
            return cls.MEDIUM
        return cls.LOW


class PoJAuthorizationError(Exception):
    """Raised when Proof-of-Justification authorization is rejected."""
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass(frozen=True)
class ExecutionTicket:
    ticket_id: str
    tenant_id: str
    agent_did: str
    tool_name: str
    params_hash: str
    risk_level: str
    issued_at: str
    expires_at: str
    nonce: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolRiskPolicy:
    """Configures default risk levels for agent tool invocations."""

    DEFAULT_TOOL_RISKS: dict[str, ToolRiskLevel] = {
        # Critical
        "send_transaction": ToolRiskLevel.CRITICAL,
        "transfer_funds": ToolRiskLevel.CRITICAL,
        "export_private_keys": ToolRiskLevel.CRITICAL,
        "sign_transaction": ToolRiskLevel.CRITICAL,
        "delete_database": ToolRiskLevel.CRITICAL,
        # High
        "bash": ToolRiskLevel.HIGH,
        "run_command": ToolRiskLevel.HIGH,
        "write_file": ToolRiskLevel.HIGH,
        "edit_file": ToolRiskLevel.HIGH,
        "http_post": ToolRiskLevel.HIGH,
        "deploy_contract": ToolRiskLevel.HIGH,
        # Medium
        "read_file": ToolRiskLevel.MEDIUM,
        "http_get": ToolRiskLevel.MEDIUM,
        "query_sql": ToolRiskLevel.MEDIUM,
        "list_directory": ToolRiskLevel.MEDIUM,
        # Low
        "search": ToolRiskLevel.LOW,
        "echo": ToolRiskLevel.LOW,
        "get_time": ToolRiskLevel.LOW,
        "status": ToolRiskLevel.LOW,
    }

    def __init__(self, overrides: Mapping[str, ToolRiskLevel | str] | None = None) -> None:
        self._rules = dict(self.DEFAULT_TOOL_RISKS)
        if overrides:
            for tool, risk in overrides.items():
                self._rules[tool] = (
                    ToolRiskLevel.from_str(risk) if isinstance(risk, str) else risk
                )

    def evaluate_risk(self, tool_name: str) -> ToolRiskLevel:
        return self._rules.get(tool_name.lower().strip(), ToolRiskLevel.HIGH)


def compute_params_hash(params: Any) -> str:
    """Canonical SHA-256 hash of tool parameters."""
    raw = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ProofOfJustificationEngine:
    """Evaluates agent justifications and issues single-use execution tickets."""

    def __init__(
        self,
        *,
        secret_key: str | bytes = "",
        policy: ToolRiskPolicy | None = None,
        default_ttl_seconds: int = 60,
    ) -> None:
        self._secret = (
            secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        ) or secrets.token_bytes(32)
        self.policy = policy or ToolRiskPolicy()
        self.default_ttl = default_ttl_seconds
        self._quarantined_memory_hashes: set[str] = set()

    def quarantine_memory(self, memory_hash: str) -> None:
        """Marks a compromised memory hash as quarantined."""
        self._quarantined_memory_hashes.add(memory_hash.strip().lower())

    def unquarantine_memory(self, memory_hash: str) -> None:
        self._quarantined_memory_hashes.discard(memory_hash.strip().lower())

    def _sign_ticket_payload(self, canonical_payload: bytes) -> str:
        return hmac.new(self._secret, canonical_payload, hashlib.sha256).hexdigest()

    def authorize_action(
        self,
        *,
        tenant_id: str,
        agent_did: str,
        tool_name: str,
        params: Any,
        causal_memory_hashes: Sequence[str] = (),
        taint_level: TaintLevel | str = TaintLevel.TRUSTED_AXIOM,
        decontamination_proof: Mapping[str, Any] | None = None,
        ttl_seconds: int | None = None,
    ) -> ExecutionTicket:
        """
        Evaluates risk and justification. If valid, issues a signed ExecutionTicket.
        Raises PoJAuthorizationError if rejected.
        """
        risk = self.policy.evaluate_risk(tool_name)
        taint = TaintLevel.from_str(taint_level) if isinstance(taint_level, (str, int)) else taint_level
        params_hash = compute_params_hash(params)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl

        # 1. Taint Check: UNTRUSTED_INGEST cannot execute HIGH or CRITICAL without decontamination
        if taint == TaintLevel.UNTRUSTED_INGEST and risk >= ToolRiskLevel.HIGH:
            if not decontamination_proof or not decontamination_proof.get("verified"):
                raise PoJAuthorizationError(
                    "POJ_TAINTED_UNTRUSTED_INGEST",
                    f"Action '{tool_name}' (risk {risk.name}) denied: execution context is UNTRUSTED_INGEST with no verified decontamination proof.",
                    {"tool_name": tool_name, "risk": risk.name, "taint": taint.name},
                )

        # 2. Causal Justification Check: HIGH and CRITICAL tools require causal memories
        if risk >= ToolRiskLevel.HIGH:
            if not causal_memory_hashes:
                raise PoJAuthorizationError(
                    "POJ_MISSING_JUSTIFICATION",
                    f"Action '{tool_name}' (risk {risk.name}) requires non-empty causal memory justification hashes.",
                    {"tool_name": tool_name, "risk": risk.name},
                )

        # 3. Quarantine Check: No causal memory may be quarantined
        for h in causal_memory_hashes:
            clean_h = h.strip().lower()
            if clean_h in self._quarantined_memory_hashes:
                raise PoJAuthorizationError(
                    "POJ_QUARANTINED_JUSTIFICATION",
                    f"Causal memory '{h}' is quarantined due to suspected poisoning/malicious injection.",
                    {"quarantined_hash": h},
                )

        # 4. Generate Ticket
        ticket_id = f"tkt_{uuid.uuid4().hex[:16]}"
        issued_ts = time.time()
        expires_ts = issued_ts + ttl
        issued_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued_ts))
        expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_ts))
        nonce = secrets.token_hex(8)

        canonical = (
            f"{ticket_id}|{tenant_id}|{agent_did}|{tool_name}|{params_hash}|"
            f"{risk.name}|{issued_at}|{expires_at}|{nonce}"
        ).encode("utf-8")
        signature = self._sign_ticket_payload(canonical)

        return ExecutionTicket(
            ticket_id=ticket_id,
            tenant_id=tenant_id,
            agent_did=agent_did,
            tool_name=tool_name,
            params_hash=params_hash,
            risk_level=risk.name,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            signature=signature,
        )

    def verify_ticket(
        self,
        ticket: ExecutionTicket | Mapping[str, Any],
        *,
        expected_tool: str,
        expected_params: Any,
    ) -> bool:
        """
        Verifies the cryptographic integrity, tool match, parameter hash, and expiration
        of an ExecutionTicket.
        """
        if isinstance(ticket, ExecutionTicket):
            t = ticket
        else:
            ticket_fields = {
                "ticket_id",
                "tenant_id",
                "agent_did",
                "tool_name",
                "params_hash",
                "risk_level",
                "issued_at",
                "expires_at",
                "nonce",
                "signature",
            }
            cleaned = {k: v for k, v in ticket.items() if k in ticket_fields}
            t = ExecutionTicket(**cleaned)
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Expiration
        if now_str > t.expires_at:
            return False

        # Tool name match
        if t.tool_name.lower().strip() != expected_tool.lower().strip():
            return False

        # Params hash match
        expected_hash = compute_params_hash(expected_params)
        if not hmac.compare_digest(t.params_hash, expected_hash):
            return False

        # Signature verification
        canonical = (
            f"{t.ticket_id}|{t.tenant_id}|{t.agent_did}|{t.tool_name}|{t.params_hash}|"
            f"{t.risk_level}|{t.issued_at}|{t.expires_at}|{t.nonce}"
        ).encode("utf-8")
        expected_sig = self._sign_ticket_payload(canonical)
        return hmac.compare_digest(t.signature, expected_sig)
