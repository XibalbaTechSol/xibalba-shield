"""Non-custodial transaction-intent validation for Shield.

This module deliberately stops before signing, routing, or broadcasting.  It turns a
caller-supplied intent into a canonical, hash-bound decision that a future signer,
paymaster, or relayer can consume.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal


_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BYTES = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
_SELECTOR = re.compile(r"^0x[0-9a-fA-F]{8}$")
Action = Literal["allow", "deny", "escalate"]


@dataclass(frozen=True)
class TransactionIntent:
    tenant_id: str
    device_id: str
    agent_id: str
    request_id: str
    chain_id: int
    to: str
    function_selector: str
    value_wei: int = 0
    token_address: str | None = None
    token_amount: int | None = None
    slippage_bps: int | None = None
    calldata_hash: str | None = None
    calldata: str | None = None
    sender: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "TransactionIntent":
        required = ("tenant_id", "device_id", "agent_id", "request_id", "chain_id", "to", "function_selector")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"missing transaction intent fields: {', '.join(missing)}")
        intent = cls(
            tenant_id=str(raw["tenant_id"]),
            device_id=str(raw["device_id"]),
            agent_id=str(raw["agent_id"]),
            request_id=str(raw["request_id"]),
            chain_id=raw["chain_id"],
            to=str(raw["to"]).lower(),
            function_selector=str(raw["function_selector"]).lower(),
            value_wei=raw.get("value_wei", 0),
            token_address=str(raw["token_address"]).lower() if raw.get("token_address") else None,
            token_amount=raw.get("token_amount"),
            slippage_bps=raw.get("slippage_bps"),
            calldata_hash=raw.get("calldata_hash"),
            calldata=str(raw["calldata"]).lower() if raw.get("calldata") else None,
            sender=str(raw["sender"]).lower() if raw.get("sender") else None,
        )
        intent.validate()
        return intent

    def validate(self) -> None:
        for field in ("tenant_id", "device_id", "agent_id", "request_id"):
            if not getattr(self, field).strip():
                raise ValueError(f"{field} must not be empty")
        if isinstance(self.chain_id, bool) or not isinstance(self.chain_id, int) or self.chain_id <= 0:
            raise ValueError("chain_id must be a positive integer")
        if not _ADDRESS.fullmatch(self.to):
            raise ValueError("to must be a 20-byte hexadecimal address")
        if not _SELECTOR.fullmatch(self.function_selector):
            raise ValueError("function_selector must be a 4-byte hexadecimal selector")
        if self.token_address is not None and not _ADDRESS.fullmatch(self.token_address):
            raise ValueError("token_address must be a 20-byte hexadecimal address")
        if self.sender is not None and not _ADDRESS.fullmatch(self.sender):
            raise ValueError("sender must be a 20-byte hexadecimal address")
        if self.calldata is not None and not _BYTES.fullmatch(self.calldata):
            raise ValueError("calldata must be hexadecimal bytes")
        if self.calldata is not None and (len(self.calldata) < 10 or self.calldata[:10] != self.function_selector):
            raise ValueError("calldata must begin with function_selector")
        for field in ("value_wei", "token_amount", "slippage_bps"):
            value = getattr(self, field)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"{field} must be a non-negative integer")
        if self.slippage_bps is not None and self.slippage_bps > 10_000:
            raise ValueError("slippage_bps must be at most 10000")
        if self.calldata_hash is not None and (not isinstance(self.calldata_hash, str) or not _BYTES.fullmatch(self.calldata_hash)):
            raise ValueError("calldata_hash must be hexadecimal bytes")

    def canonical(self) -> dict[str, Any]:
        return asdict(self)

    def intent_hash(self) -> str:
        encoded = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class TransactionPolicy:
    allowed_chain_ids: frozenset[int]
    allowed_contracts: frozenset[str]
    allowed_function_selectors: frozenset[str]
    max_value_wei: int = 0
    max_token_amount: int | None = None
    max_slippage_bps: int = 100
    require_approval: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "TransactionPolicy":
        policy = cls(
            allowed_chain_ids=frozenset(raw.get("allowed_chain_ids", [])),
            allowed_contracts=frozenset(str(value).lower() for value in raw.get("allowed_contracts", [])),
            allowed_function_selectors=frozenset(str(value).lower() for value in raw.get("allowed_function_selectors", [])),
            max_value_wei=raw.get("max_value_wei", 0),
            max_token_amount=raw.get("max_token_amount"),
            max_slippage_bps=raw.get("max_slippage_bps", 100),
            require_approval=bool(raw.get("require_approval", False)),
        )
        if policy.max_value_wei < 0 or policy.max_slippage_bps < 0:
            raise ValueError("transaction policy limits must be non-negative")
        if policy.max_token_amount is not None and policy.max_token_amount < 0:
            raise ValueError("max_token_amount must be non-negative")
        return policy


@dataclass(frozen=True)
class TransactionDecision:
    action: Action
    rule_id: str
    reason: str
    intent_hash: str
    intent: dict[str, Any]
    execution: str = "not_broadcast"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_transaction_intent(intent: TransactionIntent, policy: TransactionPolicy) -> TransactionDecision:
    intent.validate()
    intent_hash = intent.intent_hash()

    checks = (
        (intent.chain_id in policy.allowed_chain_ids, "chain-not-allowed", "chain is not allowlisted"),
        (intent.to in policy.allowed_contracts, "contract-not-allowed", "destination contract is not allowlisted"),
        (intent.function_selector in policy.allowed_function_selectors, "function-not-allowed", "function selector is not allowlisted"),
        (intent.value_wei <= policy.max_value_wei, "native-value-limit", "native value exceeds policy limit"),
        (policy.max_token_amount is None or intent.token_amount is None or intent.token_amount <= policy.max_token_amount, "token-value-limit", "token amount exceeds policy limit"),
        (intent.slippage_bps is None or intent.slippage_bps <= policy.max_slippage_bps, "slippage-limit", "slippage exceeds policy limit"),
    )
    for passed, rule_id, reason in checks:
        if not passed:
            return TransactionDecision("deny", rule_id, reason, intent_hash, intent.canonical())
    if policy.require_approval:
        return TransactionDecision("escalate", "approval-required", "operator approval is required", intent_hash, intent.canonical())
    return TransactionDecision("allow", "transaction-policy-allow", "intent satisfies transaction policy", intent_hash, intent.canonical())


__all__ = ["TransactionDecision", "TransactionIntent", "TransactionPolicy", "evaluate_transaction_intent"]
