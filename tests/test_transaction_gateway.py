from __future__ import annotations

import pytest

from shield.transaction_gateway import TransactionIntent, TransactionPolicy, evaluate_transaction_intent


INTENT = {
    "tenant_id": "tenant-a",
    "device_id": "dev-1",
    "agent_id": "agent-1",
    "request_id": "req-1",
    "chain_id": 84532,
    "to": "0x1111111111111111111111111111111111111111",
    "function_selector": "0xa9059cbb",
    "value_wei": 0,
    "token_address": "0x2222222222222222222222222222222222222222",
    "token_amount": 100,
    "slippage_bps": 50,
}


def policy(**overrides):
    values = {
        "allowed_chain_ids": [84532],
        "allowed_contracts": [INTENT["to"]],
        "allowed_function_selectors": [INTENT["function_selector"]],
        "max_value_wei": 0,
        "max_token_amount": 1000,
        "max_slippage_bps": 100,
    }
    values.update(overrides)
    return TransactionPolicy.from_dict(values)


def test_allow_decision_is_hash_bound_and_never_broadcasts():
    decision = evaluate_transaction_intent(TransactionIntent.from_dict(INTENT), policy())
    assert decision.action == "allow"
    assert decision.intent_hash.startswith("sha256:")
    assert decision.execution == "not_broadcast"


@pytest.mark.parametrize(
    ("field", "value", "rule_id"),
    [
        ("chain_id", 1, "chain-not-allowed"),
        ("to", "0x3333333333333333333333333333333333333333", "contract-not-allowed"),
        ("function_selector", "0x095ea7b3", "function-not-allowed"),
        ("token_amount", 1001, "token-value-limit"),
        ("slippage_bps", 101, "slippage-limit"),
    ],
)
def test_policy_denies_violations(field, value, rule_id):
    raw = {**INTENT, field: value}
    decision = evaluate_transaction_intent(TransactionIntent.from_dict(raw), policy())
    assert decision.action == "deny"
    assert decision.rule_id == rule_id


def test_policy_can_require_human_approval():
    decision = evaluate_transaction_intent(TransactionIntent.from_dict(INTENT), policy(require_approval=True))
    assert decision.action == "escalate"
    assert decision.rule_id == "approval-required"


def test_intent_rejects_malformed_address():
    with pytest.raises(ValueError, match="20-byte"):
        TransactionIntent.from_dict({**INTENT, "to": "not-an-address"})
