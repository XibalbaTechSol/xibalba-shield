# Shield Transaction Gateway

## Status

The first control-plane slice is implemented. `POST /api/shield/transaction-intents`
authenticates an enrolled device, loads its configured `transaction_policy`, and returns a
hash-bound `allow`, `deny`, or `escalate` decision.

`POST /api/shield/transaction-simulations` performs the same policy gate and, only after an
allow decision, calls the server-side trusted RPC registry with `eth_call` and
`eth_estimateGas`. It never accepts a caller-supplied RPC URL and never calls a write method.

`POST /api/shield/transaction-approvals` creates a human approval only for a persisted
`escalate` decision. The approval is bound to the intent hash, tenant, device, approver, and
expiry. An enrolled device can call `POST /api/shield/transaction-approvals/verify` to check
the approval, but cannot create one.

`POST /api/shield/transaction-approvals/consume` atomically marks an approval consumed and
returns the exact approved intent. Reuse returns a conflict. The `ExternalWalletSigner` client
is a separate transport boundary: it accepts only the consumed approval and unsigned
transaction, and expects an isolated signer service to return a raw signed transaction. No
private key is present in the Shield API or policy process.

This slice is deliberately non-custodial and non-executing. It does not quote, simulate,
sign, submit, or confirm a blockchain transaction. Every decision reports
`execution: not_broadcast`.

## Intent contract

Required fields are `tenant_id`, `device_id`, `agent_id`, `request_id`, `chain_id`, `to`, and
`function_selector`. Optional limits include `value_wei`, `token_address`, `token_amount`,
and `slippage_bps`.

The normalized intent is serialized with sorted keys and hashed with SHA-256. The hash is
returned with the decision and must be carried into later simulation, approval, signing, and
receipt records. A later stage must reject any transaction whose executable calldata does not
match the approved intent hash.

## Policy shape

```json
{
  "policy_version": "tenant-tx-v1",
  "transaction_policy": {
    "allowed_chain_ids": [84532],
    "allowed_contracts": ["0x1111111111111111111111111111111111111111"],
    "allowed_function_selectors": ["0xa9059cbb"],
    "max_value_wei": 0,
    "max_token_amount": 1000000,
    "max_slippage_bps": 100,
    "require_approval": true
  },
  "rules": []
}
```

Empty or missing allowlists do not authorize execution. The endpoint also requires the
existing device bearer token; admin credentials and private keys are not accepted as an
execution mechanism.

## Next gates

1. Add an explicit versioned chain and token registry rather than relying only on built-in RPC defaults.
2. Add signer-service authentication and one-time consumption at the signer boundary.
3. Add receipt/finality verification and dashboard views.
4. Evaluate smart-account/paymaster sponsorship only after the non-sponsored path is proven.

The gateway must continue to fail closed for missing policy, unsupported assets, unavailable
RPCs, simulation mismatch, stale approvals, and receipt ambiguity.
