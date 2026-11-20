---
title: Policy Pack Studio & Live OPA Editor
category: concepts
tags: [opa, rego, policy-studio, governance, hot-reload]
status: active
last_updated: 2026-11-20
---

# Policy Pack Studio & Live OPA Editor

Xibalba Shield provides an integrated Policy Pack Studio and live Rego editor within the Operator Console, allowing security administrators to view, edit, validate, and hot-deploy Open Policy Agent (OPA) rules.

## Policy Pack Architecture

Policies are organized into modular Rego packs located under `shield/policies/rego/*.rego`:
- `smb.rego`: Basic security baseline for small-to-medium business workstations (restricts unauthorized reverse shells, outbound socket creation, and privileged system modifications).
- `professional-services.rego`: Tailored for client laptops, confidential repositories, and credential vaults.
- `regulated.rego`: Strict zero-trust profile enforcing HIPAA §164.312 access controls, EHR containment, and cryptographic proof of custody.
- Custom Packs: Arbitrary operator-defined `.rego` files automatically discovered and listed by the backend.

## In-Browser Live Editor & Hot Deployment

1. **Syntax Validation**: The UI and backend validate Rego package headers (`package shield.*`) and ensure syntactically sound rule definitions before persisting.
2. **Local Disk Persistence**: Changes are committed atomically to `shield/policies/rego/<policy_id>.rego`.
3. **Hot OPA Injection**: The backend transmits the updated Rego definition via HTTP `PUT` to the running OPA daemon at `{opa_url}/v1/policies/<policy_id>.rego`.
4. **Audit Rollback**: Previous policy hashes are preserved in the policy version ledger, enabling one-click rollbacks via `RollbackForm`.
