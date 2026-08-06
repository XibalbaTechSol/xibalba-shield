# Signed Policy Bundles

Status: design accepted for Shield-local format; tenant cloud distribution and asymmetric signature verification remain planned until a real server/key contract exists.

## Goals

- Make each policy bundle uniquely identifiable by a stable hash over the exact bytes loaded.
- Let operators pin known-good bundle hashes in local device config today.
- Leave room for tenant-signed distribution without changing rule semantics later.
- Preserve fail-closed behavior: malformed, untrusted, or unverifiable bundles must not replace last-known-good rules.

## Current Implemented Format

Policy files are JSON objects:

```json
{
  "policy_version": "regulated-2026.08",
  "rules": []
}
```

`shield.config.load_policy_bundle()` computes:

- `version`: `policy_version` or `version`, if present.
- `hash`: `sha256:` plus SHA-256 over the exact policy file bytes.
- `rules`: parsed `PolicyRule` entries in file order.

`shield run` and `PolicyHotReloader` enforce `DeviceConfig.trusted_policy_hashes` when that list is non-empty. A bundle whose computed hash is absent from the trusted list is rejected and does not start or replace live policy.

## Device Trust Pinning

Example `/etc/xibalba-shield/device.json`:

```json
{
  "device_id": "pilot-linux-001",
  "tenant_id": "tenant-001",
  "trusted_policy_hashes": [
    "sha256:e7101882773dbacf4af5e39f047ce8f0e8efd6843b87c1636e70ef5f0ad98939"
  ]
}
```

This is not tenant cloud signing. It is a local integrity pin that prevents accidental startup or hot reload with an unexpected policy file.

## Future Signed Bundle Envelope

When tenant policy distribution exists, use an envelope that signs a canonical policy payload:

```json
{
  "policy_version": "regulated-2026.08",
  "tenant_id": "tenant-001",
  "issued_at": "2026-08-06T00:00:00Z",
  "expires_at": "2026-09-06T00:00:00Z",
  "key_id": "tenant-policy-key-2026-08",
  "rules": [],
  "signature": {
    "alg": "Ed25519",
    "covers": "canonical-policy-payload-v1",
    "value": "base64url-signature"
  }
}
```

Verification requirements:

- Verify `tenant_id` matches device scope.
- Verify `issued_at`/`expires_at`.
- Verify `key_id` against a locally trusted tenant public key set.
- Verify Ed25519 signature over the canonical payload excluding `signature`.
- Compute and record the exact-file `sha256:` hash after signature verification.
- Reject the whole bundle on any verification failure and keep last-known-good rules.

## Non-Goals

- Shield does not fetch policies from a tenant cloud API until that API has a real contract.
- Shield does not auto-update agent code through this mechanism.
- Shield does not treat a local JSONL decision as cryptographic evidence; only Integrity-accepted exports have that posture.
