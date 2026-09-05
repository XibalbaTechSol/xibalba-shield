"""
Policy bundle signing/verification — spec/xibalba-shield-v1.md §4.6, closing the
"signed policy bundle verification" and "expiry" items of
docs/PRODUCTION_READINESS_PLAN.md workstream B.

Reuses `integrity_sdk.did`'s real Ed25519 primitives (`Keypair.sign`/`verify_signature`)
rather than inventing a second signing scheme — this ecosystem's stated rule (see that
module's own docstring) is that `cryptography`-backed Ed25519 is the only signing
backend anywhere, never HMAC. This module owns only the policy-bundle-specific
canonicalization and the bundle's own signed-wrapper shape; `did.py` owns the actual
crypto.

Bundle shapes `shield/config/loader.py` understands:
  - Legacy/unsigned: `{"rules": [...], "policy_version": "...", "policy_revision": N}`
  - Signed: `{"policy": {...same fields, plus optional "expires_at"...},
              "signature": "<base64 Ed25519 sig>", "signer_public_key": "<base64 pubkey>"}`

The signature covers the canonical JSON encoding of the `policy` object only -- sorted
keys, no whitespace -- matching the canonicalization convention already used elsewhere
in this ecosystem (e.g. xibalba-cortex's `_canonical_json`) so a signature verifier
never has to guess which serialization the signer used.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from integrity_sdk.did import Keypair, verify_signature


def canonical_policy_json(policy: dict) -> bytes:
    """The exact bytes a signature is computed over and verified against --
    signer and verifier MUST agree byte-for-byte, so this is the single
    definition both `sign_policy_bundle` and `verify_policy_signature` call."""
    return json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_policy_bundle(policy: dict, keypair: Keypair) -> dict:
    """Wrap a plain policy dict (the same shape `load_policy_bundle` already
    accepts unsigned) into the signed-wrapper shape, signed by `keypair`."""
    signature = keypair.sign(canonical_policy_json(policy))
    return {
        "policy": policy,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signer_public_key": base64.b64encode(keypair.public_bytes()).decode("ascii"),
    }


@dataclass(frozen=True)
class SignatureResult:
    """Never raises -- callers (loader.py) decide fail-open vs fail-closed based on
    their own `require_signed_policy` setting, so verification failure must be a
    value, not an exception, the same way a policy decision itself is a value."""

    verified: bool
    signer_public_key: str | None
    reason: str | None = None


def verify_policy_signature(doc: dict, trusted_keys: list[str]) -> SignatureResult:
    """Verify a signed-wrapper bundle's signature, trusted-signer membership, and
    expiry. `trusted_keys` empty means signer-trust is not enforced (today's
    hash-allowlist-only deployments keep working unchanged) -- signature validity
    and expiry are still checked regardless, so a present-but-invalid signature is
    always rejected even with no trusted-keys list configured."""
    policy = doc.get("policy")
    signature_b64 = doc.get("signature")
    signer_key_b64 = doc.get("signer_public_key")
    if not isinstance(policy, dict) or not signature_b64 or not signer_key_b64:
        return SignatureResult(verified=False, signer_public_key=None, reason="malformed signed-bundle shape")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
        signer_key = base64.b64decode(signer_key_b64, validate=True)
    except (ValueError, TypeError) as exc:
        return SignatureResult(verified=False, signer_public_key=None, reason=f"malformed base64: {exc}")

    if not verify_signature(signer_key, canonical_policy_json(policy), signature):
        return SignatureResult(verified=False, signer_public_key=signer_key_b64, reason="signature does not verify against signer_public_key")

    if trusted_keys and signer_key_b64 not in trusted_keys:
        return SignatureResult(verified=False, signer_public_key=signer_key_b64, reason=f"signer {signer_key_b64} is not in trusted_signing_keys")

    expires_at = policy.get("expires_at")
    if expires_at:
        try:
            expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        except ValueError as exc:
            return SignatureResult(verified=False, signer_public_key=signer_key_b64, reason=f"malformed expires_at: {exc}")
        if expiry <= datetime.now(timezone.utc):
            return SignatureResult(verified=False, signer_public_key=signer_key_b64, reason=f"policy expired at {expires_at}")

    return SignatureResult(verified=True, signer_public_key=signer_key_b64, reason=None)
