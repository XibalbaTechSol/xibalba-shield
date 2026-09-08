"""Package/artifact signing -- closes the "signed package/update" half of
docs/PRODUCTION_READINESS_PLAN.md §7 item 5 / Gate 5 ("Pass when signed installation,
upgrade, rollback, service confinement, key handling, observability, and recovery are
exercised from a clean host").

Deliberately a SEPARATE key/trust domain from `shield/config/signing.py`'s policy-bundle
signing -- a policy-signing key compromise and a package-signing key compromise have very
different blast radii (a malicious policy vs. a malicious binary running as the service
account), so they must never share a key file or a trust list. Reuses the same Ed25519-
via-`integrity_sdk.did.Keypair` primitive and PEM/0600 key-handling convention as
`config/signing.py` / `cli.py`'s `_sign_policy` -- this ecosystem's stated rule is that
Ed25519-via-`cryptography` is the only signing backend anywhere, never a third scheme
invented for a third purpose.

`docs/PRODUCTION_READINESS_PLAN.md` §8 lists "production signing infrastructure... and
release approvals" as an external gate (real HSM/PKI, real key custody) -- this module is
the *mechanism* (sign/verify code using a locally-generatable keypair), not that
infrastructure. `scripts/pilot_gate_report.py`'s `_installer_gate` remains a self-
attestation stub until an operator wires a real `--installer-attestation` produced from
this module's own `sha256_of`/`verify_artifact`, not a hand-typed keyword file.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from integrity_sdk.did import Keypair, verify_signature


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_attestation_json(fields: dict[str, Any]) -> bytes:
    """The exact bytes a signature is computed over and verified against -- same
    sorted-keys, no-whitespace convention as `config.signing.canonical_policy_json`, so a
    verifier never has to guess which serialization the signer used."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_artifact(path: Path, keypair: Keypair) -> dict[str, Any]:
    """Build a signed attestation for the real file at `path` -- {"artifact", "sha256",
    "signed_at", "signature", "signer_public_key"}. The signature covers artifact/sha256/
    signed_at only, never the signature/signer_public_key fields themselves (can't sign
    your own signature, same rule `config/signing.py` follows)."""
    fields = {
        "artifact": path.name,
        "sha256": sha256_of(path),
        "signed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    signature = keypair.sign(_canonical_attestation_json(fields))
    return {
        **fields,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signer_public_key": base64.b64encode(keypair.public_bytes()).decode("ascii"),
    }


@dataclass(frozen=True)
class VerificationResult:
    """Never raised as an exception path -- callers (install_release) decide what to do
    with a failed verification; a value, not a raise, same convention as
    `config.signing.SignatureResult`."""

    verified: bool
    signer_public_key: str | None
    reason: str | None = None


def verify_artifact(
    path: Path, attestation: dict[str, Any], trusted_keys: list[str] | None = None
) -> VerificationResult:
    """Three checks, in order: (1) the real file on disk actually hashes to what the
    attestation claims -- catches a swapped/corrupted/wrong-version artifact before any
    cryptography runs; (2) the signature verifies against the attestation's own claimed
    signer key; (3) that signer is in `trusted_keys`, when a trust list is given (empty/
    None means signer-trust is not enforced, matching `config/signing.py`'s convention --
    hash+signature validity is still always checked)."""
    actual_sha256 = sha256_of(path)
    claimed_sha256 = attestation.get("sha256")
    if actual_sha256 != claimed_sha256:
        return VerificationResult(
            False, None,
            f"sha256 mismatch: artifact on disk is {actual_sha256}, attestation claims {claimed_sha256}",
        )

    signature_b64 = attestation.get("signature")
    signer_key_b64 = attestation.get("signer_public_key")
    if not signature_b64 or not signer_key_b64:
        return VerificationResult(False, None, "malformed attestation: missing signature/signer_public_key")

    signed_fields = {k: v for k, v in attestation.items() if k not in ("signature", "signer_public_key")}
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        signer_key = base64.b64decode(signer_key_b64, validate=True)
    except (ValueError, TypeError) as exc:
        return VerificationResult(False, None, f"malformed base64: {exc}")

    if not verify_signature(signer_key, _canonical_attestation_json(signed_fields), signature):
        return VerificationResult(False, signer_key_b64, "signature does not verify against signer_public_key")

    if trusted_keys and signer_key_b64 not in trusted_keys:
        return VerificationResult(False, signer_key_b64, f"signer {signer_key_b64} is not in trusted keys")

    return VerificationResult(True, signer_key_b64, None)
