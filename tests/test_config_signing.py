"""
Tests for shield/config/signing.py -- real Ed25519 signing via integrity_sdk.did.Keypair,
no mocked crypto. Every test signs/verifies real bytes.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from integrity_sdk.did import Keypair

from shield.config.signing import sign_policy_bundle, verify_policy_signature


def _policy(**extra) -> dict:
    return {
        "policy_version": "v-1",
        "policy_revision": 1,
        "rules": [{"rule_id": "a", "name": "a", "version": "1.0.0", "conditions": [], "actions": [{"type": "allow"}]}],
        **extra,
    }


def test_sign_then_verify_round_trip_with_no_trusted_keys_configured():
    keypair = Keypair.generate()
    doc = sign_policy_bundle(_policy(), keypair)

    result = verify_policy_signature(doc, trusted_keys=[])

    assert result.verified is True
    assert result.reason is None
    assert result.signer_public_key == base64.b64encode(keypair.public_bytes()).decode("ascii")


def test_verify_succeeds_when_signer_is_in_trusted_keys():
    keypair = Keypair.generate()
    doc = sign_policy_bundle(_policy(), keypair)
    trusted = base64.b64encode(keypair.public_bytes()).decode("ascii")

    result = verify_policy_signature(doc, trusted_keys=[trusted])

    assert result.verified is True


def test_verify_rejects_an_untrusted_signer():
    keypair = Keypair.generate()
    other = Keypair.generate()
    doc = sign_policy_bundle(_policy(), keypair)
    trusted = base64.b64encode(other.public_bytes()).decode("ascii")

    result = verify_policy_signature(doc, trusted_keys=[trusted])

    assert result.verified is False
    assert "not in trusted_signing_keys" in result.reason


def test_verify_rejects_tampered_policy_content():
    keypair = Keypair.generate()
    doc = sign_policy_bundle(_policy(), keypair)
    doc["policy"]["policy_version"] = "v-tampered"

    result = verify_policy_signature(doc, trusted_keys=[])

    assert result.verified is False
    assert "does not verify" in result.reason


def test_verify_rejects_a_tampered_signature():
    keypair = Keypair.generate()
    doc = sign_policy_bundle(_policy(), keypair)
    real_sig = base64.b64decode(doc["signature"])
    doc["signature"] = base64.b64encode(bytes([real_sig[0] ^ 0xFF]) + real_sig[1:]).decode("ascii")

    result = verify_policy_signature(doc, trusted_keys=[])

    assert result.verified is False


def test_verify_rejects_an_expired_policy():
    keypair = Keypair.generate()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    doc = sign_policy_bundle(_policy(expires_at=past), keypair)

    result = verify_policy_signature(doc, trusted_keys=[])

    assert result.verified is False
    assert "expired" in result.reason


def test_verify_accepts_a_not_yet_expired_policy():
    keypair = Keypair.generate()
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    doc = sign_policy_bundle(_policy(expires_at=future), keypair)

    result = verify_policy_signature(doc, trusted_keys=[])

    assert result.verified is True


def test_verify_rejects_malformed_wrapper_shape():
    result = verify_policy_signature({"rules": []}, trusted_keys=[])

    assert result.verified is False
    assert "malformed" in result.reason
