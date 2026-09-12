"""Signed device assertions — the replacement for long-lived device bearer tokens.

The negative cases matter more than the happy path here: an assertion carries its own public key,
so the tests that prove key substitution, replay, expiry, and audience confusion are rejected are
the ones that justify the mechanism.
"""
from __future__ import annotations

import pytest

from integrity_sdk.did import Keypair, fingerprint_for_pubkey

from shield.device_assertion import ReplayGuard, build_assertion, verify_assertion

AUDIENCE = "https://shield.example"
TENANT = "tenant-a"
DEVICE = "device-1"


@pytest.fixture
def keypair() -> Keypair:
    return Keypair.generate()


@pytest.fixture
def lookup(keypair: Keypair):
    enrolled = f"did:integrity:{fingerprint_for_pubkey(keypair.public_bytes())}"

    def _lookup(tenant_id: str, device_id: str) -> str | None:
        return enrolled if (tenant_id, device_id) == (TENANT, DEVICE) else None

    return _lookup


def _header(keypair: Keypair, **overrides) -> str:
    params = {"keypair": keypair, "tenant_id": TENANT, "device_id": DEVICE, "audience": AUDIENCE}
    params.update(overrides)
    return build_assertion(**params)


def test_valid_assertion_verifies(keypair, lookup):
    claims = verify_assertion(_header(keypair), expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup)
    assert claims is not None
    assert claims["tenant_id"] == TENANT and claims["device_id"] == DEVICE


def test_substituted_key_is_rejected(lookup):
    """The attack the fingerprint binding exists to stop.

    An attacker signs a perfectly valid assertion with their own key and claims to be the
    enrolled device. The signature verifies against the key they supplied — so the only thing
    standing between them and authentication is the fingerprint check.
    """
    attacker = Keypair.generate()
    assert verify_assertion(_header(attacker), expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup) is None


def test_expired_assertion_is_rejected(keypair, lookup):
    stale = _header(keypair, ttl_seconds=1, now=1_000_000)
    assert verify_assertion(stale, expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup, now=1_000_100) is None


def test_assertion_for_another_audience_is_rejected(keypair, lookup):
    other = _header(keypair, audience="https://somewhere-else.example")
    assert verify_assertion(other, expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup) is None


def test_replayed_assertion_is_rejected(keypair, lookup):
    guard = ReplayGuard()
    header = _header(keypair)
    assert verify_assertion(header, expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup, replay_guard=guard)
    assert verify_assertion(header, expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup, replay_guard=guard) is None


def test_tampered_claim_is_rejected(keypair, lookup):
    import base64
    import json

    scheme, _, encoded = _header(keypair).partition(" ")
    padding = "=" * (-len(encoded) % 4)
    claims = json.loads(base64.urlsafe_b64decode(encoded + padding))
    claims["device_id"] = "someone-elses-device"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    assert verify_assertion(f"{scheme} {forged}", expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup) is None


def test_unregistered_device_fails_closed(keypair):
    """A device with no bound agent identity has nothing to verify against."""
    assert verify_assertion(_header(keypair), expected_audience=AUDIENCE, lookup_enrolled_agent_id=lambda *_: None) is None


def test_bearer_header_is_not_mistaken_for_an_assertion(keypair, lookup):
    assert verify_assertion("Bearer some-token", expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup) is None


def test_malformed_assertion_is_rejected(lookup):
    for value in ("Assertion", "Assertion !!!not-base64!!!", "Assertion " + "eyJhIjoxfQ", ""):
        assert verify_assertion(value, expected_audience=AUDIENCE, lookup_enrolled_agent_id=lookup) is None
