"""Short-lived signed device assertions — the replacement for long-lived device bearer tokens.

Why this exists
---------------
A device agent is a machine caller: no browser, no cookie jar, no human to type a password. It
authenticated with `device_token`, a long-lived bearer secret minted at enrollment. That secret
sits on disk on every protected endpoint, never expires, and is replayable by anyone who reads
it. This module replaces it with an assertion the device *signs*, per request, with the Ed25519
key it already holds — so nothing long-lived and replayable travels on the wire.

Why not mutual TLS
------------------
mTLS would need a CA, certificate distribution, renewal, and reverse-proxy passthrough that this
deployment does not have. The device already owns an Ed25519 keypair and already produces signed
Behavioral Commitment Chain (BCC) records through `integrity_sdk`, so signing is a capability
that is present and tested. This reuses it rather than standing up a second trust domain.

Relationship to BCC — deliberately separate
-------------------------------------------
The BCC commitment shape is frozen in `integrity-core/docs/INTERFACE_CONTRACT.md`, and this
repository's rule is that `integrity_exporter` must never invent commitment fields. An auth
assertion is a *different record type* with a different purpose, so it carries its own namespaced
`type` and is built here rather than by `build_bcc_commitment`. It borrows only the canonical-JSON
encoder, so both sides agree on bytes.

How key substitution is blocked
-------------------------------
The assertion carries the public key, which invites the obvious attack: sign with your own key
and claim to be someone else. The binding that stops it is the same one BCC uses — the device's
recorded `integrity_agent_id` is `did:integrity:sha256(pubkey)`, so the verifier recomputes that
fingerprint from the supplied key and requires it to equal the enrolled value *before* checking
the signature. A substituted key yields a different fingerprint and is rejected without ever
reaching signature verification.

Fail-closed posture
-------------------
Every verification failure returns False and authenticates nothing. There is no degraded mode:
an assertion that cannot be parsed, is expired, is addressed to another audience, replays a
nonce, or whose key does not bind to the enrolled device is simply not authenticated. The caller
decides whether to fall back to `device_token` during migration; this module never does.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
from typing import Any, Callable

from integrity_sdk.bcc import canonical_json_bytes
from integrity_sdk.did import Keypair, fingerprint_for_pubkey, verify_signature

ASSERTION_TYPE = "xibalba.shield.device-assertion.v1"
ASSERTION_SCHEME = "Assertion"

# Deliberately short. The assertion is minted per request, so this only has to cover clock skew
# plus flight time; a longer window widens the replay surface for no operational benefit.
DEFAULT_TTL_SECONDS = 120

# Reject assertions issued "in the future" by more than this, so a device with a badly wrong
# clock fails loudly instead of minting credentials that outlive their intended window.
_MAX_CLOCK_SKEW_SECONDS = 60


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64u(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _signable(claims: dict[str, Any]) -> bytes:
    """Canonical bytes both sides sign and verify over.

    `signature` is excluded rather than set empty: including a placeholder would make the signed
    bytes depend on the placeholder's exact spelling, which is a needless compatibility hazard.
    """
    return canonical_json_bytes({key: value for key, value in claims.items() if key != "signature"})


def build_assertion(
    *,
    keypair: Keypair,
    tenant_id: str,
    device_id: str,
    audience: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> str:
    """Mint a signed assertion and return it as an `Authorization` header value.

    `audience` binds the assertion to one backend, so an assertion captured by one service cannot
    be replayed against another.
    """
    issued_at = int(now if now is not None else time.time())
    claims: dict[str, Any] = {
        "type": ASSERTION_TYPE,
        "tenant_id": tenant_id,
        "device_id": device_id,
        "audience": audience,
        "agent_public_key": _b64u(keypair.public_bytes()),
        "nonce": _b64u(secrets.token_bytes(16)),
        "issued_at": issued_at,
        "expires_at": issued_at + int(ttl_seconds),
    }
    claims["signature"] = _b64u(keypair.sign(_signable(claims)))
    return f"{ASSERTION_SCHEME} {_b64u(canonical_json_bytes(claims))}"


def load_device_keypair(agent_label: str | None = None) -> Keypair | None:
    """Load the device's Ed25519 key for signing, or None if it is not on disk.

    Deliberately read-only. `integrity_sdk.did.load_or_create_did()` silently generates a
    replacement keypair — and overwrites `private_key.pem` — whenever the key and its
    `document.json` disagree, which destroys the registered identity. Authentication must never
    be able to trigger that, so this reads the key directly and returns None rather than
    creating anything. A missing key means "fall back to the legacy token", not "mint a new one".
    """
    from integrity_sdk.did import agent_dir

    label = agent_label or os.environ.get("SHIELD_AGENT_LABEL") or "xibalba-shield"
    key_path = agent_dir(label) / "private_key.pem"
    try:
        return Keypair.from_pem(key_path.read_bytes())
    except (OSError, ValueError):
        return None


def device_auth_header(
    *,
    tenant_id: str,
    device_id: str,
    audience: str,
    device_token: str = "",
    agent_label: str | None = None,
) -> str:
    """Build the `Authorization` header for a device→backend request.

    Prefers a signed assertion. Falls back to the legacy long-lived `device_token` when the
    device has no signing key on disk, so a device enrolled before this migration keeps working.
    Returns an empty string when neither credential is available; the caller then sends no
    Authorization header and the backend fails it closed.
    """
    keypair = load_device_keypair(agent_label)
    if keypair is not None:
        return build_assertion(keypair=keypair, tenant_id=tenant_id, device_id=device_id, audience=audience)
    return f"Bearer {device_token}" if device_token else ""


class ReplayGuard:
    """Rejects a nonce that has already been accepted, bounded by assertion lifetime.

    Entries are dropped once they can no longer be valid, so this stays small without a sweeper
    thread. It is per-process: a multi-process deployment needs a shared store, and until then
    the short TTL plus audience binding is what limits replay.
    """

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def check_and_record(self, nonce: str, expires_at: int, *, now: int) -> bool:
        for key, expiry in [(k, v) for k, v in self._seen.items() if v <= now]:
            del self._seen[key]
        if nonce in self._seen:
            return False
        self._seen[nonce] = expires_at
        return True


def verify_assertion(
    header_value: str,
    *,
    expected_audience: str,
    lookup_enrolled_agent_id: Callable[[str, str], str | None],
    replay_guard: ReplayGuard | None = None,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Verify an `Authorization: Assertion <...>` header.

    Returns the verified claims, or None. `lookup_enrolled_agent_id(tenant_id, device_id)` must
    return the `integrity_agent_id` recorded for that device at registration, or None if the
    device is unknown or was never bound to an agent identity.
    """
    if not header_value.startswith(f"{ASSERTION_SCHEME} "):
        return None
    try:
        claims = json.loads(_unb64u(header_value[len(ASSERTION_SCHEME) + 1:].strip()))
    except Exception:
        return None
    if not isinstance(claims, dict) or claims.get("type") != ASSERTION_TYPE:
        return None

    required = ("tenant_id", "device_id", "audience", "agent_public_key", "nonce", "issued_at", "expires_at", "signature")
    if any(field not in claims for field in required):
        return None

    if claims["audience"] != expected_audience:
        return None

    current = int(now if now is not None else time.time())
    try:
        issued_at, expires_at = int(claims["issued_at"]), int(claims["expires_at"])
    except (TypeError, ValueError):
        return None
    if current >= expires_at or issued_at > current + _MAX_CLOCK_SKEW_SECONDS:
        return None

    enrolled_agent_id = lookup_enrolled_agent_id(str(claims["tenant_id"]), str(claims["device_id"]))
    if not enrolled_agent_id:
        return None

    try:
        pubkey = _unb64u(str(claims["agent_public_key"]))
        signature = _unb64u(str(claims["signature"]))
    except Exception:
        return None

    # Bind the supplied key to the enrolled identity BEFORE verifying the signature. Without
    # this, any valid self-signed assertion would authenticate as any device.
    if f"did:integrity:{fingerprint_for_pubkey(pubkey)}" != enrolled_agent_id:
        return None

    if not verify_signature(pubkey, _signable(claims), signature):
        return None

    if replay_guard is not None and not replay_guard.check_and_record(str(claims["nonce"]), expires_at, now=current):
        return None

    return claims
