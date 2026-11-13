"""Signed, expiring entitlements: what a device's plan allows, verifiable offline.

Design: docs/superpowers/specs/2026-11-12-shield-plans-metering-design.md §6.

The L0 gate never calls home while it answers a tool call (§1, "billing is never in the decision
path"), so the plan travels *to* the device as a document the backend signs:

    {"schema": "xibalba.shield.entitlement.v1", "canonicalization": "xibalba.canonical-json.v2",
     "tenant_id": "...", "device_id": "...", "plan": "pro", "zone_enforce": true,
     "issued_at": "<ISO-8601>", "not_after": "<ISO-8601>",
     "signer_public_key": "<base64 Ed25519>", "signature": "<base64>"}

The signature covers every field except `signature` (JCS bytes, the same canonicalization as policy
bundles). Verification is a *value*, never an exception: the gate turns any status other than `ok`
into shadow mode, and a broken entitlement must never become a crashed gate or a blocked call.

Statuses (each becomes the receipt control ``ais_zone_entitlement:<status>``):

    ok             signed by a trusted key, for this tenant and device, in its validity window,
                   and the plan includes zone enforcement
    missing        no entitlement file configured, or the file does not exist
    malformed      unreadable JSON, wrong schema, or a field of the wrong type
    bad_signature  the signature does not verify, or the signer is not a trusted key
    wrong_device   signed for another tenant or device
    not_yet_valid  issued more than the allowed clock skew in the future
    expired        `not_after` has passed
    plan           valid, but the plan does not include zone enforcement

This is a commercial licence check on software running on the customer's own machine, not a
security boundary: the owner of the device can change the code. What it guarantees is that an
honest gate enforces exactly what was paid for, and degrades to observing -- never to blocking.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from integrity_sdk.did import Keypair, verify_signature

from .canonical import CANONICALIZATION, canonical_bytes

logger = logging.getLogger(__name__)

ENTITLEMENT_SCHEMA = "xibalba.shield.entitlement.v1"

STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_MALFORMED = "malformed"
STATUS_BAD_SIGNATURE = "bad_signature"
STATUS_WRONG_DEVICE = "wrong_device"
STATUS_NOT_YET_VALID = "not_yet_valid"
STATUS_EXPIRED = "expired"
STATUS_PLAN = "plan"
STATUSES = (STATUS_OK, STATUS_MISSING, STATUS_MALFORMED, STATUS_BAD_SIGNATURE, STATUS_WRONG_DEVICE,
            STATUS_NOT_YET_VALID, STATUS_EXPIRED, STATUS_PLAN)

#: How far in the future `issued_at` may be before the document is refused (device clock skew).
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300.0

_SIGNED_FIELDS = ("schema", "canonicalization", "tenant_id", "device_id", "plan", "zone_enforce",
                  "issued_at", "not_after", "signer_public_key")


def _signed_bytes(document: Mapping[str, Any]) -> bytes:
    return canonical_bytes({name: document[name] for name in _SIGNED_FIELDS})


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return parsed


def sign_entitlement(
    *,
    tenant_id: str,
    device_id: str,
    plan: str,
    zone_enforce: bool,
    issued_at: datetime,
    not_after: datetime,
    keypair: Keypair,
) -> dict[str, Any]:
    """The backend's side (and the tests'): a signed entitlement document."""
    if issued_at.tzinfo is None or not_after.tzinfo is None:
        raise ValueError("issued_at and not_after must be timezone-aware")
    if not_after <= issued_at:
        raise ValueError("not_after must be after issued_at")
    document: dict[str, Any] = {
        "schema": ENTITLEMENT_SCHEMA,
        "canonicalization": CANONICALIZATION,
        "tenant_id": tenant_id,
        "device_id": device_id,
        "plan": plan,
        "zone_enforce": bool(zone_enforce),
        "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
        "not_after": not_after.astimezone(timezone.utc).isoformat(),
        "signer_public_key": base64.b64encode(keypair.public_bytes()).decode("ascii"),
    }
    document["signature"] = base64.b64encode(keypair.sign(_signed_bytes(document))).decode("ascii")
    return document


def verify_entitlement(
    document: Any,
    *,
    trusted_keys: Sequence[str],
    tenant_id: str,
    device_id: str,
    now: datetime,
    max_clock_skew_seconds: float = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
) -> str:
    """One of `STATUSES`. Never raises.

    An empty `trusted_keys` trusts nothing: unlike policy bundles there is no unsigned legacy mode,
    because an entitlement anyone can sign is not an entitlement.
    """
    try:
        if not isinstance(document, Mapping):
            return STATUS_MALFORMED
        if set(document) != {*_SIGNED_FIELDS, "signature"}:
            return STATUS_MALFORMED
        if document["schema"] != ENTITLEMENT_SCHEMA or document["canonicalization"] != CANONICALIZATION:
            return STATUS_MALFORMED
        for name in ("tenant_id", "device_id", "plan", "signer_public_key", "signature"):
            if not isinstance(document[name], str) or not document[name]:
                return STATUS_MALFORMED
        if not isinstance(document["zone_enforce"], bool):
            return STATUS_MALFORMED
        issued_at = _parse_time(document["issued_at"])
        not_after = _parse_time(document["not_after"])
        signer_key = base64.b64decode(document["signer_public_key"], validate=True)
        signature = base64.b64decode(document["signature"], validate=True)
    except (ValueError, TypeError, KeyError):
        return STATUS_MALFORMED

    # Trust, then signature, before reading any claim: an untrusted document's fields mean nothing.
    if document["signer_public_key"] not in trusted_keys:
        return STATUS_BAD_SIGNATURE
    try:
        if not verify_signature(signer_key, _signed_bytes(document), signature):
            return STATUS_BAD_SIGNATURE
    except Exception:  # noqa: BLE001 -- a verifier failure is a failed verification, not a crash
        return STATUS_BAD_SIGNATURE
    if document["tenant_id"] != tenant_id or document["device_id"] != device_id:
        return STATUS_WRONG_DEVICE
    if (issued_at - now).total_seconds() > max_clock_skew_seconds:
        return STATUS_NOT_YET_VALID
    if now >= not_after:
        return STATUS_EXPIRED
    if not document["zone_enforce"]:
        return STATUS_PLAN
    return STATUS_OK


class EntitlementGate:
    """The gate's view of its entitlement file: `status()` on every enforce decision.

    The file is re-read only when its (mtime, size, inode) changes, so a refreshed entitlement is
    picked up without a restart and an unchanged one costs a `stat`. Expiry is evaluated against the
    clock on every call, so an entitlement that lapses while the gate runs drops it to shadow then,
    not at the next restart. Never raises.
    """

    def __init__(
        self,
        path: Optional[str | os.PathLike[str]],
        *,
        trusted_keys: Sequence[str],
        tenant_id: str,
        device_id: str,
        clock: Callable[[], float] = time.time,
        max_clock_skew_seconds: float = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    ) -> None:
        self._path = Path(path) if path else None
        self._trusted_keys = tuple(trusted_keys)
        self._tenant_id = tenant_id
        self._device_id = device_id
        self._clock = clock
        self._skew = max_clock_skew_seconds
        self._lock = threading.Lock()
        self._stamp: Optional[tuple[int, int, int]] = None
        self._document: Any = None
        self._last_status: Optional[str] = None

    def _load(self) -> Any:
        """The parsed document, `None` when absent, or the sentinel `STATUS_MALFORMED`."""
        assert self._path is not None
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            self._stamp, self._document = None, None
            return None
        except OSError:
            return STATUS_MALFORMED
        stamp = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
        if stamp != self._stamp:
            try:
                self._document = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, ValueError, UnicodeDecodeError):
                self._document = STATUS_MALFORMED
            self._stamp = stamp
        return self._document

    def status(self) -> str:
        try:
            with self._lock:
                if self._path is None:
                    status = STATUS_MISSING
                else:
                    document = self._load()
                    if document is None:
                        status = STATUS_MISSING
                    elif document == STATUS_MALFORMED:
                        status = STATUS_MALFORMED
                    else:
                        status = verify_entitlement(
                            document, trusted_keys=self._trusted_keys, tenant_id=self._tenant_id,
                            device_id=self._device_id,
                            now=datetime.fromtimestamp(self._clock(), tz=timezone.utc),
                            max_clock_skew_seconds=self._skew,
                        )
                if status != self._last_status:
                    log = logger.info if status == STATUS_OK else logger.warning
                    log("zone entitlement status: %s%s", status,
                        "" if status == STATUS_OK else " -- zone enforce runs as shadow")
                    self._last_status = status
                return status
        except Exception:  # noqa: BLE001 -- never let licensing crash the gate
            logger.exception("entitlement check failed; zone enforce runs as shadow")
            return STATUS_MALFORMED


__all__ = [
    "DEFAULT_MAX_CLOCK_SKEW_SECONDS", "ENTITLEMENT_SCHEMA", "EntitlementGate", "STATUSES",
    "STATUS_BAD_SIGNATURE", "STATUS_EXPIRED", "STATUS_MALFORMED", "STATUS_MISSING", "STATUS_NOT_YET_VALID",
    "STATUS_OK", "STATUS_PLAN", "STATUS_WRONG_DEVICE", "sign_entitlement", "verify_entitlement",
]
