"""The backend's side of the device entitlement (plans & metering design §6).

The backend signs, with its Ed25519 entitlement key, a short document saying whether a device's plan
includes ``ais`` zone enforce; the device pins the public key at enrollment and verifies the document
offline. The signer is `shield.entitlement.sign_entitlement` -- there is no second one.

Configuration (environment, read per request so a rotated key needs no restart):

``SHIELD_ENTITLEMENT_SIGNING_KEY``
    The Ed25519 private key as inline PEM (PKCS#8, as `integrity_sdk.did.Keypair.private_pem` writes
    it). Literal ``\\n`` sequences are accepted for platforms that store an env value on one line.
``SHIELD_ENTITLEMENT_SIGNING_KEY_FILE``
    Alternatively, a path to that PEM. Setting both is refused as ambiguous.
``SHIELD_ENTITLEMENT_PREVIOUS_KEYS``
    Optional, comma-separated base64 public keys still pinned in new enrollments during a rotation.
``SHIELD_ENTITLEMENT_GRACE_DAYS``
    Offline validity after the period ends (§9 ``entitlement_grace_days``), default 7, 1..90.

A missing or invalid key means **nothing is issued**: the route answers 503 "entitlement issuing not
configured" and devices stay in shadow. There is no generated or ephemeral fallback key, ever: a key
nobody pinned would sign entitlements nobody can verify, and a key regenerated per process would
silently invalidate every device on restart.

Who gets ``zone_enforce: true`` -- every one of these must hold, otherwise the document is still
issued (so a cancelled plan's file is *replaced* by a non-enforcing one) but with ``zone_enforce:
false`` and a short validity:

* the tenant's plan is configured and valid in the catalog (`shield.backend.plans`) and includes enforce;
* its status is ``active``, ``trialing`` or ``past_due`` (Stripe's dunning window; the period end plus
  grace bounds how long a ``past_due`` tenant keeps enforcing);
* it has a ``period_end`` and ``period_end + grace`` is still in the future;
* the device is not synthetic (``devices.synthetic = 1``): demo devices are never seats (§4.3) and
  never enforce.

An enforcing document is valid until ``period_end + grace``. Every other document is valid for
``grace`` from now (rolling): the device refreshes it well before then.
"""

from __future__ import annotations

import base64
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any, Mapping, Optional

from integrity_sdk.did import Keypair

from ..entitlement import sign_entitlement
from .plans import ShieldPlan, load_plan_catalog
from .plans_store import STATUS_ACTIVE, STATUS_PAST_DUE, STATUS_TRIALING

logger = logging.getLogger(__name__)

KEY_ENV = "SHIELD_ENTITLEMENT_SIGNING_KEY"
KEY_FILE_ENV = "SHIELD_ENTITLEMENT_SIGNING_KEY_FILE"
PREVIOUS_KEYS_ENV = "SHIELD_ENTITLEMENT_PREVIOUS_KEYS"
GRACE_DAYS_ENV = "SHIELD_ENTITLEMENT_GRACE_DAYS"
DEFAULT_GRACE_DAYS = 7
MAX_GRACE_DAYS = 90

ENFORCING_STATUSES = frozenset({STATUS_ACTIVE, STATUS_TRIALING, STATUS_PAST_DUE})
NOT_CONFIGURED = "entitlement issuing not configured"

# Why a document does or does not enforce; returned next to it so an operator can tell.
REASON_ENFORCE = "enforce"
REASON_PLAN = "plan_excludes_enforce"
REASON_PLAN_NOT_CONFIGURED = "plan_not_configured"
REASON_STATUS = "subscription_status"
REASON_NO_PERIOD = "no_period_end"
REASON_LAPSED = "period_lapsed"
REASON_SYNTHETIC = "synthetic_device"

_DIGITS = re.compile(r"[0-9]+")


@dataclass(frozen=True)
class IssuerConfig:
    keypair: Keypair
    public_key: str                 # base64 raw Ed25519, the format `verify_entitlement` compares
    trusted_keys: tuple[str, ...]   # current key first, then previous keys still pinned
    grace: timedelta


def public_key_b64(keypair: Keypair) -> str:
    return base64.b64encode(keypair.public_bytes()).decode("ascii")


def _valid_public_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def load_issuer_config(environ: Optional[Mapping[str, str]] = None) -> tuple[Optional[IssuerConfig], str]:
    """(the config, "") or (None, why issuing is off). Never raises, never generates a key."""
    env = os.environ if environ is None else environ
    inline, key_file = env.get(KEY_ENV, "").strip(), env.get(KEY_FILE_ENV, "").strip()
    if inline and key_file:
        return None, f"both {KEY_ENV} and {KEY_FILE_ENV} are set; set exactly one"
    if not inline and not key_file:
        return None, f"{KEY_ENV} is not set"
    try:
        if inline:
            pem = inline.replace("\\n", "\n").encode("ascii")
        else:
            pem = Path(key_file).read_bytes()
        keypair = Keypair.from_pem(pem)
    except Exception as exc:  # noqa: BLE001 -- any parse failure is "not configured", never a crash
        return None, f"the entitlement signing key could not be loaded ({type(exc).__name__})"

    raw_grace = env.get(GRACE_DAYS_ENV, "").strip()
    if raw_grace:
        if not _DIGITS.fullmatch(raw_grace) or not 1 <= int(raw_grace) <= MAX_GRACE_DAYS:
            return None, f"{GRACE_DAYS_ENV} must be an integer from 1 to {MAX_GRACE_DAYS}"
        grace_days = int(raw_grace)
    else:
        grace_days = DEFAULT_GRACE_DAYS

    current = public_key_b64(keypair)
    previous = [key.strip() for key in env.get(PREVIOUS_KEYS_ENV, "").split(",") if key.strip()]
    bad = [key for key in previous if not _valid_public_key(key)]
    if bad:
        return None, f"{PREVIOUS_KEYS_ENV} holds {len(bad)} value(s) that are not base64 Ed25519 public keys"
    trusted = tuple(dict.fromkeys([current, *previous]))
    return IssuerConfig(keypair=keypair, public_key=current, trusted_keys=trusted,
                        grace=timedelta(days=grace_days)), ""


def enrollment_gate_zone(environ: Optional[Mapping[str, str]] = None) -> Optional[dict[str, Any]]:
    """The `gate_zone` fragment an enrollment's device config carries so the device pins the
    entitlement keys; None when issuing is not configured (the config is then unchanged).

    Nested under `gate_zone` because that is where `GateZoneSettings` reads `entitlement_keys`, and
    `load_device_config` refuses unknown top-level fields."""
    config, _reason = load_issuer_config(environ)
    if config is None:
        return None
    return {"entitlement_keys": list(config.trusted_keys)}


def _parse_period_end(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def decide(
    *,
    plan_row: Mapping[str, Any],
    catalog: Mapping[str, ShieldPlan],
    synthetic: bool,
    grace: timedelta,
    now: datetime,
) -> tuple[bool, datetime, str]:
    """(zone_enforce, not_after, reason) for one device. Pure: the policy above, nothing else."""
    rolling = now + grace
    plan = catalog.get(str(plan_row.get("plan_id")))
    if plan is None:
        return False, rolling, REASON_PLAN_NOT_CONFIGURED
    if not plan.zone_enforce:
        return False, rolling, REASON_PLAN
    if synthetic:
        return False, rolling, REASON_SYNTHETIC
    if plan_row.get("status") not in ENFORCING_STATUSES:
        return False, rolling, REASON_STATUS
    period_end = _parse_period_end(plan_row.get("period_end"))
    if period_end is None:
        return False, rolling, REASON_NO_PERIOD
    not_after = period_end + grace
    if not_after <= now:
        return False, rolling, REASON_LAPSED
    return True, not_after, REASON_ENFORCE


def issue_entitlement(
    *,
    config: IssuerConfig,
    tenant_id: str,
    device_id: str,
    plan_row: Mapping[str, Any],
    catalog: Mapping[str, ShieldPlan],
    synthetic: bool,
    now: Optional[datetime] = None,
) -> tuple[dict[str, Any], str]:
    """(the signed document, the reason it does or does not enforce)."""
    now = now or datetime.now(timezone.utc)
    zone_enforce, not_after, reason = decide(plan_row=plan_row, catalog=catalog, synthetic=synthetic,
                                             grace=config.grace, now=now)
    document = sign_entitlement(
        tenant_id=tenant_id, device_id=device_id, plan=str(plan_row.get("plan_id")),
        zone_enforce=zone_enforce, issued_at=now, not_after=not_after, keypair=config.keypair,
    )
    return document, reason


def handle_entitlement_request(handler: Any, store: Any, query: Mapping[str, list[str]]) -> None:
    """`GET /api/shield/entitlement?tenant_id=&device_id=`, behind the device credential."""
    tenant_id = query.get("tenant_id", [""])[0]
    device_id = query.get("device_id", [""])[0]
    if not handler._require_device_token(tenant_id=tenant_id, device_id=device_id):
        return
    config, reason = load_issuer_config()
    if config is None:
        logger.warning("entitlement not issued for %s/%s: %s", tenant_id, device_id, reason)
        handler._send_error(HTTPStatus.SERVICE_UNAVAILABLE, NOT_CONFIGURED)
        return
    synthetic = store.plans.device_is_synthetic(tenant_id=tenant_id, device_id=device_id)
    if synthetic is None:
        handler._send_error(HTTPStatus.NOT_FOUND, "device not found")
        return
    document, why = issue_entitlement(
        config=config, tenant_id=tenant_id, device_id=device_id,
        plan_row=store.plans.get_tenant_plan(tenant_id), catalog=load_plan_catalog(), synthetic=synthetic,
    )
    handler._send_json({"entitlement": document, "zone_enforce_reason": why})


__all__ = [
    "DEFAULT_GRACE_DAYS", "ENFORCING_STATUSES", "GRACE_DAYS_ENV", "IssuerConfig", "KEY_ENV", "KEY_FILE_ENV",
    "NOT_CONFIGURED", "PREVIOUS_KEYS_ENV", "decide", "enrollment_gate_zone", "handle_entitlement_request",
    "issue_entitlement", "load_issuer_config", "public_key_b64",
]
