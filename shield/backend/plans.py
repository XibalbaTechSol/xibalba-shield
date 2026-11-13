"""The Shield plan catalog: what each plan costs and allows (plans & metering design §4.3, §9).

Prices and allowances are **operator parameters** that are not decided yet, so nothing here hard-codes
a paid price. The catalog is read from the environment:

* ``SHIELD_PLAN_CATALOG_JSON`` -- a JSON object keyed by plan id, each value an object with any of the
  fields below. When set, it is the only source (the per-field variables are ignored).
* otherwise ``SHIELD_PLAN_<ID>_<FIELD>`` per field, e.g. ``SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS=1500``.

Fields: ``name``, ``per_device_monthly_cents``, ``included_decisions_per_device``,
``overage_cents_per_1k``, ``max_devices``, ``zone_enforce``.

Rules (each one fails closed: a plan that breaks one is **not loaded**, and the reason is logged):

* integers are non-negative, written as plain ASCII digits (env) or JSON integers -- never a bool, a
  float, ``"1_000"`` or ``" 5"``; booleans are ``true``/``false``.
* ``free`` always exists, defaults to the §9 suggestions (2 devices, 5,000 decisions, no enforce), and
  may never price itself, bill overage, or include zone enforce (D3: enforce is the paid feature).
* a paid plan (``pro``, ``team``) is **configured** only once its price, allowance and overage are all
  set. Until then it is absent from the catalog: not purchasable, and never issued as enforcing.

Billing is never in the decision path (§1): this module is read by the backend only.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional

logger = logging.getLogger(__name__)

FREE = "free"
PAID_PLAN_IDS = ("pro", "team")
PLAN_IDS = (FREE, *PAID_PLAN_IDS)

CATALOG_ENV = "SHIELD_PLAN_CATALOG_JSON"

_INT_FIELDS = ("per_device_monthly_cents", "included_decisions_per_device")
_OPTIONAL_INT_FIELDS = ("overage_cents_per_1k", "max_devices")
_FIELDS = ("name", *_INT_FIELDS, *_OPTIONAL_INT_FIELDS, "zone_enforce")
_DIGITS = re.compile(r"[0-9]+")

#: §9 suggestions for the free tier. Not decisions: the operator may override each one.
FREE_DEFAULTS: Mapping[str, Any] = {
    "name": "Free",
    "per_device_monthly_cents": 0,
    "included_decisions_per_device": 5000,
    "overage_cents_per_1k": None,
    "max_devices": 2,
    "zone_enforce": False,
}
_PAID_NAMES = {"pro": "Pro", "team": "Team"}


class PlanConfigError(ValueError):
    """A plan's configuration is invalid; the plan is not loaded."""


@dataclass(frozen=True)
class ShieldPlan:
    id: str                               # "free" | "pro" | "team"
    name: str
    per_device_monthly_cents: int         # 0 on free
    included_decisions_per_device: int    # per billing period
    overage_cents_per_1k: int | None      # None on free: no overage billing
    max_devices: int | None               # cap on enrolled, non-synthetic devices
    zone_enforce: bool                    # D3: False on free

    def __post_init__(self) -> None:
        if self.id not in PLAN_IDS:
            raise PlanConfigError(f"unknown plan id {self.id!r}; known: {PLAN_IDS}")
        if not isinstance(self.name, str) or not self.name.strip():
            raise PlanConfigError(f"{self.id}: name must be a non-empty string")
        for name in _INT_FIELDS:
            _check_int(self.id, name, getattr(self, name))
        for name in _OPTIONAL_INT_FIELDS:
            value = getattr(self, name)
            if value is not None:
                _check_int(self.id, name, value)
        if not isinstance(self.zone_enforce, bool):
            raise PlanConfigError(f"{self.id}: zone_enforce must be a boolean")
        if self.max_devices is not None and self.max_devices < 1:
            raise PlanConfigError(f"{self.id}: max_devices must be at least 1, or unset for no cap")
        if self.id == FREE:
            if self.per_device_monthly_cents != 0:
                raise PlanConfigError("free: per_device_monthly_cents must be 0")
            if self.overage_cents_per_1k is not None:
                raise PlanConfigError("free: overage_cents_per_1k must be unset (free has no overage billing)")
            if self.zone_enforce:
                raise PlanConfigError("free: zone_enforce must be false (enforce is a paid feature, D3)")
        else:
            if self.per_device_monthly_cents <= 0:
                raise PlanConfigError(f"{self.id}: per_device_monthly_cents must be positive on a paid plan")
            if self.overage_cents_per_1k is None:
                raise PlanConfigError(f"{self.id}: overage_cents_per_1k must be set on a paid plan")

    @property
    def paid(self) -> bool:
        return self.id != FREE


def _check_int(plan_id: str, name: str, value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlanConfigError(f"{plan_id}: {name} must be an integer, got {type(value).__name__}")
    if value < 0:
        raise PlanConfigError(f"{plan_id}: {name} must be non-negative")


def _parse_env_value(plan_id: str, name: str, raw: str) -> Any:
    if name == "name":
        return raw
    if name == "zone_enforce":
        if raw not in ("true", "false"):
            raise PlanConfigError(f"{plan_id}: zone_enforce must be 'true' or 'false', got {raw!r}")
        return raw == "true"
    if name in _OPTIONAL_INT_FIELDS and raw == "":
        return None
    if not _DIGITS.fullmatch(raw):
        raise PlanConfigError(f"{plan_id}: {name} must be a non-negative integer, got {raw!r}")
    return int(raw)


def _fields_from_env(plan_id: str, environ: Mapping[str, str]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for name in _FIELDS:
        key = f"SHIELD_PLAN_{plan_id.upper()}_{name.upper()}"
        if key in environ:
            fields[name] = _parse_env_value(plan_id, name, environ[key])
    return fields


def _fields_from_json(plan_id: str, document: Mapping[str, Any]) -> dict[str, Any]:
    raw = document.get(plan_id, {})
    if not isinstance(raw, Mapping):
        raise PlanConfigError(f"{plan_id}: catalog entry must be an object")
    unknown = set(raw) - set(_FIELDS)
    if unknown:
        raise PlanConfigError(f"{plan_id}: unknown field(s) {sorted(unknown)}")
    return dict(raw)


def _build(plan_id: str, fields: Mapping[str, Any]) -> Optional[ShieldPlan]:
    """The plan, or None when a paid plan is simply not configured yet. Raises on invalid config."""
    if plan_id == FREE:
        merged = {**FREE_DEFAULTS, **fields}
    else:
        if not fields:
            return None
        required = ("per_device_monthly_cents", "included_decisions_per_device", "overage_cents_per_1k")
        missing = [name for name in required if fields.get(name) is None]
        if missing:
            raise PlanConfigError(f"{plan_id}: partially configured, missing {missing}")
        merged = {"name": _PAID_NAMES[plan_id], "max_devices": None, "zone_enforce": True, **fields}
    return ShieldPlan(id=plan_id, **merged)


def load_plan_catalog(environ: Optional[Mapping[str, str]] = None) -> dict[str, ShieldPlan]:
    """The plans that are configured and valid, keyed by id. Never raises.

    An invalid plan is left out and logged; an invalid catalog JSON leaves out every plan -- the issuer
    then treats every tenant as not entitled to enforce. Neither is a reason to stop the backend.
    """
    env = os.environ if environ is None else environ
    document: Optional[Mapping[str, Any]] = None
    if env.get(CATALOG_ENV):
        try:
            parsed = json.loads(env[CATALOG_ENV])
            if not isinstance(parsed, dict):
                raise PlanConfigError(f"{CATALOG_ENV} must be a JSON object keyed by plan id")
            unknown = set(parsed) - set(PLAN_IDS)
            if unknown:
                raise PlanConfigError(f"{CATALOG_ENV} has unknown plan id(s) {sorted(unknown)}")
            document = parsed
        except (ValueError, PlanConfigError) as exc:
            logger.error("plan catalog not loaded: %s", exc)
            return {}
    catalog: dict[str, ShieldPlan] = {}
    for plan_id in PLAN_IDS:
        try:
            fields = _fields_from_json(plan_id, document) if document is not None else _fields_from_env(plan_id, env)
            plan = _build(plan_id, fields)
        except (PlanConfigError, TypeError) as exc:
            logger.error("plan %r not loaded (fails closed): %s", plan_id, exc)
            continue
        if plan is not None:
            catalog[plan_id] = plan
    return catalog


__all__ = ["CATALOG_ENV", "FREE", "FREE_DEFAULTS", "PAID_PLAN_IDS", "PLAN_IDS", "PlanConfigError", "ShieldPlan",
           "load_plan_catalog"]
