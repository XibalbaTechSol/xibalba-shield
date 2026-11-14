"""Stripe billing for Shield: checkout, portal, webhook and seat sync (plans & metering design §4–§5, phase 3c).

Billing is never in a gate's decision path (§1). Nothing here is consulted to allow or deny an action. The
only thing billing changes on a device is the signed entitlement, which the issuer derives from
`tenant_plans`, and the webhook below is the only writer of that table.

Each paid plan is one subscription with two prices (§5):

* devices: a licensed, per-unit, monthly USD price whose `unit_amount` equals the plan's
  `per_device_monthly_cents`; quantity = the tenant's enrolled non-synthetic devices;
* overage: a metered price backed by the configured Billing Meter, whose `unit_amount` equals the plan's
  `overage_cents_per_1k` (one meter unit = 1,000 gated decisions beyond the allowance). Phase 3d
  sends the meter events.

Fail closed, as Cortex does: without a real Stripe key and webhook secret, configured price ids, a meter
id, or with a Stripe price that does not match the catalog, checkout answers "billing unavailable" and no
plan changes. Configuration (environment, read per request):

``SHIELD_STRIPE_SECRET_KEY`` / ``SHIELD_STRIPE_WEBHOOK_SECRET`` / ``SHIELD_STRIPE_LIVE`` (``1`` for live)
``SHIELD_STRIPE_METER_ID`` (``mtr_…``)
``SHIELD_STRIPE_PRICE_<PLAN>_DEVICE`` / ``SHIELD_STRIPE_PRICE_<PLAN>_OVERAGE`` for ``PRO`` and ``TEAM``
``SHIELD_STRIPE_TRIAL_DAYS`` (default 14, ``0`` disables, at most 30)
``SHIELD_STRIPE_PORTAL_CONFIGURATION`` (optional ``bpc_…``: the portal configuration to open; it must cancel at
period end and not offer plan switching, see §5. Unset uses the account default.)

Trial (operator decision 2026-11-13): a tenant's first paid checkout includes a 14-day trial with the
card collected up front; Stripe charges it when the trial ends. `trialing` enforces like `active`. One
trial per tenant: the first subscription seen with a trial stamps `billing_customers.trial_used_at`.

Shield tenants get their own Stripe customers (metadata ``product=shield``) until identity is unified
with Cortex (§4.2).
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any, Callable, Mapping, Optional

from integrity_sdk.billing import BillingUnavailable, StripeConfig, StripeGateway, ensure_stripe_events_table, record_once

from .plans import FREE, PAID_PLAN_IDS, ShieldPlan, load_plan_catalog
from .plans_store import (
    STATUS_ACTIVE, STATUS_CANCELED, STATUS_INCOMPLETE, STATUS_PAST_DUE, STATUS_TRIALING, STATUS_UNPAID,
)

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS billing_customers (
    tenant_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL UNIQUE,
    subscription_id TEXT,
    plan_id TEXT,
    device_item_id TEXT,
    overage_item_id TEXT,
    seat_quantity INTEGER,
    trial_used_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkout_requests (
    tenant_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    attempt TEXT NOT NULL,
    checkout_id TEXT,
    url TEXT
);
CREATE TABLE IF NOT EXISTS seat_syncs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    requested_at TEXT NOT NULL,
    acknowledged_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_seat_syncs_tenant ON seat_syncs(tenant_id, requested_at);
-- One overage submission per closed period (design §5, phase 3d). Written before the Stripe call and
-- acknowledged after it: this ledger, not Stripe's ~24h identifier window, is the dedupe authority.
-- Periods are ISO-8601 UTC, the same format as `usage_reports.received_at`, so windows compare as text.
CREATE TABLE IF NOT EXISTS meter_submissions (
    tenant_id TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    seats INTEGER NOT NULL,
    billable INTEGER NOT NULL,
    included INTEGER NOT NULL,
    value INTEGER NOT NULL,
    identifier TEXT NOT NULL UNIQUE,
    invoice_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    sent_at TEXT,
    acknowledged_at TEXT,
    PRIMARY KEY (tenant_id, period_start)
);
"""

HANDLED_EVENTS = frozenset({
    "checkout.session.completed", "customer.subscription.created", "customer.subscription.updated",
    "customer.subscription.deleted", "invoice.created",
})
# Overage is metered in single gated decisions and priced per 1,000 through `transform_quantity`, rounded
# down once per invoice: at most 999 decisions a period go unbilled, never a fraction over-billed.
OVERAGE_TRANSFORM = {"divide_by": 1000, "round": "down"}
# A pending submission older than this is outside Stripe's identifier dedupe window: resending it blind
# could bill twice, so it is reconciled against Stripe's own meter totals first.
DEDUPE_WINDOW_SECONDS = 23 * 3600
# Stripe subscription status -> `tenant_plans.status`. Anything that ends the subscription returns the
# tenant to free; `paused` keeps the plan but never enforces.
_STATUS_MAP = {
    "active": STATUS_ACTIVE, "trialing": STATUS_TRIALING, "past_due": STATUS_PAST_DUE,
    "unpaid": STATUS_UNPAID, "incomplete": STATUS_INCOMPLETE, "paused": STATUS_UNPAID,
}
_ENDED = frozenset({"canceled", "incomplete_expired"})
MAX_WEBHOOK_BYTES = 1 << 20
DEFAULT_TRIAL_DAYS = 14
MAX_TRIAL_DAYS = 30


def _trial_days(raw: Optional[str]) -> int:
    """Malformed or out-of-range values fall back to the default rather than silently granting more."""
    if raw is None or not raw.strip():
        return DEFAULT_TRIAL_DAYS
    try:
        value = int(raw.strip())
    except ValueError:
        return DEFAULT_TRIAL_DAYS
    return value if 0 <= value <= MAX_TRIAL_DAYS else DEFAULT_TRIAL_DAYS


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class BillingRefused(ValueError):
    """A request billing will not carry out; `status` is the HTTP status. The message is safe to show."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class PlanPrices:
    device: str
    overage: str


@dataclass(frozen=True)
class BillingConfig:
    stripe: StripeConfig = field(default_factory=StripeConfig)
    meter_id: str = ""
    prices: Mapping[str, PlanPrices] = field(default_factory=dict)
    trial_days: int = DEFAULT_TRIAL_DAYS
    portal_configuration: str = ""

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "BillingConfig":
        env = os.environ if environ is None else environ
        prices = {}
        for plan_id in PAID_PLAN_IDS:
            device = env.get(f"SHIELD_STRIPE_PRICE_{plan_id.upper()}_DEVICE", "").strip()
            overage = env.get(f"SHIELD_STRIPE_PRICE_{plan_id.upper()}_OVERAGE", "").strip()
            if device.startswith("price_") and overage.startswith("price_"):
                prices[plan_id] = PlanPrices(device=device, overage=overage)
        portal = env.get("SHIELD_STRIPE_PORTAL_CONFIGURATION", "").strip()
        return cls(
            stripe=StripeConfig(
                secret_key=env.get("SHIELD_STRIPE_SECRET_KEY", "").strip(),
                webhook_secret=env.get("SHIELD_STRIPE_WEBHOOK_SECRET", "").strip(),
                live=env.get("SHIELD_STRIPE_LIVE", "").strip() == "1",
            ),
            meter_id=env.get("SHIELD_STRIPE_METER_ID", "").strip(),
            prices=prices,
            trial_days=_trial_days(env.get("SHIELD_STRIPE_TRIAL_DAYS")),
            portal_configuration=portal if portal.startswith("bpc_") else "",
        )

    @property
    def ready(self) -> bool:
        return self.stripe.billing_ready and self.meter_id.startswith("mtr_") and bool(self.prices)


def _recurring(price: Mapping[str, Any]) -> Mapping[str, Any]:
    value = price.get("recurring")
    return value if isinstance(value, Mapping) else {}


def validate_device_price(price: Mapping[str, Any], *, price_id: str, plan: ShieldPlan) -> None:
    recurring = _recurring(price)
    if (price.get("id") != price_id or price.get("active") is False or price.get("currency") != "usd"
            or price.get("billing_scheme", "per_unit") != "per_unit"
            or price.get("unit_amount") != plan.per_device_monthly_cents
            or recurring.get("usage_type") != "licensed" or recurring.get("interval") != "month"
            or recurring.get("interval_count") != 1):
        raise BillingUnavailable("Stripe device price does not match the approved Shield catalog")


def validate_overage_price(price: Mapping[str, Any], *, price_id: str, plan: ShieldPlan, meter_id: str) -> None:
    recurring = _recurring(price)
    if (price.get("id") != price_id or price.get("active") is False or price.get("currency") != "usd"
            or price.get("billing_scheme", "per_unit") != "per_unit"
            or price.get("unit_amount") != plan.overage_cents_per_1k
            or dict(price.get("transform_quantity") or {}) != OVERAGE_TRANSFORM
            or recurring.get("usage_type") != "metered" or recurring.get("meter") != meter_id
            or recurring.get("interval") != "month" or recurring.get("interval_count") != 1):
        raise BillingUnavailable("Stripe overage price does not match the approved Shield catalog")


def validate_meter(meter: Mapping[str, Any], *, meter_id: str) -> str:
    """The meter's event name, after checking it sums the payload keys `send_meter_event` writes."""
    aggregation = meter.get("default_aggregation") or {}
    mapping = meter.get("customer_mapping") or {}
    values = meter.get("value_settings") or {}
    name = meter.get("event_name")
    if (meter.get("id") != meter_id or meter.get("status") != "active" or aggregation.get("formula") != "sum"
            or mapping.get("event_payload_key") != "stripe_customer_id"
            or values.get("event_payload_key", "value") != "value" or not isinstance(name, str) or not name):
        raise BillingUnavailable("Stripe meter does not match the approved Shield configuration")
    return name


def _iso(epoch: Any) -> str:
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        raise BillingRefused(HTTPStatus.BAD_REQUEST, "Subscription period is missing")
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(iso: str) -> float:
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def _is_epoch(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def overage_for_period(*, seats: int, billable: int, included_per_device: int, in_trial: bool) -> tuple[int, int]:
    """(included decisions, overage decisions) for a period. The period close bills the second number and
    the usage page shows it accruing, so both call this one function."""
    included = seats * included_per_device
    return included, 0 if in_trial else max(0, billable - included)


def _month_bounds(now: datetime) -> tuple[str, str]:
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = start.replace(year=start.year + 1, month=1) if start.month == 12 else start.replace(month=start.month + 1)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


class ShieldBilling:
    """Checkout, portal, webhook and seat sync over the ShieldStore connection."""

    def __init__(
        self,
        conn: Any,
        plans: Any,
        *,
        config: Optional[Callable[[], BillingConfig]] = None,
        gateway: Optional[Callable[[BillingConfig], Any]] = None,
        catalog: Optional[Callable[[], Mapping[str, ShieldPlan]]] = None,
        durable: Optional[Callable[[], bool]] = None,
    ) -> None:
        self._conn = conn
        self._plans = plans
        self._config = config or BillingConfig.from_env
        self._gateway = gateway or (lambda cfg: StripeGateway(cfg.stripe))
        self._catalog = catalog or load_plan_catalog
        # On Render the database is a periodic Supabase snapshot: a plan written by a webhook could be
        # lost on restart after Stripe already got its 2xx. `durable()` forces a checkpoint; when it
        # fails the webhook answers 503 so Stripe redelivers (the local replay is then a duplicate).
        self._durable = durable or (lambda: True)

    def init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        ensure_stripe_events_table(self._conn)
        self._conn.commit()

    # -- helpers ------------------------------------------------------------------------------

    def _ready(self) -> tuple[BillingConfig, Any]:
        cfg = self._config()
        if not cfg.ready:
            raise BillingUnavailable("Stripe billing is not configured")
        return cfg, self._gateway(cfg)

    def customer(self, tenant_id: str) -> Optional[dict[str, Any]]:
        row = self._conn.execute("SELECT * FROM billing_customers WHERE tenant_id=?", (tenant_id,)).fetchone()
        return dict(row) if row else None

    def seat_count(self, tenant_id: str) -> int:
        """Enrolled, non-synthetic devices: synthetic/demo devices are never seats (§4.3)."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM devices WHERE tenant_id=? AND synthetic=0", (tenant_id,)).fetchone()
        return int(row[0])

    def _validated_plan(self, plan_id: str, cfg: BillingConfig, gw: Any) -> tuple[ShieldPlan, PlanPrices]:
        plan = self._catalog().get(plan_id)
        prices = cfg.prices.get(plan_id)
        if plan is None or not plan.paid or prices is None:
            raise BillingUnavailable("This plan is not available for purchase yet")
        validate_device_price(gw.request("GET", "/prices/" + prices.device), price_id=prices.device, plan=plan)
        validate_overage_price(gw.request("GET", "/prices/" + prices.overage), price_id=prices.overage, plan=plan,
                               meter_id=cfg.meter_id)
        validate_meter(gw.request("GET", "/billing/meters/" + cfg.meter_id), meter_id=cfg.meter_id)
        return plan, prices

    # -- checkout and portal ------------------------------------------------------------------

    def checkout(self, *, tenant_id: str, plan_id: str, base_url: str) -> dict[str, Any]:
        if plan_id not in PAID_PLAN_IDS:
            raise BillingRefused(HTTPStatus.BAD_REQUEST, "Choose a paid plan: " + " or ".join(PAID_PLAN_IDS))
        cfg, gw = self._ready()
        plan, prices = self._validated_plan(plan_id, cfg, gw)
        current = self._plans.get_tenant_plan(tenant_id)
        if current["plan_id"] != FREE and current["status"] != STATUS_CANCELED:
            raise BillingRefused(HTTPStatus.CONFLICT, "Manage the existing subscription through the billing portal")
        seats = self.seat_count(tenant_id)
        if seats == 0:
            # Billing a floor of one seat would be prorated straight back to zero by the first sync.
            raise BillingRefused(HTTPStatus.CONFLICT, "Enroll a device before choosing a paid plan")
        if plan.max_devices is not None and seats > plan.max_devices:
            raise BillingRefused(HTTPStatus.CONFLICT, f"The {plan.name} plan covers at most {plan.max_devices} devices")

        record = self.customer(tenant_id)
        if record is None:
            created = gw.request("POST", "/customers", data={
                "metadata[tenant_id]": tenant_id, "metadata[product]": "shield",
            }, idempotency_key="shield-customer:" + tenant_id)
            customer_id = created.get("id")
            if not isinstance(customer_id, str) or not customer_id.startswith("cus_"):
                raise BillingUnavailable("Stripe returned an invalid customer")
            with self._conn:
                self._conn.execute(
                    "INSERT OR IGNORE INTO billing_customers (tenant_id, customer_id, updated_at) VALUES (?,?,?)",
                    (tenant_id, customer_id, _now()))
            record = self.customer(tenant_id)

        # Persist the attempt before talking to Stripe: a crash after Stripe creates the session reuses
        # the same idempotency key on retry instead of creating a second subscription.
        pending = self._conn.execute("SELECT * FROM checkout_requests WHERE tenant_id=?", (tenant_id,)).fetchone()
        if pending and pending["checkout_id"]:
            session = gw.request("GET", "/checkout/sessions/" + pending["checkout_id"])
            if session.get("status") == "open":
                if pending["plan_id"] != plan_id:
                    raise BillingRefused(HTTPStatus.CONFLICT, "Finish or let the open checkout expire before choosing another plan")
                return {"url": session.get("url")}
            if session.get("status") == "complete":
                raise BillingRefused(HTTPStatus.CONFLICT, "Payment is processing; wait for the subscription to confirm")
            with self._conn:
                self._conn.execute("DELETE FROM checkout_requests WHERE tenant_id=?", (tenant_id,))
            pending = None
        if pending is None or pending["plan_id"] != plan_id:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO checkout_requests (tenant_id, plan_id, attempt) VALUES (?,?,?) "
                    "ON CONFLICT(tenant_id) DO UPDATE SET plan_id=excluded.plan_id, attempt=excluded.attempt, "
                    "checkout_id=NULL, url=NULL",
                    (tenant_id, plan_id, uuid.uuid4().hex))
            pending = self._conn.execute("SELECT * FROM checkout_requests WHERE tenant_id=?", (tenant_id,)).fetchone()

        base = base_url.rstrip("/")
        params: dict[str, Any] = {
            "mode": "subscription",
            "customer": record["customer_id"],
            "client_reference_id": tenant_id,
            "line_items[0][price]": prices.device,
            "line_items[0][quantity]": seats,
            # A metered price takes no quantity: Stripe bills what the meter reports.
            "line_items[1][price]": prices.overage,
            # Card on file even during a trial, so the subscription continues without a second step.
            "payment_method_collection": "always",
            "subscription_data[metadata][tenant_id]": tenant_id,
            "subscription_data[metadata][product]": "shield",
            "success_url": base + "/billing?checkout=success",
            "cancel_url": base + "/billing?checkout=canceled",
        }
        if cfg.trial_days > 0 and not record["trial_used_at"]:
            params["subscription_data[trial_period_days]"] = cfg.trial_days
        session = gw.request("POST", "/checkout/sessions", data=params,
                             idempotency_key="shield-checkout:" + pending["attempt"])
        if not isinstance(session.get("id"), str) or not isinstance(session.get("url"), str):
            raise BillingUnavailable("Stripe returned an invalid checkout session")
        with self._conn:
            self._conn.execute("UPDATE checkout_requests SET checkout_id=?, url=? WHERE tenant_id=?",
                               (session["id"], session["url"], tenant_id))
        return {"url": session["url"]}

    def portal(self, *, tenant_id: str, base_url: str) -> dict[str, Any]:
        cfg, gw = self._ready()
        record = self.customer(tenant_id)
        if record is None:
            raise BillingRefused(HTTPStatus.CONFLICT, "This tenant has no Stripe billing account yet")
        data = {"customer": record["customer_id"], "return_url": base_url.rstrip("/") + "/billing"}
        if cfg.portal_configuration:
            data["configuration"] = cfg.portal_configuration
        result = gw.request("POST", "/billing_portal/sessions", data=data)
        if not isinstance(result.get("url"), str):
            raise BillingUnavailable("Stripe returned an invalid portal session")
        return {"url": result["url"]}

    def status(self, tenant_id: str) -> dict[str, Any]:
        record = self.customer(tenant_id) or {}
        catalog = {
            plan_id: {
                "id": plan.id,
                "name": plan.name,
                "per_device_monthly_cents": plan.per_device_monthly_cents,
                "included_decisions_per_device": plan.included_decisions_per_device,
                "overage_cents_per_1k": plan.overage_cents_per_1k,
                "max_devices": plan.max_devices,
                "zone_enforce": plan.zone_enforce,
            }
            for plan_id, plan in load_plan_catalog().items()
        }
        return {
            "tenant_id": tenant_id,
            "billing_configured": self._config().ready,
            "plan": self._plans.get_tenant_plan(tenant_id),
            "plans": catalog,
            "has_billing_account": bool(record),
            "trial_available": self._config().trial_days > 0 and not record.get("trial_used_at"),
            "seats": self.seat_count(tenant_id),
            "billed_seats": record.get("seat_quantity"),
        }

    def usage(self, tenant_id: str, *, now: Optional[datetime] = None) -> dict[str, Any]:
        """Usage in the tenant's current billing period, counted exactly as the period close will count it.

        A paid tenant's period is the subscription's own (anniversary-aligned, from the webhook), never a
        calendar month: a calendar month would not match the invoice. A paid tenant whose period is not yet
        known gets ``period: None`` rather than a guess. Free tenants have no invoice and use the UTC
        calendar month. ``overage_decisions`` is what the close would send if the period ended now; seats
        only grow during a period (see :meth:`period_seats`), so it can only fall as devices are added.
        """
        plan_row = self._plans.get_tenant_plan(tenant_id)
        plan = self._catalog().get(plan_row["plan_id"])
        as_of = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        result: dict[str, Any] = {"tenant_id": tenant_id, "plan_id": plan_row["plan_id"],
                                  "status": plan_row["status"], "as_of": as_of.strftime("%Y-%m-%dT%H:%M:%SZ")}
        if plan is None:
            return {**result, "period": None, "reason": "plan is not in the catalog"}
        record = self.customer(tenant_id) or {}
        if plan.paid:
            start, end = plan_row.get("period_start"), plan_row.get("period_end")
            if not start or not end:
                return {**result, "period": None, "reason": "billing period not yet known"}
            basis = "subscription"
            fallback = record.get("seat_quantity")
            seats = (self.period_seats(record["subscription_id"], start, end,
                                       fallback=fallback if fallback is not None else self.seat_count(tenant_id))
                     if record.get("subscription_id") else self.seat_count(tenant_id))
            trial_end = plan_row.get("trial_end")
            in_trial = bool(trial_end) and end <= trial_end
        else:
            start, end = _month_bounds(as_of)
            basis, seats, in_trial = "calendar_month", None, False
        devices = self.period_counts(tenant_id, start, end)
        if seats is None:
            seats = self.free_seats(tenant_id, start, end)
        totals = {name: sum(d[name] for d in devices) for name in ("billable", "excluded_mask", "excluded_fault")}
        included, overage = overage_for_period(seats=seats, billable=totals["billable"],
                                               included_per_device=plan.included_decisions_per_device,
                                               in_trial=in_trial)
        # Stripe's overage price divides by 1,000 and rounds down (transform_quantity), so whole units only.
        cents = (overage // 1000) * plan.overage_cents_per_1k if plan.paid and plan.overage_cents_per_1k else 0
        return {**result, "period": {"start": start, "end": end, "basis": basis}, "in_trial": in_trial,
                "seats": seats, "included_per_device": plan.included_decisions_per_device, "included": included,
                "totals": totals, "remaining": max(0, included - totals["billable"]),
                "overage_decisions": overage, "overage_accrued_cents": cents,
                "overage_cents_per_1k": plan.overage_cents_per_1k, "devices": devices}

    # -- webhook ------------------------------------------------------------------------------

    def handle_webhook(self, body: bytes, signature: str) -> dict[str, Any]:
        cfg, gw = self._ready()
        event = gw.verify_event(body, signature)
        result = self.apply_event(event, cfg=cfg, gw=gw)
        # A duplicate may be the redelivery of a change whose checkpoint failed: acknowledging it before
        # the state is durable would let Stripe stop retrying while a restart could still lose the change.
        if (result.get("plan_id") or result.get("duplicate") or result.get("closed")) and not self._durable():
            raise BillingUnavailable("Billing change is not yet durable; Stripe will redeliver")
        return result

    def apply_event(self, event: Mapping[str, Any], *, cfg: BillingConfig, gw: Any) -> dict[str, Any]:
        if event.get("type") not in HANDLED_EVENTS:
            return {"received": True, "ignored": True}
        event_id = event.get("id")
        if self._conn.execute("SELECT 1 FROM stripe_events WHERE id=?", (event_id,)).fetchone():
            return {"received": True, "duplicate": True}
        obj = (event.get("data") or {}).get("object") or {}
        customer_id = obj.get("customer")
        record = self._conn.execute("SELECT * FROM billing_customers WHERE customer_id=?", (customer_id,)).fetchone()
        if record is None:
            # Events for Cortex or any other product on the same Stripe account grant nothing here.
            return {"received": True, "ignored": True}
        if event.get("type") == "invoice.created":
            return self._close_period(str(event_id), obj, record, cfg=cfg, gw=gw)
        tenant_id = record["tenant_id"]
        sub_id = obj.get("subscription") if event["type"] == "checkout.session.completed" else obj.get("id")
        if not isinstance(sub_id, str) or not sub_id.startswith("sub_"):
            raise BillingRefused(HTTPStatus.BAD_REQUEST, "Missing subscription reference")

        # Re-read Stripe's current state: delivery order and event bodies never decide the plan. The
        # network call happens before the database transaction so the store is not held during it.
        sub = gw.request("GET", "/subscriptions/" + sub_id)
        if sub.get("customer") != customer_id:
            raise BillingRefused(HTTPStatus.BAD_REQUEST, "Subscription customer does not match the tenant")
        stripe_status = str(sub.get("status") or "")
        ended = stripe_status in _ENDED
        known = record["subscription_id"]
        if known and known != sub_id:
            current = self._plans.get_tenant_plan(tenant_id)
            live_elsewhere = current["plan_id"] != FREE and current["status"] != STATUS_CANCELED
            if ended or live_elsewhere:
                # An old or second subscription must not overwrite the one the tenant is on.
                with self._conn:
                    record_once(self._conn, event_id, processed_at=int(time.time()))
                return {"received": True, "ignored": True}

        if ended:
            plan_id, status, device_item, overage_item = FREE, STATUS_ACTIVE, None, None
            period_start = period_end = None
        else:
            if stripe_status not in _STATUS_MAP:
                raise BillingRefused(HTTPStatus.BAD_REQUEST, "Unsupported subscription status")
            plan_id, device_item, overage_item, period_start, period_end = self._identify(sub, cfg=cfg)
            status = _STATUS_MAP[stripe_status]

        had_trial = sub.get("trial_end") is not None or stripe_status == "trialing"
        trial_end = sub.get("trial_end")
        trial_end_iso = _iso(trial_end) if not ended and _is_epoch(trial_end) else None
        # One transaction: the event is marked processed only together with the plan it produced, so a
        # crash in between leaves both undone and Stripe's retry applies them.
        with self._conn:
            if not record_once(self._conn, event_id, processed_at=int(time.time())):
                return {"received": True, "duplicate": True}
            self._conn.execute(
                "UPDATE billing_customers SET subscription_id=?, plan_id=?, device_item_id=?, overage_item_id=?, "
                "seat_quantity=COALESCE(?, seat_quantity), updated_at=?, "
                "trial_used_at=CASE WHEN ? THEN COALESCE(trial_used_at, ?) ELSE trial_used_at END WHERE tenant_id=?",
                (None if ended else sub_id, None if ended else plan_id,
                 device_item["id"] if device_item else None, overage_item["id"] if overage_item else None,
                 device_item.get("quantity") if device_item else None, _now(), had_trial, _now(), tenant_id))
            self._conn.execute("DELETE FROM checkout_requests WHERE tenant_id=?", (tenant_id,))
            if device_item:
                self._observe_seats(tenant_id, sub_id, device_item.get("quantity"))
            # Last statement: its own `with` commits this whole transaction, or rolls all of it back.
            self._plans.set_tenant_plan(tenant_id=tenant_id, plan_id=plan_id, status=status, period_end=period_end,
                                        period_start=period_start, trial_end=trial_end_iso)
        return {"received": True, "plan_id": plan_id, "status": status, "tenant_id": tenant_id}

    def _identify(self, sub: Mapping[str, Any], *, cfg: BillingConfig) -> tuple[str, dict, dict, Optional[str], str]:
        """(plan_id, device item, overage item, period_start ISO or None, period_end ISO) after checking the
        items against the catalog."""
        items = (sub.get("items") or {}).get("data") or []
        if len(items) != 2:
            raise BillingRefused(HTTPStatus.BAD_REQUEST, "Subscription must contain the device and overage prices")
        catalog = self._catalog()
        by_price = {item.get("price", {}).get("id"): item for item in items if isinstance(item, Mapping)}
        for plan_id, prices in cfg.prices.items():
            if set(by_price) == {prices.device, prices.overage}:
                plan = catalog.get(plan_id)
                if plan is None or not plan.paid:
                    break
                device_item, overage_item = by_price[prices.device], by_price[prices.overage]
                try:
                    validate_device_price(device_item["price"], price_id=prices.device, plan=plan)
                    validate_overage_price(overage_item["price"], price_id=prices.overage, plan=plan, meter_id=cfg.meter_id)
                except BillingUnavailable as exc:
                    raise BillingRefused(HTTPStatus.BAD_REQUEST, str(exc)) from exc
                # Basil moved the billing period onto the subscription items.
                period_end = device_item.get("current_period_end", sub.get("current_period_end"))
                period_start = device_item.get("current_period_start", sub.get("current_period_start"))
                return (plan_id, dict(device_item), dict(overage_item),
                        None if period_start is None else _iso(period_start), _iso(period_end))
        raise BillingRefused(HTTPStatus.BAD_REQUEST, "Subscription prices do not match the configured Shield catalog")

    # -- period close: overage (phase 3d) -----------------------------------------------------
    #
    # Overage is sent once per period, when Stripe creates the period's invoice. A subscription-cycle
    # invoice stays a draft for the finalization grace period (and for up to 72h while this webhook has
    # not answered 2xx), and Stripe adds usage reported in that window to it when the meter event's
    # timestamp falls inside the invoice's service period. Sending only at close means the allowance is
    # computed once, from the period's final seat count, so no mid-period send can over-bill.
    #
    # Known limits (documented in the design doc, §5): other invoice types count only usage received
    # before they are created, so an immediate cancellation or a mid-period plan change bills no overage
    # for that period. Both under-bill; neither over-bills. The customer portal must therefore cancel at
    # period end and must not offer plan switching.

    def _mark_seen(self, event_id: str, **extra: Any) -> dict[str, Any]:
        with self._conn:
            record_once(self._conn, event_id, processed_at=int(time.time()))
        return {"received": True, "ignored": True, **extra}

    def _observe_seats(self, tenant_id: str, sub_id: str, quantity: Any) -> None:
        """Record the device quantity Stripe reports (checkout, portal) as acknowledged seat history.

        Runs inside the caller's transaction. Only changes are recorded, so a redelivery adds nothing.
        """
        if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 0:
            return
        last = self._conn.execute(
            "SELECT quantity FROM seat_syncs WHERE subscription_id=? AND acknowledged_at IS NOT NULL "
            "ORDER BY acknowledged_at DESC, id DESC LIMIT 1", (sub_id,)).fetchone()
        if last is None or last["quantity"] != quantity:
            now = _now()
            self._conn.execute(
                "INSERT INTO seat_syncs (tenant_id, subscription_id, quantity, requested_at, acknowledged_at) "
                "VALUES (?,?,?,?,?)", (tenant_id, sub_id, quantity, now, now))

    def period_seats(self, sub_id: str, start: str, end: str, *, fallback: int) -> int:
        """The most seats billed at any point in [start, end): the quantity in force when the period
        began, and every change acknowledged during it. Counting the maximum errs toward a larger
        allowance, so a seat added late in the period never produces overage the customer did not owe."""
        in_force = self._conn.execute(
            "SELECT quantity FROM seat_syncs WHERE subscription_id=? AND acknowledged_at IS NOT NULL "
            "AND acknowledged_at<=? ORDER BY acknowledged_at DESC, id DESC LIMIT 1", (sub_id, start)).fetchone()
        during = self._conn.execute(
            "SELECT MAX(quantity) FROM seat_syncs WHERE subscription_id=? AND acknowledged_at>? AND acknowledged_at<?",
            (sub_id, start, end)).fetchone()[0]
        known = [q for q in (in_force["quantity"] if in_force else None, during) if q is not None]
        return max(known) if known else fallback

    def period_counts(self, tenant_id: str, start: str, end: str) -> list[dict[str, Any]]:
        """Per-device counts received in [start, end) from non-synthetic devices (design §4.3). A report
        received after the period closes counts toward the period in which it arrived. The close and the
        usage page both read this query, so the page cannot show a number the invoice will not bill."""
        rows = self._conn.execute(
            "SELECT u.device_id AS device_id, SUM(u.billable) AS billable, SUM(u.excluded_mask) AS excluded_mask, "
            "SUM(u.excluded_fault) AS excluded_fault, COUNT(*) AS reports FROM usage_reports u "
            "JOIN devices d ON d.tenant_id=u.tenant_id AND d.device_id=u.device_id "
            "WHERE u.tenant_id=? AND d.synthetic=0 AND u.received_at>=? AND u.received_at<? "
            "GROUP BY u.device_id ORDER BY u.device_id",
            (tenant_id, start, end)).fetchall()
        return [{key: (row[key] if key == "device_id" else int(row[key])) for key in row.keys()} for row in rows]

    def free_seats(self, tenant_id: str, start: str, end: str) -> int:
        """Seats for a free-tier allowance: enrolled non-synthetic devices now, or the devices that reported in
        [start, end), whichever is larger. Free tenants have no seat history, so this errs toward the larger
        allowance: removing a device never shrinks a past month's allowance. A reporter that has since been
        removed still counts; only devices marked synthetic are left out. The usage page and free-tier
        enforcement both call it, so the page never says "under" while enrollment is refused."""
        reporters = self._conn.execute(
            "SELECT COUNT(DISTINCT u.device_id) FROM usage_reports u LEFT JOIN devices d "
            "ON d.tenant_id=u.tenant_id AND d.device_id=u.device_id "
            "WHERE u.tenant_id=? AND u.received_at>=? AND u.received_at<? AND COALESCE(d.synthetic, 0)=0",
            (tenant_id, start, end)).fetchone()[0]
        return max(self.seat_count(tenant_id), int(reporters))

    def period_billable(self, tenant_id: str, start: str, end: str) -> int:
        return sum(device["billable"] for device in self.period_counts(tenant_id, start, end))

    def _close_period(self, event_id: str, obj: Mapping[str, Any], record: Any, *, cfg: BillingConfig,
                      gw: Any) -> dict[str, Any]:
        tenant_id, customer_id = record["tenant_id"], record["customer_id"]
        invoice_id = obj.get("id")
        if not isinstance(invoice_id, str) or not invoice_id.startswith("in_"):
            raise BillingRefused(HTTPStatus.BAD_REQUEST, "Missing invoice reference")
        invoice = gw.request("GET", "/invoices/" + invoice_id)
        if invoice.get("customer") != customer_id:
            raise BillingRefused(HTTPStatus.BAD_REQUEST, "Invoice customer does not match the tenant")
        sub_id = ((invoice.get("parent") or {}).get("subscription_details") or {}).get("subscription")
        if (invoice.get("billing_reason") != "subscription_cycle" or not isinstance(sub_id, str)
                or not sub_id.startswith("sub_")):
            # Only a cycle invoice closes a usage period that can still take usage (see above).
            return self._mark_seen(event_id)
        start, end = invoice.get("period_start"), invoice.get("period_end")
        period_start, period_end = _iso(start), _iso(end)
        if end <= start:
            return self._mark_seen(event_id)

        key = (tenant_id, period_start)
        row = self._conn.execute("SELECT * FROM meter_submissions WHERE tenant_id=? AND period_start=?", key).fetchone()
        if row is not None and row["acknowledged_at"]:
            self._mark_seen(event_id)
            return {"received": True, "closed": True, "value": row["value"], "replay": True}
        if invoice.get("status") != "draft":
            # Past finalization Stripe no longer adds usage to this invoice; resending cannot bill it.
            logger.error("overage for %s period %s missed its invoice (status %s)", tenant_id, period_start,
                         invoice.get("status"))
            return self._mark_seen(event_id, reason="invoice already finalized")

        if row is None:
            sub = gw.request("GET", "/subscriptions/" + sub_id)
            if sub.get("customer") != customer_id:
                raise BillingRefused(HTTPStatus.BAD_REQUEST, "Subscription customer does not match the tenant")
            plan_id, device_item, _overage_item, next_start, next_end = self._identify(sub, cfg=cfg)
            plan = self._catalog()[plan_id]
            seats = self.period_seats(sub_id, period_start, period_end, fallback=int(device_item.get("quantity") or 0))
            billable = self.period_billable(tenant_id, period_start, period_end)
            trial_end = sub.get("trial_end")
            included, value = overage_for_period(
                seats=seats, billable=billable, included_per_device=plan.included_decisions_per_device,
                in_trial=_is_epoch(trial_end) and end <= trial_end)
            with self._conn:
                if next_start is not None:
                    # Stripe moves the subscription onto its next period before it creates the cycle invoice.
                    # `customer.subscription.updated` normally carries that too; this keeps the usage page
                    # on the right period if that event is late or lost. The SQL guard never moves a stored
                    # period backwards, so a late invoice for an older period changes nothing.
                    self._conn.execute(
                        "UPDATE tenant_plans SET period_start=?, period_end=?, updated_at=? WHERE tenant_id=? "
                        "AND plan_id=? AND (period_start IS NULL OR period_start<?)",
                        (next_start, next_end, _now(), tenant_id, plan_id, next_start))
                self._conn.execute(
                    "INSERT OR IGNORE INTO meter_submissions (tenant_id, period_start, period_end, plan_id, seats, "
                    "billable, included, value, identifier, invoice_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (tenant_id, period_start, period_end, plan_id, seats, billable, included, value,
                     f"shield-ovg:{tenant_id}:{start}", invoice_id, _now()))
            row = self._conn.execute("SELECT * FROM meter_submissions WHERE tenant_id=? AND period_start=?",
                                     key).fetchone()

        if row["value"] > 0:
            if row["sent_at"] and time.time() - _epoch(row["sent_at"]) > DEDUPE_WINDOW_SECONDS:
                # Stripe may have the first send but no longer dedupes its identifier: resending could
                # bill twice. Stay unacknowledged (Stripe keeps retrying) until an operator reconciles.
                logger.error("overage for %s period %s needs reconciliation before resending", tenant_id, period_start)
                raise BillingUnavailable("Overage submission needs reconciliation")
            event_name = validate_meter(gw.request("GET", "/billing/meters/" + cfg.meter_id), meter_id=cfg.meter_id)
            with self._conn:
                self._conn.execute("UPDATE meter_submissions SET sent_at=COALESCE(sent_at, ?) "
                                   "WHERE tenant_id=? AND period_start=?", (_now(), *key))
            # Timestamped at the period's midpoint. Stripe adds the event to this draft only if the timestamp is
            # inside the metered line's service period, and that period's end is truncated (to the minute in a
            # 2026-11-13 test-clock run): `end - 1` fell after it and slipped to the next invoice. A monthly
            # midpoint stays well inside Stripe's 35-day window even after the 72h finalization hold.
            gw.send_meter_event(event_name, customer_id, row["value"], row["identifier"],
                                timestamp=start + (end - start) // 2)
        # The event is marked processed only with the acknowledgement: a crash after the send leaves both
        # undone, and Stripe's redelivery resends under the same identifier.
        with self._conn:
            record_once(self._conn, event_id, processed_at=int(time.time()))
            self._conn.execute("UPDATE meter_submissions SET acknowledged_at=COALESCE(acknowledged_at, ?) "
                               "WHERE tenant_id=? AND period_start=?", (_now(), *key))
        return {"received": True, "closed": True, "value": row["value"]}

    # -- seats --------------------------------------------------------------------------------

    def sync_seats(self, tenant_id: str) -> dict[str, Any]:
        """Set the device item's quantity to the tenant's seat count, prorated (§5). Idempotent.

        A `seat_syncs` row is written before the Stripe call and its id is the idempotency key, so a
        retry after a crash replays the same change and a later change (even back to an earlier count)
        is never mistaken for a replay. 3d reads these rows for the period's maximum device count.
        """
        record = self.customer(tenant_id)
        if not record or not record["subscription_id"] or not record["device_item_id"]:
            return {"synced": False, "reason": "no subscription"}
        quantity = self.seat_count(tenant_id)
        if record["seat_quantity"] == quantity:
            return {"synced": True, "quantity": quantity, "changed": False}
        _cfg, gw = self._ready()
        pending = self._conn.execute(
            "SELECT id FROM seat_syncs WHERE tenant_id=? AND subscription_id=? AND quantity=? AND acknowledged_at IS NULL "
            "ORDER BY id DESC LIMIT 1", (tenant_id, record["subscription_id"], quantity)).fetchone()
        if pending is None:
            with self._conn:
                cursor = self._conn.execute(
                    "INSERT INTO seat_syncs (tenant_id, subscription_id, quantity, requested_at) VALUES (?,?,?,?)",
                    (tenant_id, record["subscription_id"], quantity, _now()))
            sync_id = cursor.lastrowid
        else:
            sync_id = pending["id"]
        gw.request("POST", "/subscription_items/" + record["device_item_id"], data={
            "quantity": quantity, "proration_behavior": "create_prorations",
        }, idempotency_key=f"shield-seats:{tenant_id}:{sync_id}")
        with self._conn:
            self._conn.execute("UPDATE seat_syncs SET acknowledged_at=? WHERE id=?", (_now(), sync_id))
            self._conn.execute("UPDATE billing_customers SET seat_quantity=?, updated_at=? WHERE tenant_id=?",
                               (quantity, _now(), tenant_id))
        return {"synced": True, "quantity": quantity, "changed": True}

    def sync_seats_soon(self, tenant_id: str) -> None:
        """Best-effort seat sync off the request thread: enrollment never waits on, or fails with, Stripe."""
        def run() -> None:
            try:
                self.sync_seats(tenant_id)
            except Exception as exc:  # noqa: BLE001 -- reconciled later by the webhook, checkout or admin sync
                logger.warning("seat sync for %s deferred: %s", tenant_id, type(exc).__name__)
        threading.Thread(target=run, name="shield-seat-sync", daemon=True).start()


def supabase_durability(db_path: Any) -> Callable[[], bool]:
    """A `durable` hook that checkpoints to Supabase when it is configured (Render); a no-op locally."""
    def durable() -> bool:
        from .supabase_persistence import checkpoint_database, get_configured_dsn  # noqa: PLC0415
        dsn = get_configured_dsn()
        return True if not dsn else checkpoint_database(dsn, db_path, meta={"trigger": "stripe-webhook"})
    return durable


# -- HTTP routes (called from api.py's handler; `h` is the request handler) ---------------------

BILLING_POST_ROUTES = frozenset({"/api/shield/billing/checkout", "/api/shield/billing/portal",
                                 "/api/shield/billing/sync"})
WEBHOOK_ROUTE = "/api/shield/stripe/webhook"


def _send_billing_error(h: Any, exc: Exception) -> None:
    if isinstance(exc, BillingRefused):
        h._send_error(exc.status, str(exc))
    elif isinstance(exc, BillingUnavailable):
        h._send_error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
    else:
        h._send_error(HTTPStatus.BAD_REQUEST, str(exc))


def handle_billing_get(h: Any, billing: ShieldBilling, query: Mapping[str, list[str]]) -> None:
    tenant_id = h._tenant_from_query_or_error(query)
    if tenant_id is None or not h._require_admin(tenant_id=tenant_id):
        return
    h._send_json(billing.status(tenant_id))


def handle_billing_usage_get(h: Any, billing: ShieldBilling, ledger: Any, query: Mapping[str, list[str]], *,
                             free_tier: Any = None) -> None:
    tenant_id = h._tenant_from_query_or_error(query)
    if tenant_id is None or not h._require_admin(tenant_id=tenant_id):
        return
    # Gaps are holes in a log's whole history (a fact about the chain, not about one period).
    result = {**billing.usage(tenant_id), "gaps": ledger.gaps(tenant_id=tenant_id)}
    if free_tier is not None:
        result["free_tier"] = free_tier.status(tenant_id)
    h._send_json(result)


def handle_billing_post(h: Any, billing: ShieldBilling, path: str, body: Mapping[str, Any], base_url: str) -> None:
    tenant_id = str(body.get("tenant_id") or "")
    if not tenant_id:
        h._send_error(HTTPStatus.BAD_REQUEST, "tenant_id is required")
        return
    if not h._require_admin(tenant_id=tenant_id):
        return
    try:
        if path.endswith("/checkout"):
            result = billing.checkout(tenant_id=tenant_id, plan_id=str(body.get("plan_id") or ""), base_url=base_url)
        elif path.endswith("/portal"):
            result = billing.portal(tenant_id=tenant_id, base_url=base_url)
        else:
            result = billing.sync_seats(tenant_id)
    except (BillingRefused, BillingUnavailable, ValueError) as exc:
        _send_billing_error(h, exc)
        return
    h._send_json(result)


def handle_stripe_webhook(h: Any, billing: ShieldBilling) -> None:
    """Raw body (the signature covers the exact bytes), so this runs before any JSON parsing."""
    try:
        length = int(h.headers.get("Content-Length", "0"))
    except ValueError:
        length = -1
    if length <= 0 or length > MAX_WEBHOOK_BYTES:
        # The body is deliberately left unread, so this connection must not be reused: its bytes would be
        # parsed as the next request.
        h.close_connection = True
        h._send_error(HTTPStatus.BAD_REQUEST, "invalid webhook body")
        return
    body = h.rfile.read(length)
    try:
        result = billing.handle_webhook(body, h.headers.get("Stripe-Signature", ""))
    except (BillingRefused, BillingUnavailable, ValueError) as exc:
        _send_billing_error(h, exc)
        return
    tenant_id = result.pop("tenant_id", None)
    if tenant_id and result.get("plan_id") != FREE:
        billing.sync_seats_soon(tenant_id)
    h._send_json(result)


__all__ = ["BILLING_POST_ROUTES", "BillingConfig", "BillingRefused", "PlanPrices", "ShieldBilling", "WEBHOOK_ROUTE",
           "handle_billing_get", "handle_billing_post", "handle_billing_usage_get", "overage_for_period", "handle_stripe_webhook", "supabase_durability",
           "validate_device_price", "validate_overage_price"]
