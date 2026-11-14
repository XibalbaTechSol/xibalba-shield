"""Free-tier pressure (plans & metering design §4.3).

When a free tenant goes over its included decisions, decisions keep flowing (§1). The pressure is aimed
only at **new device enrollments**, never at decisions or at devices already enrolled:

* the free plan's ``max_devices`` caps the non-synthetic devices a free tenant can enroll, and
* after more than ``free_over_periods`` consecutive months over the allowance, new devices are refused.

The tenant admins are emailed once per month in which the tenant is over.

Both refusals and the email are **off** unless ``SHIELD_FREE_TIER_PRESSURE=1``: the §9 numbers they rest
on are suggestions until shadow-mode measurement sets them. The status is computed and shown either way.

Free tenants have no invoice, so a period is a UTC calendar month. A month's allowance is
``included_decisions_per_device × max(enrolled seats now, devices that reported that month)`` -- free
tenants have no seat history, and this errs toward the larger allowance. Only months the tenant spent
entirely on free count: a tenant that downgrades from a paid plan starts with a clean streak.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any, Callable, Mapping, Optional

from .plans import FREE, load_plan_catalog

logger = logging.getLogger(__name__)

PRESSURE_ENV = "SHIELD_FREE_TIER_PRESSURE"
OVER_PERIODS_ENV = "SHIELD_PLAN_FREE_OVER_PERIODS"
DEFAULT_OVER_PERIODS = 2  # §9 suggestion
NOTICE_RETRY_SECONDS = 3600  # a failed email is retried at most hourly, however many uploads arrive
_ISO = "%Y-%m-%dT%H:%M:%SZ"

SCHEMA = """
CREATE TABLE IF NOT EXISTS free_tier_notices (
    tenant_id TEXT NOT NULL,
    period TEXT NOT NULL,
    claimed_at TEXT NOT NULL,
    sent_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 1,
    last_error TEXT,
    PRIMARY KEY (tenant_id, period)
);
"""


class EnrollmentRefused(ValueError):
    """A new device was refused enrollment; ``status`` is the HTTP status to answer with."""

    def __init__(self, message: str, *, status: HTTPStatus = HTTPStatus.PAYMENT_REQUIRED) -> None:
        super().__init__(message)
        self.status = status


def pressure_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    return (os.environ if env is None else env).get(PRESSURE_ENV, "").strip() == "1"


def over_periods(env: Optional[Mapping[str, str]] = None) -> int:
    raw = (os.environ if env is None else env).get(OVER_PERIODS_ENV, "").strip()
    if raw.isdigit() and int(raw) >= 1:
        return int(raw)
    if raw:
        logger.error("%s must be a positive integer; using %d", OVER_PERIODS_ENV, DEFAULT_OVER_PERIODS)
    return DEFAULT_OVER_PERIODS


def month_of(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m")


def month_bounds(month: str) -> tuple[str, str]:
    year, mon = int(month[:4]), int(month[5:7])
    nxt = (year + 1, 1) if mon == 12 else (year, mon + 1)
    return f"{year:04d}-{mon:02d}-01T00:00:00Z", f"{nxt[0]:04d}-{nxt[1]:02d}-01T00:00:00Z"


def previous_month(month: str) -> str:
    year, mon = int(month[:4]), int(month[5:7])
    return f"{year - 1:04d}-12" if mon == 1 else f"{year:04d}-{mon - 1:02d}"


def _smtp_configured() -> bool:
    return bool(os.environ.get("SHIELD_SMTP_HOST", "").strip() and os.environ.get("SHIELD_SMTP_FROM", "").strip())


class FreeTierPressure:
    """Operates on the ShieldStore connection, through the billing counts the usage page also uses."""

    def __init__(
        self,
        conn: Any,
        plans: Any,
        billing: Any,
        *,
        catalog: Optional[Callable[[], Mapping[str, Any]]] = None,
        send_email: Optional[Callable[[str, str, str], None]] = None,
        spawn: Optional[Callable[[Callable[[], None]], None]] = None,
    ) -> None:
        self._conn = conn
        self._plans = plans
        self._billing = billing
        self._catalog = catalog or load_plan_catalog
        self._send_email = send_email
        self._spawn = spawn or (lambda fn: threading.Thread(target=fn, name="shield-free-notice", daemon=True).start())

    def init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # -- status -------------------------------------------------------------------------------

    def _free_since(self, tenant_id: str, plan_row: Mapping[str, Any]) -> Optional[str]:
        """When the tenant last left a paid plan (ISO), or None if it never had one."""
        if plan_row.get("updated_at") is None:
            return None  # no plan row: free from the start
        last_close = self._conn.execute(
            "SELECT MAX(period_end) FROM meter_submissions WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
        had_billing = self._conn.execute(
            "SELECT 1 FROM billing_customers WHERE tenant_id=? AND (subscription_id IS NOT NULL OR trial_used_at "
            "IS NOT NULL)", (tenant_id,)).fetchone()
        marks = [m for m in (plan_row["updated_at"], last_close) if m]
        return max(marks) if (had_billing or last_close) and marks else None

    def month_usage(self, tenant_id: str, month: str, plan: Any) -> dict[str, Any]:
        start, end = month_bounds(month)
        devices = self._billing.period_counts(tenant_id, start, end)
        seats = self._billing.free_seats(tenant_id, devices)
        billable = sum(d["billable"] for d in devices)
        included = seats * plan.included_decisions_per_device
        return {"month": month, "billable": billable, "seats": seats, "included": included, "over": billable > included}

    def status(self, tenant_id: str, *, now: Optional[datetime] = None) -> dict[str, Any]:
        """Where the tenant stands. ``enrollment_blocked`` is what enforcement would do, even when off."""
        plan_row = self._plans.get_tenant_plan(tenant_id)
        n = over_periods()
        result: dict[str, Any] = {"enforced": pressure_enabled(), "free_over_periods": n}
        plan = self._catalog().get(FREE)
        if plan_row["plan_id"] != FREE or plan is None:
            return {**result, "applies": False, "over": False, "over_streak": 0, "enrollment_blocked": False,
                    "device_cap_reached": False}
        now = now or datetime.now(timezone.utc)
        free_since = self._free_since(tenant_id, plan_row)
        # Only whole months on free count; the month of a downgrade is skipped.
        first_month = None if free_since is None else month_of(
            datetime.strptime(free_since, _ISO).replace(tzinfo=timezone.utc))
        current = self.month_usage(tenant_id, month_of(now), plan)

        def countable(month: str) -> bool:
            return first_month is None or month > first_month

        streak = 0
        month = current["month"] if current["over"] else previous_month(current["month"])
        while countable(month) and streak <= n:
            if not self.month_usage(tenant_id, month, plan)["over"]:
                break
            streak += 1
            month = previous_month(month)
        seats = self._billing.seat_count(tenant_id)
        cap = plan.max_devices
        return {**result, "applies": True, "over": current["over"] and countable(current["month"]),
                "over_streak": streak, "enrollment_blocked": streak > n,
                "device_cap": cap, "device_cap_reached": cap is not None and seats >= cap,
                "month": {k: current[k] for k in ("month", "billable", "seats", "included")}}

    # -- enforcement --------------------------------------------------------------------------

    def check_new_device(self, tenant_id: str) -> None:
        """Raises EnrollmentRefused when pressure is on and a free tenant may not add a device."""
        if not pressure_enabled():
            return
        state = self.status(tenant_id)
        if not state["applies"]:
            return
        if state["device_cap_reached"]:
            raise EnrollmentRefused(f"The Free plan covers at most {state['device_cap']} devices. "
                                    "Upgrade to enroll more; enrolled devices keep working.")
        if state["enrollment_blocked"]:
            raise EnrollmentRefused(
                f"This tenant has been over the Free plan's included decisions for {state['over_streak']} "
                "consecutive months. Upgrade to enroll more devices; enrolled devices keep working.")

    # -- notice -------------------------------------------------------------------------------

    def _recipients(self, tenant_id: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT email FROM accounts WHERE tenant_id=? AND role='tenant_admin' AND status='active' "
            "UNION SELECT a.email FROM account_tenant_memberships m JOIN accounts a ON a.account_id=m.account_id "
            "WHERE m.tenant_id=? AND m.role='tenant_admin' AND a.status='active'", (tenant_id, tenant_id)).fetchall()
        return sorted({row[0] for row in rows if row[0]})

    def _claim(self, tenant_id: str, period: str) -> bool:
        now = time.strftime(_ISO, time.gmtime())
        retry_before = time.strftime(_ISO, time.gmtime(time.time() - NOTICE_RETRY_SECONDS))
        with self._conn:
            if self._conn.execute("INSERT OR IGNORE INTO free_tier_notices (tenant_id, period, claimed_at) "
                                  "VALUES (?,?,?)", (tenant_id, period, now)).rowcount:
                return True
            # A failed send is retried, but at most hourly: one claim per window, so concurrent uploads
            # during an SMTP outage do not each wait on it.
            return bool(self._conn.execute(
                "UPDATE free_tier_notices SET claimed_at=?, attempts=attempts+1 WHERE tenant_id=? AND period=? "
                "AND sent_at IS NULL AND claimed_at<?", (now, tenant_id, period, retry_before)).rowcount)

    def notify_if_over(self, tenant_id: str) -> bool:
        """Called after a usage upload. Emails the tenant admins once per month the tenant is over.
        Returns True when a send was started. Never raises: usage uploads must not fail on email."""
        try:
            if not pressure_enabled() or not _smtp_configured():
                return False
            state = self.status(tenant_id)
            if not state.get("over"):
                return False
            recipients = self._recipients(tenant_id)
            period = state["month"]["month"]
            if not recipients or not self._claim(tenant_id, period):
                return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("free-tier notice check for %s failed: %s", tenant_id, type(exc).__name__)
            return False
        month = state["month"]
        subject = "Xibalba Shield: your Free plan is over its included decisions"
        body = (f"Tenant {tenant_id} has used {month['billable']:,} gated decisions in {period}, over the Free plan's "
                f"{month['included']:,} included ({month['seats']} device(s)).\n\n"
                "Decisions keep flowing and enrolled devices keep working. If the tenant stays over for more than "
                f"{state['free_over_periods']} consecutive months, new devices cannot be enrolled until it upgrades.\n")
        send = self._send_email
        if send is None:
            from .email_delivery import send_email as send  # noqa: PLC0415

        def run() -> None:
            errors = []
            for to in recipients:
                try:
                    send(to, subject, body)
                except Exception as exc:  # noqa: BLE001
                    errors.append(type(exc).__name__)
            with self._conn:
                if errors and len(errors) == len(recipients):
                    self._conn.execute("UPDATE free_tier_notices SET last_error=? WHERE tenant_id=? AND period=?",
                                       (",".join(sorted(set(errors))), tenant_id, period))
                else:
                    self._conn.execute("UPDATE free_tier_notices SET sent_at=?, last_error=? WHERE tenant_id=? "
                                       "AND period=?", (time.strftime(_ISO, time.gmtime()),
                                                        ",".join(sorted(set(errors))) or None, tenant_id, period))
        self._spawn(run)
        return True


__all__ = ["DEFAULT_OVER_PERIODS", "EnrollmentRefused", "FreeTierPressure", "NOTICE_RETRY_SECONDS",
           "OVER_PERIODS_ENV", "PRESSURE_ENV", "month_bounds", "over_periods", "pressure_enabled"]
