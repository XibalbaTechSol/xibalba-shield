"""Which plan each tenant is on (plans & metering design §4.3).

One row per tenant. A tenant with no row is on ``free``. Phase 3c (the Stripe webhook) becomes the
writer; until then the only writer is :meth:`PlanStore.set_tenant_plan`, deliberately **not** exposed
over HTTP: ``_require_admin`` accepts tenant-scoped admin tokens, so an HTTP setter behind it would let
a tenant upgrade itself.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Optional

from .plans import FREE, PLAN_IDS

#: Subscription states (Stripe's vocabulary, so the webhook can write them as-is).
STATUS_ACTIVE = "active"
STATUS_TRIALING = "trialing"
STATUS_PAST_DUE = "past_due"
STATUS_UNPAID = "unpaid"
STATUS_INCOMPLETE = "incomplete"
STATUS_CANCELED = "canceled"
PLAN_STATUSES = (STATUS_ACTIVE, STATUS_TRIALING, STATUS_PAST_DUE, STATUS_UNPAID, STATUS_INCOMPLETE,
                 STATUS_CANCELED)

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenant_plans (
    tenant_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL,
    period_end TEXT,
    updated_at TEXT NOT NULL
);
"""

#: Columns added after the table first shipped. ``CREATE TABLE IF NOT EXISTS`` leaves an existing table
#: as it is, so a database created before them (Render's) gets them from :meth:`PlanStore.init_schema`.
#: ``period_start`` and ``trial_end`` (phase 3e) let the usage page show the invoice's own period.
ADDED_COLUMNS = (("period_start", "TEXT"), ("trial_end", "TEXT"))
_COLUMNS = "tenant_id, plan_id, status, period_start, period_end, trial_end, updated_at"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class PlanStore:
    """Operates on the ShieldStore connection."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        present = {row[1] for row in self._conn.execute("PRAGMA table_info(tenant_plans)")}
        with self._conn:
            for name, kind in ADDED_COLUMNS:
                if name not in present:
                    self._conn.execute(f"ALTER TABLE tenant_plans ADD COLUMN {name} {kind}")

    def get_tenant_plan(self, tenant_id: str) -> dict[str, Any]:
        """The tenant's plan row; the free default when there is none."""
        row = self._conn.execute(
            f"SELECT {_COLUMNS} FROM tenant_plans WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            return {"tenant_id": tenant_id, "plan_id": FREE, "status": STATUS_ACTIVE, "period_start": None,
                    "period_end": None, "trial_end": None, "updated_at": None}
        return dict(row)

    def device_is_synthetic(self, *, tenant_id: str, device_id: str) -> Optional[bool]:
        """True/False for an enrolled device; None when there is no such device."""
        row = self._conn.execute(
            "SELECT synthetic FROM devices WHERE tenant_id=? AND device_id=?", (tenant_id, device_id),
        ).fetchone()
        return None if row is None else bool(row["synthetic"])

    def set_tenant_plan(
        self, *, tenant_id: str, plan_id: str, status: str, period_end: Optional[str] = None,
        period_start: Optional[str] = None, trial_end: Optional[str] = None,
    ) -> dict[str, Any]:
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError("tenant_id is required")
        if plan_id not in PLAN_IDS:
            raise ValueError(f"plan_id must be one of {PLAN_IDS}")
        if status not in PLAN_STATUSES:
            raise ValueError(f"status must be one of {PLAN_STATUSES}")
        for name, value in (("period_start", period_start), ("period_end", period_end), ("trial_end", trial_end)):
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{name} must be an ISO-8601 string")
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError(f"{name} must carry a timezone")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO tenant_plans (tenant_id, plan_id, status, period_start, period_end, trial_end, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    plan_id=excluded.plan_id, status=excluded.status, period_start=excluded.period_start,
                    period_end=excluded.period_end, trial_end=excluded.trial_end, updated_at=excluded.updated_at
                """,
                (tenant_id, plan_id, status, period_start, period_end, trial_end, _now()),
            )
        return self.get_tenant_plan(tenant_id)


__all__ = ["ADDED_COLUMNS", "PLAN_STATUSES", "PlanStore", "SCHEMA", "STATUS_ACTIVE", "STATUS_CANCELED", "STATUS_INCOMPLETE",
           "STATUS_PAST_DUE", "STATUS_TRIALING", "STATUS_UNPAID"]
