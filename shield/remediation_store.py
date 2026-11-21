"""Durable approval ledger for vulnerability remediation plans; never executes updates."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class RemediationPlanStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS remediation_plans (plan_id TEXT PRIMARY KEY, plan TEXT NOT NULL, status TEXT NOT NULL, updated_at REAL NOT NULL)")

    def create(self, plan: dict[str, Any]) -> str:
        canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
        plan_id = hashlib.sha256(canonical.encode()).hexdigest()
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT OR IGNORE INTO remediation_plans VALUES (?, ?, 'pending', ?)", (plan_id, canonical, time.time()))
        return plan_id

    def transition(self, plan_id: str, status: str) -> None:
        if status not in {"approved", "rejected"}:
            raise ValueError("status must be approved or rejected")
        with sqlite3.connect(self.path) as db:
            cur = db.execute("UPDATE remediation_plans SET status=?, updated_at=? WHERE plan_id=?", (status, time.time(), plan_id))
            if cur.rowcount != 1:
                raise KeyError(plan_id)

    def get(self, plan_id: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT plan, status, updated_at FROM remediation_plans WHERE plan_id=?", (plan_id,)).fetchone()
        if row is None:
            return None
        return {"plan_id": plan_id, "plan": json.loads(row[0]), "status": row[1], "updated_at": row[2], "executed": False}
