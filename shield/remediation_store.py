"""Durable approval ledger for vulnerability remediation plans; never executes updates."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class RemediationPlanStore:
    def __init__(self, target: Path | str | sqlite3.Connection | Any) -> None:
        self.path: Path | None = None
        self._shared_conn: Any = None

        if isinstance(target, (Path, str)):
            self.path = Path(target)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.path) as db:
                self._init_tables(db)
        else:
            # Assume database connection proxy (e.g. ShieldStore._conn or sqlite3.Connection)
            self._shared_conn = target
            self._init_tables(self._shared_conn)

    @contextmanager
    def _db(self):
        if self._shared_conn is not None:
            yield self._shared_conn
        else:
            with sqlite3.connect(self.path) as db:
                yield db

    def _init_tables(self, db: Any) -> None:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_plans (
                plan_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                plan TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at REAL NOT NULL,
                created_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                status TEXT NOT NULL,
                actor TEXT NOT NULL,
                actor_id TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )

    def init_schema(self) -> None:
        with self._db() as db:
            self._init_tables(db)

    def create(self, plan: dict[str, Any], tenant_id: str = "default") -> str:
        canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
        plan_id = hashlib.sha256(canonical.encode()).hexdigest()
        now = time.time()
        with self._db() as db:
            db.execute(
                "INSERT OR IGNORE INTO remediation_plans (plan_id, tenant_id, plan, status, updated_at, created_at) VALUES (?, ?, ?, 'pending', ?, ?)",
                (plan_id, tenant_id, canonical, now, now),
            )
        return plan_id

    def transition(
        self,
        plan_id: str,
        status: str,
        *,
        actor: str = "operator",
        actor_id: str = "",
        reason: str = "",
        tenant_id: str | None = None,
    ) -> None:
        if status not in {"approved", "rejected"}:
            raise ValueError("status must be approved or rejected")
        now = time.time()
        with self._db() as db:
            query = "UPDATE remediation_plans SET status=?, updated_at=? WHERE plan_id=?"
            params: list[Any] = [status, now, plan_id]
            if tenant_id is not None:
                query += " AND tenant_id=?"
                params.append(tenant_id)

            cur = db.execute(query, tuple(params))
            if cur.rowcount != 1:
                raise KeyError(plan_id)

            tid = tenant_id or "default"
            db.execute(
                "INSERT INTO remediation_audit(plan_id, tenant_id, status, actor, actor_id, reason, created_at) VALUES (?,?,?,?,?,?,?)",
                (plan_id, tid, status, actor[:128], actor_id[:128], reason[:512], now),
            )

    def get(self, plan_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
        with self._db() as db:
            query = "SELECT plan_id, tenant_id, plan, status, updated_at, created_at FROM remediation_plans WHERE plan_id=?"
            params: list[Any] = [plan_id]
            if tenant_id is not None:
                query += " AND tenant_id=?"
                params.append(tenant_id)

            cur = db.execute(query, tuple(params))
            row = cur.fetchone()
            if row is None:
                return None

            audit_query = "SELECT status, actor, actor_id, reason, created_at FROM remediation_audit WHERE plan_id=?"
            audit_params: list[Any] = [plan_id]
            if tenant_id is not None:
                audit_query += " AND tenant_id=?"
                audit_params.append(tenant_id)
            audit_query += " ORDER BY id"
            audit_rows = db.execute(audit_query, tuple(audit_params)).fetchall()

        plan_data = json.loads(row[2]) if isinstance(row[2], str) else row[2]
        return {
            "plan_id": row[0],
            "tenant_id": row[1],
            "plan": plan_data,
            "status": row[3],
            "updated_at": row[4],
            "created_at": row[5],
            "executed": False,
            "audit": [
                {
                    "status": a[0],
                    "actor": a[1],
                    "actor_id": a[2],
                    "reason": a[3],
                    "created_at": a[4],
                }
                for a in audit_rows
            ],
        }

    def list_plans(
        self,
        tenant_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self._db() as db:
            query = "SELECT plan_id, tenant_id, plan, status, updated_at, created_at FROM remediation_plans WHERE 1=1"
            params: list[Any] = []
            if tenant_id is not None:
                query += " AND tenant_id=?"
                params.append(tenant_id)
            if status is not None:
                query += " AND status=?"
                params.append(status)
            query += " ORDER BY updated_at DESC LIMIT ?"
            params.append(max(1, min(int(limit), 500)))

            rows = db.execute(query, tuple(params)).fetchall()

        results = []
        for r in rows:
            plan_data = json.loads(r[2]) if isinstance(r[2], str) else r[2]
            results.append({
                "plan_id": r[0],
                "tenant_id": r[1],
                "plan": plan_data,
                "status": r[3],
                "updated_at": r[4],
                "created_at": r[5],
                "executed": False,
            })
        return results
