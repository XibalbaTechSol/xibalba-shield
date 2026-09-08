"""Durable, atomic lifecycle operations for device remediation jobs."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .store import ShieldStore, _now


def _ensure_attempts(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS exporter_remediation_attempts (
            request_id INTEGER PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'running',
            detail_json TEXT,
            FOREIGN KEY (request_id) REFERENCES exporter_remediation_requests(id) ON DELETE CASCADE
        )
        """
    )


def claim_next(store: ShieldStore, *, tenant_id: str, device_id: str) -> dict[str, Any] | None:
    """Atomically claim the oldest queued request for one authenticated device."""
    store._require_device(tenant_id, device_id)
    with store._conn:
        _ensure_attempts(store._conn)
        row = store._conn.execute(
            "SELECT id,action,reason,created_at FROM exporter_remediation_requests "
            "WHERE tenant_id=? AND device_id=? AND status='queued' ORDER BY id LIMIT 1",
            (tenant_id, device_id),
        ).fetchone()
        if row is None:
            return None
        started_at = _now()
        changed = store._conn.execute(
            "UPDATE exporter_remediation_requests SET status='running' WHERE id=? AND status='queued'",
            (row["id"],),
        ).rowcount
        if changed != 1:
            return None
        store._conn.execute(
            "INSERT INTO exporter_remediation_attempts(request_id,tenant_id,device_id,started_at) VALUES(?,?,?,?)",
            (row["id"], tenant_id, device_id, started_at),
        )
    return {"id": row["id"], "tenant_id": tenant_id, "device_id": device_id,
            "action": row["action"], "reason": row["reason"], "status": "running",
            "created_at": row["created_at"], "started_at": started_at}


def complete(
    store: ShieldStore, *, tenant_id: str, device_id: str, request_id: int,
    status: str, detail: dict[str, Any],
) -> dict[str, Any]:
    if status not in {"completed", "failed"}:
        raise ValueError("status must be completed or failed")
    completed_at = _now()
    encoded = json.dumps(detail, sort_keys=True)
    with store._conn:
        _ensure_attempts(store._conn)
        changed = store._conn.execute(
            "UPDATE exporter_remediation_requests SET status=? WHERE id=? AND tenant_id=? AND device_id=? AND status='running'",
            (status, request_id, tenant_id, device_id),
        ).rowcount
        if changed != 1:
            raise KeyError("running remediation request not found")
        store._conn.execute(
            "UPDATE exporter_remediation_attempts SET status=?,completed_at=?,detail_json=? "
            "WHERE request_id=? AND tenant_id=? AND device_id=?",
            (status, completed_at, encoded, request_id, tenant_id, device_id),
        )
    return {"id": request_id, "tenant_id": tenant_id, "device_id": device_id,
            "status": status, "completed_at": completed_at, "detail": detail}


def list_attempts(store: ShieldStore, *, tenant_id: str, device_id: str | None = None) -> list[dict[str, Any]]:
    with store._conn:
        _ensure_attempts(store._conn)
    query = "SELECT request_id,tenant_id,device_id,started_at,completed_at,status,detail_json FROM exporter_remediation_attempts WHERE tenant_id=?"
    params: list[Any] = [tenant_id]
    if device_id:
        query += " AND device_id=?"
        params.append(device_id)
    query += " ORDER BY request_id DESC"
    rows = store._conn.execute(query, params).fetchall()
    return [{**dict(row), "detail": json.loads(row["detail_json"]) if row["detail_json"] else None}
            for row in rows]
