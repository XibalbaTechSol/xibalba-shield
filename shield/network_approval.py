"""One-time, intent-bound approval workflow for network actions."""

from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .network_policy import NetworkActionRequest


class NetworkApprovalError(RuntimeError):
    pass


@dataclass(frozen=True)
class NetworkApproval:
    approval_id: str
    intent_hash: str
    requested_by: str
    status: str
    approved_by: str | None = None
    reason: str | None = None


class NetworkApprovalStore:
    """Small durable store; authorization remains with the local policy gate."""

    def __init__(self, path: str | Path, *, clock: callable = time.time) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._clock = clock
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, requested_by TEXT NOT NULL, status TEXT NOT NULL, approved_by TEXT, reason TEXT, updated_at REAL NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=1.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def request(self, action: NetworkActionRequest) -> NetworkApproval:
        approval_id = "approval-" + uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?,?)", (approval_id, action.intent_hash(), action.requested_by, "pending", None, None, self._clock()))
        return NetworkApproval(approval_id, action.intent_hash(), action.requested_by, "pending")

    def get(self, approval_id: str) -> NetworkApproval:
        with self._connect() as conn:
            row = conn.execute("SELECT approval_id,intent_hash,requested_by,status,approved_by,reason FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
        if row is None:
            raise NetworkApprovalError("approval not found")
        return NetworkApproval(*row)

    def approve(self, approval_id: str, action: NetworkActionRequest, *, operator: str, role: str) -> NetworkApproval:
        if role not in {"network_approver", "network_admin"}:
            raise NetworkApprovalError("operator role cannot approve network actions")
        current = self.get(approval_id)
        if current.status != "pending":
            raise NetworkApprovalError("approval is not pending")
        if current.intent_hash != action.intent_hash():
            raise NetworkApprovalError("approval intent does not match requested action")
        with self._connect() as conn:
            conn.execute("UPDATE approvals SET status='approved',approved_by=?,updated_at=? WHERE approval_id=? AND status='pending'", (operator, self._clock(), approval_id))
        return self.get(approval_id)

    def consume(self, approval_id: str, action: NetworkActionRequest) -> NetworkApproval:
        current = self.get(approval_id)
        if current.status != "approved":
            raise NetworkApprovalError("approval is not consumable")
        if current.intent_hash != action.intent_hash():
            raise NetworkApprovalError("approval intent does not match requested action")
        with self._connect() as conn:
            conn.execute("UPDATE approvals SET status='consumed',updated_at=? WHERE approval_id=? AND status='approved'", (self._clock(), approval_id))
        return self.get(approval_id)

    def reject(self, approval_id: str, *, reason: str) -> NetworkApproval:
        current = self.get(approval_id)
        if current.status != "pending":
            raise NetworkApprovalError("approval is not pending")
        with self._connect() as conn:
            conn.execute("UPDATE approvals SET status='rejected',reason=?,updated_at=? WHERE approval_id=? AND status='pending'", (reason[:256], self._clock(), approval_id))
        return self.get(approval_id)


__all__ = ["NetworkApproval", "NetworkApprovalError", "NetworkApprovalStore"]
