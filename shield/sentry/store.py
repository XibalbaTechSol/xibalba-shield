"""
Persistence store for Sentry Defense Subsystem (canary traps, execution tickets, OCSF events).
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Mapping, Sequence

from .canary import CanaryTrap
from .justification import ExecutionTicket
from .ocsf import OCSFEvent


class SentryDefenseStore:
    """Manages SQLite persistence for Shield Sentry defense artifacts."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sentry_canaries (
                canary_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                secret_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                tripped INTEGER NOT NULL DEFAULT 0,
                tripped_at TEXT,
                tripped_context TEXT
            );

            CREATE TABLE IF NOT EXISTS sentry_tickets (
                ticket_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                agent_did TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                params_hash TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                nonce TEXT NOT NULL,
                signature TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                consumed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS sentry_ocsf_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                class_uid INTEGER NOT NULL DEFAULT 6003,
                activity_id INTEGER NOT NULL,
                severity_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sentry_enclave_records (
                tenant_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, record_id)
            );
            """
        )

    # --- Canaries ---
    def record_canary(self, trap: CanaryTrap) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO sentry_canaries (
                canary_id, tenant_id, agent_id, secret_key, created_at, tripped, tripped_at, tripped_context
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trap.canary_id,
                trap.tenant_id,
                trap.agent_id,
                trap.secret_key,
                trap.created_at,
                1 if trap.tripped else 0,
                trap.tripped_at,
                trap.tripped_context,
            ),
        )
        self._conn.commit()

    def trip_canary(self, canary_id: str, context: str) -> bool:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cur = self._conn.execute(
            """
            UPDATE sentry_canaries
            SET tripped = 1, tripped_at = ?, tripped_context = ?
            WHERE canary_id = ?
            """,
            (now, context[:200], canary_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def get_canary(self, canary_id: str) -> dict[str, Any] | None:
        cur = self._conn.execute(
            "SELECT canary_id, tenant_id, agent_id, secret_key, created_at, tripped, tripped_at, tripped_context FROM sentry_canaries WHERE canary_id = ?",
            (canary_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "canary_id": row[0],
            "tenant_id": row[1],
            "agent_id": row[2],
            "secret_key": row[3],
            "created_at": row[4],
            "tripped": bool(row[5]),
            "tripped_at": row[6],
            "tripped_context": row[7],
        }

    # --- Execution Tickets ---
    def record_ticket(self, ticket: ExecutionTicket) -> None:
        self._conn.execute(
            """
            INSERT INTO sentry_tickets (
                ticket_id, tenant_id, agent_did, tool_name, params_hash, risk_level,
                issued_at, expires_at, nonce, signature, consumed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                ticket.ticket_id,
                ticket.tenant_id,
                ticket.agent_did,
                ticket.tool_name,
                ticket.params_hash,
                ticket.risk_level,
                ticket.issued_at,
                ticket.expires_at,
                ticket.nonce,
                ticket.signature,
            ),
        )
        self._conn.commit()

    def consume_ticket(self, ticket_id: str) -> bool:
        """Atomically marks a ticket as consumed to prevent replay attacks."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cur = self._conn.execute(
            """
            UPDATE sentry_tickets
            SET consumed = 1, consumed_at = ?
            WHERE ticket_id = ? AND consumed = 0 AND expires_at >= ?
            """,
            (now, ticket_id, now),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        cur = self._conn.execute(
            """
            SELECT ticket_id, tenant_id, agent_did, tool_name, params_hash, risk_level,
                   issued_at, expires_at, nonce, signature, consumed, consumed_at
            FROM sentry_tickets WHERE ticket_id = ?
            """,
            (ticket_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "ticket_id": row[0],
            "tenant_id": row[1],
            "agent_did": row[2],
            "tool_name": row[3],
            "params_hash": row[4],
            "risk_level": row[5],
            "issued_at": row[6],
            "expires_at": row[7],
            "nonce": row[8],
            "signature": row[9],
            "consumed": bool(row[10]),
            "consumed_at": row[11],
        }

    # --- OCSF Audit Events ---
    def record_ocsf_event(self, event: OCSFEvent | Mapping[str, Any], event_type: str = "ai_activity") -> int:
        d = event.to_dict() if isinstance(event, OCSFEvent) else dict(event)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cur = self._conn.execute(
            """
            INSERT INTO sentry_ocsf_events (
                tenant_id, class_uid, activity_id, severity_id, event_type, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                d.get("metadata", {}).get("tenant_id", "default"),
                d.get("class_uid", 6003),
                d.get("activity_id", 0),
                d.get("severity_id", 1),
                event_type,
                json.dumps(d, sort_keys=True),
                now,
            ),
        )
        self._conn.commit()
        return cur.lastrowid or 0

    def list_ocsf_events(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            """
            SELECT id, tenant_id, class_uid, activity_id, severity_id, event_type, payload_json, created_at
            FROM sentry_ocsf_events
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (tenant_id, limit),
        )
        rows = cur.fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r[0],
                "tenant_id": r[1],
                "class_uid": r[2],
                "activity_id": r[3],
                "severity_id": r[4],
                "event_type": r[5],
                "payload": json.loads(r[6]),
                "created_at": r[7],
            })
        return result

    # --- Enclave Records ---
    def put_enclave_record(self, tenant_id: str, record_id: str, envelope: Mapping[str, Any]) -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._conn.execute(
            """
            INSERT OR REPLACE INTO sentry_enclave_records (tenant_id, record_id, envelope_json, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (tenant_id, record_id, json.dumps(envelope, sort_keys=True), now),
        )
        self._conn.commit()

    def get_enclave_record(self, tenant_id: str, record_id: str) -> dict[str, Any] | None:
        cur = self._conn.execute(
            "SELECT envelope_json FROM sentry_enclave_records WHERE tenant_id = ? AND record_id = ?",
            (tenant_id, record_id),
        )
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row[0])

    # --- Audit Summary ---
    def get_audit_summary(self, tenant_id: str) -> dict[str, Any]:
        cur = self._conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM sentry_canaries WHERE tenant_id = ?) as total_canaries,
                (SELECT COUNT(*) FROM sentry_canaries WHERE tenant_id = ? AND tripped = 1) as tripped_canaries,
                (SELECT COUNT(*) FROM sentry_tickets WHERE tenant_id = ?) as total_tickets,
                (SELECT COUNT(*) FROM sentry_tickets WHERE tenant_id = ? AND consumed = 1) as consumed_tickets,
                (SELECT COUNT(*) FROM sentry_ocsf_events WHERE tenant_id = ?) as total_ocsf_events,
                (SELECT COUNT(*) FROM sentry_ocsf_events WHERE tenant_id = ? AND event_type = 'poj_denied') as denied_actions
            """,
            (tenant_id, tenant_id, tenant_id, tenant_id, tenant_id, tenant_id),
        )
        row = cur.fetchone()
        if not row:
            return {
                "total_canaries": 0,
                "tripped_canaries": 0,
                "total_tickets": 0,
                "consumed_tickets": 0,
                "total_ocsf_events": 0,
                "denied_actions": 0,
            }
        return {
            "total_canaries": row[0],
            "tripped_canaries": row[1],
            "total_tickets": row[2],
            "consumed_tickets": row[3],
            "total_ocsf_events": row[4],
            "denied_actions": row[5],
        }
