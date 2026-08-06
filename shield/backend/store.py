"""SQLite persistence for the Shield platform MVP backend."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config.loader import ConfigError, PolicyBundle, load_policy_bundle


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Enrollment:
    tenant_id: str
    device_id: str
    device_role: str
    device_token: str
    device_config: dict[str, Any]


class ShieldStore:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        if self.db_path != Path(":memory:"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_schema()

    def close(self) -> None:
        self._conn.close()

    def init_schema(self) -> None:
        self._conn.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_role TEXT NOT NULL DEFAULT '',
                device_token_hash TEXT NOT NULL,
                agent_label TEXT NOT NULL DEFAULT 'xibalba-shield',
                last_seen_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS policies (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                action TEXT NOT NULL,
                event_class TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                export_ok INTEGER NOT NULL,
                synthetic INTEGER NOT NULL DEFAULT 0,
                received_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS exporter_status (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                status_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id),
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS integrations (
                tenant_id TEXT NOT NULL,
                integration_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                config_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, integration_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );
            """
        )
        self._conn.commit()

    def enroll_device(
        self,
        *,
        tenant_id: str,
        device_id: str,
        device_role: str = "",
        base_url: str,
        agent_label: str = "xibalba-shield",
    ) -> Enrollment:
        self._validate_id("tenant_id", tenant_id)
        self._validate_id("device_id", device_id)
        token = secrets.token_urlsafe(32)
        now = _now()
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, created_at) VALUES (?, ?)",
                (tenant_id, now),
            )
            self._conn.execute(
                """
                INSERT INTO devices
                    (tenant_id, device_id, device_role, device_token_hash, agent_label, last_seen_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, device_id) DO UPDATE SET
                    device_role=excluded.device_role,
                    device_token_hash=excluded.device_token_hash,
                    agent_label=excluded.agent_label,
                    last_seen_at=excluded.last_seen_at
                """,
                (tenant_id, device_id, device_role, _hash_token(token), agent_label, now, now),
            )
        policy_url = f"{base_url.rstrip('/')}/api/shield/policies/{tenant_id}/{device_id}"
        return Enrollment(
            tenant_id=tenant_id,
            device_id=device_id,
            device_role=device_role,
            device_token=token,
            device_config={
                "device_id": device_id,
                "tenant_id": tenant_id,
                "device_role": device_role,
                "tenant_policy_url": policy_url,
                "device_token": token,
                "feature_flags": {},
                "sensitive_paths": [],
                "trusted_policy_hashes": [],
            },
        )

    def authenticate_device(self, *, tenant_id: str, device_id: str, token: str) -> bool:
        row = self._conn.execute(
            "SELECT device_token_hash FROM devices WHERE tenant_id=? AND device_id=?",
            (tenant_id, device_id),
        ).fetchone()
        return bool(row and secrets.compare_digest(row["device_token_hash"], _hash_token(token)))

    def put_policy(self, *, tenant_id: str, device_id: str, policy_doc: dict[str, Any]) -> PolicyBundle:
        self._validate_id("tenant_id", tenant_id)
        self._validate_id("device_id", device_id)
        raw = json.dumps(policy_doc, sort_keys=True).encode("utf-8")
        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
            tmp.write(raw)
            tmp_path = Path(tmp.name)
        try:
            bundle = load_policy_bundle(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, created_at) VALUES (?, ?)",
                (tenant_id, _now()),
            )
            self._conn.execute(
                """
                INSERT INTO policies (tenant_id, device_id, policy_version, policy_hash, policy_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, device_id) DO UPDATE SET
                    policy_version=excluded.policy_version,
                    policy_hash=excluded.policy_hash,
                    policy_json=excluded.policy_json,
                    created_at=excluded.created_at
                """,
                (tenant_id, device_id, bundle.version, bundle.hash, raw.decode("utf-8"), _now()),
            )
        return bundle

    def get_policy_doc(self, *, tenant_id: str, device_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT policy_json FROM policies
            WHERE tenant_id=? AND device_id IN (?, '*')
            ORDER BY CASE WHEN device_id=? THEN 0 ELSE 1 END
            LIMIT 1
            """,
            (tenant_id, device_id, device_id),
        ).fetchone()
        return json.loads(row["policy_json"]) if row else None

    def list_devices(self, *, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT d.tenant_id, d.device_id, d.device_role, d.agent_label, d.last_seen_at,
                   p.policy_version, p.policy_hash
            FROM devices d
            LEFT JOIN policies p ON p.tenant_id=d.tenant_id AND p.device_id IN (d.device_id, '*')
            WHERE d.tenant_id=?
            GROUP BY d.tenant_id, d.device_id
            ORDER BY d.device_id
            """,
            (tenant_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_device(self, *, tenant_id: str, device_id: str) -> dict[str, Any] | None:
        rows = [row for row in self.list_devices(tenant_id=tenant_id) if row["device_id"] == device_id]
        return rows[0] if rows else None

    def record_decision(self, *, tenant_id: str, device_id: str, decision: dict[str, Any]) -> int:
        self._require_device(tenant_id, device_id)
        action = str(decision.get("decision", {}).get("action", ""))
        event_class = str(decision.get("event_ref", {}).get("class", decision.get("class", "")))
        rule_id = str(decision.get("rule", {}).get("rule_id", ""))
        severity = str(decision.get("decision", {}).get("severity", "low"))
        export = decision.get("export", {})
        export_ok = bool(export.get("decision_exported") or export.get("authorized"))
        synthetic = bool(decision.get("synthetic") or decision.get("_demo"))
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO decisions
                    (tenant_id, device_id, decision_json, action, event_class, rule_id, severity, export_ok, synthetic, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, device_id, json.dumps(decision, sort_keys=True), action, event_class, rule_id, severity, int(export_ok), int(synthetic), _now()),
            )
            self._touch_device(tenant_id, device_id)
        return int(cursor.lastrowid)

    def record_metrics(self, *, tenant_id: str, device_id: str, metrics: dict[str, Any]) -> int:
        self._require_device(tenant_id, device_id)
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO metrics (tenant_id, device_id, metrics_json, received_at) VALUES (?, ?, ?, ?)",
                (tenant_id, device_id, json.dumps(metrics, sort_keys=True), _now()),
            )
            self._touch_device(tenant_id, device_id)
        return int(cursor.lastrowid)

    def upsert_exporter_status(self, *, tenant_id: str, device_id: str, status: dict[str, Any]) -> None:
        self._require_device(tenant_id, device_id)
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO exporter_status (tenant_id, device_id, status_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(tenant_id, device_id) DO UPDATE SET
                    status_json=excluded.status_json,
                    updated_at=excluded.updated_at
                """,
                (tenant_id, device_id, json.dumps(status, sort_keys=True), _now()),
            )

    def list_exporter_status(self, *, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT device_id, status_json, updated_at FROM exporter_status WHERE tenant_id=? ORDER BY device_id",
            (tenant_id,),
        ).fetchall()
        return [
            {"device_id": row["device_id"], "status": json.loads(row["status_json"]), "updated_at": row["updated_at"]}
            for row in rows
        ]

    def put_integration(
        self,
        *,
        tenant_id: str,
        kind: str,
        config: dict[str, Any],
        integration_id: str | None = None,
    ) -> str:
        self._validate_id("tenant_id", tenant_id)
        integration_id = integration_id or f"{kind}-{secrets.token_hex(6)}"
        self._validate_id("integration_id", integration_id)
        now = _now()
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, created_at) VALUES (?, ?)",
                (tenant_id, now),
            )
            self._conn.execute(
                """
                INSERT INTO integrations (tenant_id, integration_id, kind, config_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, integration_id) DO UPDATE SET
                    kind=excluded.kind,
                    config_json=excluded.config_json
                """,
                (tenant_id, integration_id, kind, json.dumps(config, sort_keys=True), now),
            )
        return integration_id

    def list_integrations(self, *, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT integration_id, kind, config_json, created_at FROM integrations WHERE tenant_id=? ORDER BY integration_id",
            (tenant_id,),
        ).fetchall()
        return [
            {
                "integration_id": row["integration_id"],
                "kind": row["kind"],
                "config": json.loads(row["config_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def dashboard_summary(self, *, tenant_id: str) -> dict[str, Any]:
        devices = self.list_devices(tenant_id=tenant_id)
        decision_rows = self._conn.execute(
            """
            SELECT action, COUNT(*) AS count
            FROM decisions
            WHERE tenant_id=?
            GROUP BY action
            """,
            (tenant_id,),
        ).fetchall()
        latest_rows = self._conn.execute(
            """
            SELECT decision_json, received_at
            FROM decisions
            WHERE tenant_id=?
            ORDER BY id DESC
            LIMIT 25
            """,
            (tenant_id,),
        ).fetchall()
        metrics_row = self._conn.execute(
            """
            SELECT metrics_json, received_at
            FROM metrics
            WHERE tenant_id=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (tenant_id,),
        ).fetchone()
        return {
            "tenant_id": tenant_id,
            "device_count": len(devices),
            "devices": devices,
            "decisions_by_action": {row["action"]: row["count"] for row in decision_rows},
            "latest_decisions": [
                {"received_at": row["received_at"], "decision": json.loads(row["decision_json"])}
                for row in latest_rows
            ],
            "latest_metrics": json.loads(metrics_row["metrics_json"]) if metrics_row else None,
            "exporter_status": self.list_exporter_status(tenant_id=tenant_id),
            "integrations": self.list_integrations(tenant_id=tenant_id),
        }

    def _touch_device(self, tenant_id: str, device_id: str) -> None:
        self._conn.execute(
            "UPDATE devices SET last_seen_at=? WHERE tenant_id=? AND device_id=?",
            (_now(), tenant_id, device_id),
        )

    def _require_device(self, tenant_id: str, device_id: str) -> None:
        if self.get_device(tenant_id=tenant_id, device_id=device_id) is None:
            raise KeyError(f"unknown device {tenant_id}/{device_id}")

    @staticmethod
    def _validate_id(label: str, value: str) -> None:
        if not value or any(ch in value for ch in "/?#"):
            raise ConfigError(f"{label} must be non-empty and must not contain '/', '?', or '#'")
