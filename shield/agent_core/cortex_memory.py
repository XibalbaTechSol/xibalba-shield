"""Optional redacted Cortex memory provider for Shield's hybrid agent path."""

from __future__ import annotations

import json
import os
import sqlite3
import hashlib
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..codex_agent import redact_event


class CortexMemoryProvider:
    """Best-effort cloud-memory sink; local Shield policy remains authoritative."""

    def __init__(self, *, base_url: str, token: str, agent_id: str, device_id: str, timeout: float = 3.0, outbox_path: str | Path | None = None, max_attempts: int = 8):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.agent_id = agent_id
        self.device_id = device_id
        self.timeout = timeout
        self.max_attempts = max(1, int(max_attempts))
        self.outbox_path = Path(outbox_path or os.environ.get("XIBALBA_CORTEX_OUTBOX", "/var/lib/xibalba-shield/cortex/outbox.sqlite3"))
        self._init_outbox()

    @classmethod
    def from_environment(cls, *, device_id: str, agent_id: str | None = None, base_url: str | None = None, token: str | None = None) -> "CortexMemoryProvider | None":
        base_url = (base_url or os.environ.get("XIBALBA_CORTEX_URL", "")).strip()
        token = (token or os.environ.get("XIBALBA_CORTEX_TOKEN", "")).strip()
        canonical_agent_id = (agent_id or os.environ.get("XIBALBA_AGENT_ID", "")).strip()
        if not (base_url and token and canonical_agent_id):
            return None
        return cls(base_url=base_url, token=token, agent_id=canonical_agent_id, device_id=device_id, outbox_path=os.environ.get("XIBALBA_CORTEX_OUTBOX"))

    def _connect_outbox(self) -> sqlite3.Connection:
        self.outbox_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.outbox_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _init_outbox(self) -> None:
        with self._connect_outbox() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS cortex_outbox (id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending', last_error TEXT, created_at REAL NOT NULL, sent_at REAL)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cortex_outbox_pending ON cortex_outbox(status, next_attempt_at)")
            conn.execute("CREATE TABLE IF NOT EXISTS cortex_outbox_metrics (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0)")

    @staticmethod
    def _allowlisted_event(event: dict[str, Any]) -> dict[str, Any]:
        allowed = {"class", "event_id", "device_id", "tenant_id", "time", "activity", "process", "agent", "context", "decision"}
        process_allowed = {"name", "exe_path", "hash_sha256", "pid", "ppid", "parent_name"}
        result = {key: event[key] for key in allowed if key in event}
        if isinstance(result.get("process"), dict):
            result["process"] = {key: result["process"][key] for key in process_allowed if key in result["process"]}
        return result

    def _enqueue(self, payload: dict[str, Any], event_id: str) -> None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._connect_outbox() as conn:
            conn.execute("INSERT OR IGNORE INTO cortex_outbox(id,payload_json,created_at) VALUES(?,?,?)", (event_id, encoded, time.time()))

    def _publish(self, row: sqlite3.Row) -> bool:
        request = urllib.request.Request(
            f"{self.base_url}/api/memory/propositions",
            data=row["payload_json"].encode("utf-8"),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout):
                pass
        except Exception as exc:  # noqa: BLE001 -- durable retry boundary
            attempts = int(row["attempts"]) + 1
            status = "dead_letter" if attempts >= self.max_attempts else "pending"
            with self._connect_outbox() as conn:
                conn.execute("UPDATE cortex_outbox SET attempts=?, next_attempt_at=?, status=?, last_error=? WHERE id=?", (attempts, time.time() + min(300, 2 ** min(attempts, 8)), status, str(exc)[:500], row["id"]))
                if status == "dead_letter":
                    conn.execute("INSERT INTO cortex_outbox_metrics(name,value) VALUES('dead_letter_total',1) ON CONFLICT(name) DO UPDATE SET value=value+1")
            return False
        with self._connect_outbox() as conn:
            conn.execute("UPDATE cortex_outbox SET status='sent', sent_at=? WHERE id=?", (time.time(), row["id"]))
            conn.execute("INSERT INTO cortex_outbox_metrics(name,value) VALUES('delivered_total',1) ON CONFLICT(name) DO UPDATE SET value=value+1")
        return True

    def flush(self, *, limit: int = 20) -> dict[str, int]:
        now = time.time()
        with self._connect_outbox() as conn:
            rows = conn.execute("SELECT * FROM cortex_outbox WHERE status='pending' AND next_attempt_at <= ? ORDER BY created_at LIMIT ?", (now, max(1, min(int(limit), 1000)))).fetchall()
        workers = max(1, min(int(os.environ.get("XIBALBA_CORTEX_OUTBOX_WORKERS", "1")), 32))
        if workers == 1 or len(rows) < 2:
            delivered = sum(1 for row in rows if self._publish(row))
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cortex-outbox") as pool:
                delivered = sum(pool.map(self._publish, rows))
        with self._connect_outbox() as conn:
            pending = conn.execute("SELECT COUNT(*) FROM cortex_outbox WHERE status='pending'").fetchone()[0]
            dead = conn.execute("SELECT COUNT(*) FROM cortex_outbox WHERE status='dead_letter'").fetchone()[0]
        return {"attempted": len(rows), "delivered": delivered, "pending": pending, "dead_letter": dead}

    def metrics(self) -> dict[str, int]:
        with self._connect_outbox() as conn:
            return {row["name"]: int(row["value"]) for row in conn.execute("SELECT name,value FROM cortex_outbox_metrics")}

    def status(self) -> dict[str, int]:
        """Return durable queue depth plus cumulative delivery/loss counters."""
        with self._connect_outbox() as conn:
            counts = {
                row["status"]: int(row["count"])
                for row in conn.execute("SELECT status, COUNT(*) AS count FROM cortex_outbox GROUP BY status")
            }
        return {
            "pending": counts.get("pending", 0),
            "sent": counts.get("sent", 0),
            "dead_letter": counts.get("dead_letter", 0),
            **self.metrics(),
        }

    def remember_event(self, event: Any, decision: Any) -> None:
        raw_event = event.to_dict() if hasattr(event, "to_dict") else (event if isinstance(event, dict) else {"class": type(event).__name__})
        safe_event = redact_event(self._allowlisted_event(raw_event))
        decision_payload = decision.to_dict() if hasattr(decision, "to_dict") else (decision if isinstance(decision, dict) else {})
        safe_decision = redact_event(self._allowlisted_event(decision_payload if isinstance(decision_payload, dict) else {}))
        content_payload = {"event": safe_event, "decision": safe_decision}
        content = json.dumps(content_payload, sort_keys=True, separators=(",", ":"))
        redaction_proof = hashlib.sha256(content.encode("utf-8")).hexdigest()
        event_id = str(getattr(getattr(decision, "event_ref", None), "event_id", id(event)))
        payload = {
            "content": content,
            "source": {
                "kind": "shield_event",
                "locator": f"shield://{self.device_id}/{getattr(getattr(decision, 'event_ref', None), 'event_id', 'event')}",
                "agent_id": self.agent_id,
                "metadata": {"device_id": self.device_id, "agent_name": "xibalba-shield", "redaction_version": "allowlist-v1", "redaction_proof": redaction_proof},
            },
            "status": "candidate",
            "evidence_class": "observed_event",
            "idempotency_key": f"shield:{self.device_id}:{event_id}",
        }
        self._enqueue(payload, f"shield:{self.device_id}:{event_id}")
        self.flush(limit=20)


__all__ = ["CortexMemoryProvider"]
