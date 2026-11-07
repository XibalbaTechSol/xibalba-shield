"""Persistence for EDR response governance: intents, approvals, and a hash-chained ledger.

State machine for one response intent (keyed by intent hash, scoped to a tenant)::

    allow    -> allowed  -> consumed -> executed | failed
    escalate -> pending  -> approved -> consumed -> executed | failed
                pending  -> denied
    allowed | pending | approved -> expired      (decision TTL elapsed before consume)
    deny     -> denied

Every transition appends a row to ``response_events``. Each row carries the SHA-256 of the
previous row for the same tenant, so editing or deleting history is detectable with
:meth:`ResponseLedgerStore.verify_chain`. The local chain is tamper-*evident*, not
tamper-proof against an attacker with database write access; export to the Integrity
Protocol is the off-host evidence path.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from ..canonical import canonical_bytes
from ..edr.provider import ExecutionAuthorization

GENESIS = "sha256:" + "0" * 64
_CONSUMABLE = ("allowed", "approved")
_OPEN = ("allowed", "pending", "approved")
_TERMINAL_RESULTS = {"succeeded": "executed", "pending": "executed", "failed": "failed"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS response_intents (
    intent_hash TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    vendor TEXT NOT NULL,
    host_id TEXT NOT NULL,
    action TEXT NOT NULL,
    intent_json TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, intent_hash),
    UNIQUE (tenant_id, request_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS response_intents_status ON response_intents(tenant_id, status, created_at);

CREATE TABLE IF NOT EXISTS response_approvals (
    approval_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('approve', 'deny')),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    UNIQUE (tenant_id, intent_hash, approver_id),
    FOREIGN KEY (tenant_id, intent_hash) REFERENCES response_intents(tenant_id, intent_hash) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS response_events (
    tenant_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    intent_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, seq),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS response_events_intent ON response_events(tenant_id, intent_hash, seq);
"""


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def event_hash(*, tenant_id: str, seq: int, intent_hash: str, event_type: str, payload: dict[str, Any], prev_hash: str, created_at: str) -> str:
    body = {
        "tenant_id": tenant_id,
        "seq": seq,
        "intent_hash": intent_hash,
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev_hash,
        "created_at": created_at,
    }
    return "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


class ResponseLedgerStore:
    """Operates on the ShieldStore connection; callers pass ``now`` only in tests."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def init_schema(self) -> None:
        self._conn.executescript(SCHEMA)

    # -- writes ------------------------------------------------------------------------

    def record_intent(self, *, intent: dict[str, Any], decision: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
        """Persist a decided intent. Idempotent per (tenant, request_id) for the same intent."""
        now = now or datetime.now(timezone.utc)
        tenant_id = str(intent["tenant_id"])
        intent_hash = str(decision["intent_hash"])
        verdict = decision.get("action")
        status = {"allow": "allowed", "escalate": "pending", "deny": "denied"}.get(verdict)
        if status is None:
            raise ValueError("decision action must be allow, deny, or escalate")
        if decision.get("intent") != intent:
            raise ValueError("decision is not bound to this intent")
        with self._conn:
            self._require_tenant(tenant_id)
            existing = self._conn.execute(
                "SELECT intent_hash FROM response_intents WHERE tenant_id=? AND request_id=?",
                (tenant_id, intent["request_id"]),
            ).fetchone()
            if existing:
                if existing["intent_hash"] != intent_hash:
                    raise ValueError("request_id was already used for a different intent")
                return self._row(tenant_id, intent_hash)
            stamp = _iso(now)
            expires = _iso(now + timedelta(seconds=int(decision.get("approval_ttl_seconds") or 0)))
            self._conn.execute(
                """
                INSERT INTO response_intents
                    (intent_hash, tenant_id, request_id, actor_type, actor_id, vendor, host_id, action,
                     intent_json, decision_json, status, expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    intent_hash, tenant_id, intent["request_id"], intent["actor_type"], intent["actor_id"],
                    intent["vendor"], intent["host_id"], intent["action"],
                    json.dumps(intent, sort_keys=True), json.dumps(decision, sort_keys=True),
                    status, expires, stamp, stamp,
                ),
            )
            self._append(tenant_id, intent_hash, "decided", {
                "decision": verdict,
                "rule_id": decision.get("rule_id"),
                "policy_version": decision.get("policy_version"),
                "required_approvals": decision.get("required_approvals", 0),
                "actor_type": intent["actor_type"],
                "actor_id": intent["actor_id"],
                "action": intent["action"],
                "host_id": intent["host_id"],
                "vendor": intent["vendor"],
            }, stamp)
            return self._row(tenant_id, intent_hash)

    def record_approval(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        approver_id: str,
        verdict: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        approver_id = str(approver_id or "").strip()
        reason = str(reason or "").strip()
        if verdict not in ("approve", "deny"):
            raise ValueError("verdict must be approve or deny")
        if not approver_id:
            raise ValueError("approver_id is required")
        if not reason:
            raise ValueError("a reason is required for every approval decision")
        self._expire_one(tenant_id, intent_hash, now)
        with self._conn:
            row = self._get(tenant_id, intent_hash)
            if row["status"] != "pending":
                raise ValueError(f"intent is {row['status']}, not pending")
            if approver_id == row["actor_id"]:
                raise PermissionError("an actor cannot approve or deny its own intent")
            stamp = _iso(now)
            try:
                self._conn.execute(
                    "INSERT INTO response_approvals (approval_id, tenant_id, intent_hash, approver_id, verdict, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ("rapproval-" + secrets.token_hex(12), tenant_id, intent_hash, approver_id, verdict, reason, stamp),
                )
            except Exception as exc:  # sqlite3.IntegrityError on the unique approver constraint
                if "UNIQUE" in str(exc):
                    raise ValueError("this approver has already recorded a decision") from exc
                raise
            decision = json.loads(row["decision_json"])
            if verdict == "deny":
                new_status = "denied"
            else:
                count = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM response_approvals WHERE tenant_id=? AND intent_hash=? AND verdict='approve'",
                    (tenant_id, intent_hash),
                ).fetchone()["n"]
                new_status = "approved" if count >= int(decision.get("required_approvals") or 1) else "pending"
            self._set_status(tenant_id, intent_hash, new_status, stamp)
            self._append(tenant_id, intent_hash, "approval_recorded", {
                "approver_id": approver_id, "verdict": verdict, "reason": reason, "status": new_status,
            }, stamp)
            return self._row(tenant_id, intent_hash)

    def consume(self, *, tenant_id: str, intent_hash: str, now: datetime | None = None) -> ExecutionAuthorization:
        """Atomically claim the right to execute an intent exactly once."""
        now = now or datetime.now(timezone.utc)
        self._expire_one(tenant_id, intent_hash, now)
        with self._conn:
            row = self._get(tenant_id, intent_hash)
            if row["status"] not in _CONSUMABLE:
                raise ValueError(f"intent is {row['status']}; only allowed or approved intents can be consumed")
            stamp = _iso(now)
            updated = self._conn.execute(
                "UPDATE response_intents SET status='consumed', updated_at=? WHERE tenant_id=? AND intent_hash=? AND status IN ('allowed', 'approved')",
                (stamp, tenant_id, intent_hash),
            )
            if updated.rowcount != 1:
                raise ValueError("intent was consumed concurrently")
            self._conn.execute(
                "UPDATE response_approvals SET consumed_at=? WHERE tenant_id=? AND intent_hash=? AND verdict='approve'",
                (stamp, tenant_id, intent_hash),
            )
            approvals = self._approvals(tenant_id, intent_hash)
            self._append(tenant_id, intent_hash, "consumed", {
                "approvers": [a["approver_id"] for a in approvals if a["verdict"] == "approve"],
            }, stamp)
        return ExecutionAuthorization(
            intent_hash=intent_hash,
            decision=json.loads(row["decision_json"]),
            approvals=tuple({**a, "intent_hash": intent_hash} for a in approvals),
            consumed_at=stamp,
        )

    def record_result(self, *, tenant_id: str, intent_hash: str, result: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        new_status = _TERMINAL_RESULTS.get(str(result.get("status")))
        if new_status is None:
            raise ValueError("result status must be succeeded, pending, or failed")
        with self._conn:
            row = self._get(tenant_id, intent_hash)
            if row["status"] != "consumed":
                raise ValueError(f"intent is {row['status']}; results are recorded only after consume")
            stamp = _iso(now)
            self._conn.execute(
                "UPDATE response_intents SET status=?, result_json=?, updated_at=? WHERE tenant_id=? AND intent_hash=?",
                (new_status, json.dumps(result, sort_keys=True), stamp, tenant_id, intent_hash),
            )
            self._append(tenant_id, intent_hash, new_status, {"result": result}, stamp)
            return self._row(tenant_id, intent_hash)

    def expire_due(self, *, tenant_id: str, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        with self._conn:
            rows = self._conn.execute(
                f"SELECT * FROM response_intents WHERE tenant_id=? AND status IN ({','.join('?' * len(_OPEN))}) AND expires_at<=?",
                (tenant_id, *_OPEN, _iso(now)),
            ).fetchall()
            for row in rows:
                self._expire_if_due(row, now)
        return len(rows)

    # -- reads -------------------------------------------------------------------------

    def list_intents(
        self, *, tenant_id: str, statuses: list[str] | None = None, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        sql = "SELECT * FROM response_intents WHERE tenant_id=?"
        args: list[Any] = [tenant_id]
        if statuses:
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            args.extend(statuses)
        sql += " ORDER BY created_at DESC, intent_hash LIMIT ? OFFSET ?"
        args.extend([limit, offset])
        return [self._public(r) for r in self._conn.execute(sql, args).fetchall()]

    def chain(self, *, tenant_id: str, intent_hash: str) -> dict[str, Any]:
        row = self._get(tenant_id, intent_hash)
        events = self._conn.execute(
            "SELECT seq, event_type, payload_json, prev_hash, event_hash, created_at FROM response_events WHERE tenant_id=? AND intent_hash=? ORDER BY seq",
            (tenant_id, intent_hash),
        ).fetchall()
        return {
            **self._public(row),
            "approvals": self._approvals(tenant_id, intent_hash),
            "events": [
                {**{k: e[k] for k in ("seq", "event_type", "prev_hash", "event_hash", "created_at")}, "payload": json.loads(e["payload_json"])}
                for e in events
            ],
        }

    def verify_chain(self, *, tenant_id: str) -> dict[str, Any]:
        prev = GENESIS
        count = 0
        for e in self._conn.execute("SELECT * FROM response_events WHERE tenant_id=? ORDER BY seq", (tenant_id,)):
            count += 1
            if e["seq"] != count:
                return {"valid": False, "events": count, "broken_at": e["seq"], "reason": "sequence gap"}
            if e["prev_hash"] != prev:
                return {"valid": False, "events": count, "broken_at": e["seq"], "reason": "prev_hash mismatch"}
            expected = event_hash(
                tenant_id=tenant_id, seq=e["seq"], intent_hash=e["intent_hash"], event_type=e["event_type"],
                payload=json.loads(e["payload_json"]), prev_hash=e["prev_hash"], created_at=e["created_at"],
            )
            if expected != e["event_hash"]:
                return {"valid": False, "events": count, "broken_at": e["seq"], "reason": "event_hash mismatch"}
            prev = e["event_hash"]
        return {"valid": True, "events": count, "head": prev}

    # -- internals ---------------------------------------------------------------------

    def _require_tenant(self, tenant_id: str) -> None:
        if not self._conn.execute("SELECT 1 FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone():
            raise KeyError(f"unknown tenant {tenant_id}")

    def _get(self, tenant_id: str, intent_hash: str) -> Any:
        row = self._conn.execute(
            "SELECT * FROM response_intents WHERE tenant_id=? AND intent_hash=?", (tenant_id, intent_hash)
        ).fetchone()
        if not row:
            raise KeyError("response intent not found")
        return row

    def _row(self, tenant_id: str, intent_hash: str) -> dict[str, Any]:
        return self._public(self._get(tenant_id, intent_hash))

    @staticmethod
    def _public(row: Any) -> dict[str, Any]:
        return {
            "intent_hash": row["intent_hash"],
            "tenant_id": row["tenant_id"],
            "request_id": row["request_id"],
            "status": row["status"],
            "intent": json.loads(row["intent_json"]),
            "decision": json.loads(row["decision_json"]),
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _approvals(self, tenant_id: str, intent_hash: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT approval_id, approver_id, verdict, reason, created_at, consumed_at FROM response_approvals WHERE tenant_id=? AND intent_hash=? ORDER BY created_at, approval_id",
            (tenant_id, intent_hash),
        ).fetchall()
        return [dict(r) for r in rows]

    def _set_status(self, tenant_id: str, intent_hash: str, status: str, stamp: str) -> None:
        self._conn.execute(
            "UPDATE response_intents SET status=?, updated_at=? WHERE tenant_id=? AND intent_hash=?",
            (status, stamp, tenant_id, intent_hash),
        )

    def _expire_one(self, tenant_id: str, intent_hash: str, now: datetime) -> None:
        """Persist expiry in its own transaction so a later refusal cannot roll it back."""
        with self._conn:
            self._expire_if_due(self._get(tenant_id, intent_hash), now)

    def _expire_if_due(self, row: Any, now: datetime) -> None:
        if row["status"] in _OPEN and _parse(row["expires_at"]) <= now:
            stamp = _iso(now)
            self._set_status(row["tenant_id"], row["intent_hash"], "expired", stamp)
            self._append(row["tenant_id"], row["intent_hash"], "expired", {"previous_status": row["status"]}, stamp)

    def _append(self, tenant_id: str, intent_hash: str, event_type: str, payload: dict[str, Any], stamp: str) -> None:
        head = self._conn.execute(
            "SELECT seq, event_hash FROM response_events WHERE tenant_id=? ORDER BY seq DESC LIMIT 1", (tenant_id,)
        ).fetchone()
        seq = (head["seq"] + 1) if head else 1
        prev = head["event_hash"] if head else GENESIS
        digest = event_hash(
            tenant_id=tenant_id, seq=seq, intent_hash=intent_hash, event_type=event_type,
            payload=payload, prev_hash=prev, created_at=stamp,
        )
        self._conn.execute(
            "INSERT INTO response_events (tenant_id, seq, intent_hash, event_type, payload_json, prev_hash, event_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, seq, intent_hash, event_type, json.dumps(payload, sort_keys=True), prev, digest, stamp),
        )


__all__ = ["GENESIS", "ResponseLedgerStore", "event_hash"]
