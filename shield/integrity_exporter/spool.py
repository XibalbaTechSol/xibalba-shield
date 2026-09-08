"""Durable local spool for `IntegrityExporter.export_decision` — closes the
audit-report-loss-on-outage gap for Shield's BCC-commitment export path
(`docs/PRODUCTION_READINESS_PLAN.md` §7 item 4, Gate 4 — Evidence continuity).

Mirrors `integrity-core/bcc_middleware/app/spool.py`'s design deliberately, for
consistency across the two products rather than inventing a second spool shape:
a single SQLite file, write-AFTER-failure (not write-ahead of the network call, so a
successful submission never touches disk at all), and a periodic retry cycle with
capped exponential backoff. Single-process/single-device scope, same disclosed
limitation as the parent repo's version — a multi-device fleet needs a shared queue,
not N independent SQLite files, if central visibility into pending spool state across
a fleet is ever required.

What gets spooled is the already-built, already-signed BCC commitment dict, not the
raw decision — `export_decision` calls `bcc.build_bcc_commitment` (which consumes a
local monotonic nonce) exactly once, before attempting submission; replaying the
identical signed commitment later needs no new nonce and no re-signing. The retry
cycle's delivery semantics: `bcc.submit_commitment` raises only on a network/HTTP
failure (per `integrity_sdk.bcc`'s own source — a 200 response is returned as a plain
dict regardless of its `authorized` verdict, including a `BCC_NONCE_REPLAY` denial for
a commitment `bcc_middleware` already recorded). So "delivered" here means "the call
returned without raising," irrespective of the returned verdict — the spool's job is
guaranteeing the evidence reaches `bcc_middleware` at least once, not re-litigating
what it decided.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("shield.integrity_exporter.spool")

_DEFAULT_BACKOFF_BASE_SECONDS = 30.0
_DEFAULT_MAX_BACKOFF_SECONDS = 3600.0


def _connect(db_path: Path | str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(
        """CREATE TABLE IF NOT EXISTS spool (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            next_retry_at REAL NOT NULL,
            last_error TEXT
        )"""
    )
    return conn


def _backoff_seconds(
    attempts: int,
    *,
    base: float = _DEFAULT_BACKOFF_BASE_SECONDS,
    max_backoff: float = _DEFAULT_MAX_BACKOFF_SECONDS,
) -> float:
    return min(max_backoff, base * (2 ** max(0, attempts - 1)))


def enqueue(db_path: Path | str, *, kind: str, payload: dict[str, Any], error: str) -> None:
    """Best-effort: if the local write itself fails (disk full, permissions), the
    record is lost with a logged error, same disclosed limitation as the parent
    repo's version -- there is no second fallback spool."""
    try:
        conn = _connect(db_path)
        now = time.time()
        conn.execute(
            "INSERT INTO spool (kind, payload_json, attempts, created_at, next_retry_at, last_error) "
            "VALUES (?, ?, 0, ?, ?, ?)",
            (kind, json.dumps(payload), now, now, error),
        )
        conn.commit()
        conn.close()
    except Exception:  # noqa: BLE001 - logging the loss is the whole point here
        logger.exception("failed to spool undelivered %s export to %s -- evidence lost", kind, db_path)


@dataclass
class RetryCycleResult:
    delivered: int
    still_pending: int


def run_retry_cycle(
    db_path: Path | str,
    submit: Callable[[dict[str, Any]], Any],
    *,
    now: float | None = None,
) -> RetryCycleResult:
    """Attempts every due row once. `submit` should raise on delivery failure and
    return (anything, ignored) on a completed round-trip -- see module docstring for
    why a completed round-trip is "delivered" regardless of its verdict."""
    if not Path(db_path).exists():
        return RetryCycleResult(delivered=0, still_pending=0)

    now = now if now is not None else time.time()
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT id, payload_json, attempts FROM spool WHERE next_retry_at <= ? ORDER BY id", (now,)
    ).fetchall()

    delivered = 0
    still_pending = 0
    for row_id, payload_json, attempts in rows:
        payload = json.loads(payload_json)
        try:
            submit(payload)
        except Exception as exc:  # noqa: BLE001 - a retry failure just reschedules, never raises out
            new_attempts = attempts + 1
            conn.execute(
                "UPDATE spool SET attempts = ?, next_retry_at = ?, last_error = ? WHERE id = ?",
                (new_attempts, now + _backoff_seconds(new_attempts), str(exc), row_id),
            )
            still_pending += 1
        else:
            conn.execute("DELETE FROM spool WHERE id = ?", (row_id,))
            delivered += 1
    conn.commit()
    conn.close()
    return RetryCycleResult(delivered=delivered, still_pending=still_pending)


def status(db_path: Path | str) -> dict[str, Any]:
    if not Path(db_path).exists():
        return {"pending": 0, "oldest_age_seconds": None}
    conn = _connect(db_path)
    count, oldest = conn.execute("SELECT COUNT(*), MIN(created_at) FROM spool").fetchone()
    conn.close()
    if not count:
        return {"pending": 0, "oldest_age_seconds": None}
    return {"pending": count, "oldest_age_seconds": time.time() - oldest}
