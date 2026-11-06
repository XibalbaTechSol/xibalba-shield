"""Supabase state persistence bridge for Xibalba Shield.

Provides durability for Shield on ephemeral container platforms (e.g. Render).
On boot, pulls the latest database snapshot from the Supabase PostgreSQL
`shield.system_state` table into the local SQLite file and *claims ownership* of it.
Periodically and on shutdown, checkpoints the SQLite state back to Supabase -- but only
while this process still owns the snapshot.

Why ownership: a zero-downtime deploy runs the old and new instance side by side. Without a
guard, the old instance's shutdown checkpoint lands *after* the new instance booted and
overwrites everything the new instance has written since. Each process therefore generates
an instance id, stamps it into `meta.owner` atomically with the restore (row lock), and every
checkpoint is a compare-and-swap on that owner. A superseded instance's write matches zero
rows, is logged, and the checkpoint worker stops.
"""
from __future__ import annotations

import atexit
import json
import logging
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import threading
import uuid
from typing import Any

logger = logging.getLogger("xibalba.shield.supabase_persistence")

STATE_KEY = "backend.sqlite3"
INSTANCE_ID = uuid.uuid4().hex

_stop_event = threading.Event()
_checkpoint_thread: threading.Thread | None = None
_superseded = False


def get_configured_dsn() -> str | None:
    """Return the configured Supabase/PostgreSQL DSN if present in environment."""
    for key in ("DATABASE_URL", "SHIELD_DATABASE_URL", "SUPABASE_DATABASE_URL", "CORTEX_MANAGED_DATABASE_URL"):
        val = str(os.environ.get(key, "")).strip()
        if val:
            return val
    return None


def restore_database(dsn: str, db_path: Path, *, instance_id: str = INSTANCE_ID) -> bool:
    """Restore the latest snapshot into db_path and claim ownership of the row.

    The read and the ownership claim happen in one transaction under a row lock, so no other
    instance can checkpoint between "what I restored" and "I own it". If no row exists yet, an
    empty owned row is created so this instance's first checkpoint succeeds.

    Returns True if a snapshot was found and restored, False otherwise.
    """
    try:
        import psycopg
    except ImportError:
        logger.warning("psycopg is not installed; cannot restore from Supabase")
        return False

    try:
        with psycopg.connect(dsn, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT data, updated_at FROM shield.system_state WHERE key = %s FOR UPDATE",
                    (STATE_KEY,),
                )
                row = cur.fetchone()
                restored = False
                if row and row[0]:
                    data = bytes(row[0])
                    db_path.parent.mkdir(parents=True, exist_ok=True)
                    with tempfile.NamedTemporaryFile(dir=db_path.parent, delete=False) as tmp:
                        tmp.write(data)
                        tmp_path = Path(tmp.name)
                    tmp_path.replace(db_path)
                    logger.info("Restored Shield SQLite snapshot from Supabase (%d bytes, updated_at: %s)", len(data), row[1])
                    restored = True
                else:
                    logger.info("No existing Shield database snapshot found in Supabase shield.system_state")
                cur.execute(
                    """
                    INSERT INTO shield.system_state (key, data, meta, updated_at)
                    VALUES (%s, NULL, jsonb_build_object('owner', %s::text), NOW())
                    ON CONFLICT (key) DO UPDATE
                    SET meta = COALESCE(shield.system_state.meta, '{}'::jsonb) || jsonb_build_object('owner', %s::text)
                    """,
                    (STATE_KEY, instance_id, instance_id),
                )
            conn.commit()
        return restored
    except Exception as exc:
        logger.warning("Failed to restore Shield database from Supabase: %s", exc)
        return False


def checkpoint_database(
    dsn: str,
    db_path: Path,
    meta: dict[str, Any] | None = None,
    *,
    instance_id: str = INSTANCE_ID,
) -> bool:
    """Save a consistent snapshot into Supabase, only if this instance still owns the row."""
    global _superseded
    if _superseded or not db_path.exists():
        return False

    try:
        import psycopg
    except ImportError:
        logger.warning("psycopg is not installed; cannot checkpoint to Supabase")
        return False

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        # SQLite online backup API: a transaction-consistent copy of a live database.
        src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        dst = sqlite3.connect(str(tmp_path))
        src.backup(dst)
        dst.close()
        src.close()

        data = tmp_path.read_bytes()
        if not data:
            return False

        meta_json = json.dumps({**(meta or {"source": "shield-backend"}), "owner": instance_id})

        with psycopg.connect(dsn, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE shield.system_state
                    SET data = %s, meta = %s::jsonb, updated_at = NOW()
                    WHERE key = %s AND meta->>'owner' = %s
                    """,
                    (data, meta_json, STATE_KEY, instance_id),
                )
                written = cur.rowcount
            conn.commit()

        if not written:
            _superseded = True
            _stop_event.set()
            logger.warning(
                "Shield snapshot is owned by a newer instance; skipping checkpoint and stopping the worker (instance %s)",
                instance_id,
            )
            return False

        logger.info("Checkpointed Shield database snapshot to Supabase (%d bytes)", len(data))
        return True
    except Exception as exc:
        logger.warning("Failed to checkpoint Shield database to Supabase: %s", exc)
        return False
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def start_periodic_checkpoint(dsn: str, db_path: Path, interval: float = 30.0) -> None:
    """Start background periodic checkpoint worker and shutdown handlers."""
    global _checkpoint_thread

    if _checkpoint_thread is not None and _checkpoint_thread.is_alive():
        return

    _stop_event.clear()

    def _worker():
        logger.info("Started Supabase persistence checkpoint worker (interval: %.1fs, instance %s)", interval, INSTANCE_ID)
        while not _stop_event.wait(interval):
            checkpoint_database(dsn, db_path, meta={"trigger": "periodic"})

    _checkpoint_thread = threading.Thread(target=_worker, name="ShieldSupabaseCheckpoint", daemon=True)
    _checkpoint_thread.start()

    def _on_shutdown(*_args):
        checkpoint_database(dsn, db_path, meta={"trigger": "shutdown"})

    atexit.register(_on_shutdown)
    try:
        previous = signal.getsignal(signal.SIGTERM)

        def _sigterm(signum, frame):
            _on_shutdown()
            if callable(previous):
                previous(signum, frame)
            else:
                raise SystemExit(0)

        signal.signal(signal.SIGTERM, _sigterm)
    except (ValueError, AttributeError):
        pass


def stop_periodic_checkpoint() -> None:
    """Signal background checkpoint thread to terminate."""
    _stop_event.set()
