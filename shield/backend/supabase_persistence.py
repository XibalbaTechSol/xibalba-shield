"""Supabase state persistence bridge for Xibalba Shield.

Provides zero-data-loss durability for Shield on ephemeral container platforms (e.g. Render).
On boot, pulls the latest consistent database snapshot from the Supabase PostgreSQL
`shield.system_state` table into the local SQLite file.
Periodically and on shutdown, checkpoints the SQLite state back to Supabase.
"""
from __future__ import annotations

import atexit
import logging
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import threading
import time
from typing import Any

logger = logging.getLogger("xibalba.shield.supabase_persistence")

_stop_event = threading.Event()
_checkpoint_thread: threading.Thread | None = None
_last_checkpoint_hash: str | None = None


def get_configured_dsn() -> str | None:
    """Return the configured Supabase/PostgreSQL DSN if present in environment."""
    for key in ("DATABASE_URL", "SHIELD_DATABASE_URL", "SUPABASE_DATABASE_URL", "CORTEX_MANAGED_DATABASE_URL"):
        val = str(os.environ.get(key, "")).strip()
        if val:
            return val
    return None


def restore_database(dsn: str, db_path: Path) -> bool:
    """Restore the latest SQLite database snapshot from Supabase into db_path.

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
                    "SELECT data, updated_at FROM shield.system_state WHERE key = 'backend.sqlite3'"
                )
                row = cur.fetchone()
                if row and row[0]:
                    data = bytes(row[0])
                    db_path.parent.mkdir(parents=True, exist_ok=True)
                    # Write to a sibling temp file and atomic rename
                    with tempfile.NamedTemporaryFile(dir=db_path.parent, delete=False) as tmp:
                        tmp.write(data)
                        tmp_path = Path(tmp.name)
                    tmp_path.replace(db_path)
                    logger.info("Restored Shield SQLite snapshot from Supabase (%d bytes, updated_at: %s)", len(data), row[1])
                    return True
                logger.info("No existing Shield database snapshot found in Supabase shield.system_state")
                return False
    except Exception as exc:
        logger.warning("Failed to restore Shield database from Supabase: %s", exc)
        return False


def checkpoint_database(dsn: str, db_path: Path, meta: dict[str, Any] | None = None) -> bool:
    """Save a consistent snapshot of the local SQLite database into Supabase shield.system_state."""
    if not db_path.exists():
        return False

    try:
        import psycopg
        import json
    except ImportError:
        logger.warning("psycopg is not installed; cannot checkpoint to Supabase")
        return False

    # Extract a hot backup via SQLite online backup API to ensure transaction consistency
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        dst = sqlite3.connect(str(tmp_path))
        src.backup(dst)
        dst.close()
        src.close()

        data = tmp_path.read_bytes()
        if not data:
            return False

        meta_json = json.dumps(meta or {"source": "shield-backend"})

        with psycopg.connect(dsn, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO shield.system_state (key, data, meta, updated_at)
                    VALUES ('backend.sqlite3', %s, %s, NOW())
                    ON CONFLICT (key) DO UPDATE
                    SET data = EXCLUDED.data, meta = EXCLUDED.meta, updated_at = NOW();
                    """,
                    (data, meta_json),
                )
            conn.commit()

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
    global _checkpoint_thread, _stop_event

    if _checkpoint_thread is not None and _checkpoint_thread.is_alive():
        return

    _stop_event.clear()

    def _worker():
        logger.info("Started Supabase persistence background checkpoint worker (interval: %.1fs)", interval)
        while not _stop_event.wait(interval):
            checkpoint_database(dsn, db_path, meta={"trigger": "periodic"})

    _checkpoint_thread = threading.Thread(target=_worker, name="ShieldSupabaseCheckpoint", daemon=True)
    _checkpoint_thread.start()

    def _on_shutdown(*args):
        logger.info("Executing final Shield database checkpoint to Supabase before shutdown...")
        checkpoint_database(dsn, db_path, meta={"trigger": "shutdown"})

    atexit.register(_on_shutdown)
    try:
        signal.signal(signal.SIGTERM, lambda s, f: (_on_shutdown(), signal.default_int_handler(s, f)))
    except (ValueError, AttributeError):
        pass


def stop_periodic_checkpoint() -> None:
    """Signal background checkpoint thread to terminate."""
    global _stop_event
    _stop_event.set()
