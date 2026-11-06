"""Unit tests for Shield Supabase persistence bridge."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

from shield.backend.supabase_persistence import (
    checkpoint_database,
    get_configured_dsn,
    restore_database,
    start_periodic_checkpoint,
    stop_periodic_checkpoint,
)


def test_get_configured_dsn(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SHIELD_DATABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_DATABASE_URL", raising=False)
    monkeypatch.delenv("CORTEX_MANAGED_DATABASE_URL", raising=False)

    assert get_configured_dsn() is None

    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db")
    assert get_configured_dsn() == "postgresql://user:pass@localhost:5432/db"


def test_restore_database_success(tmp_path):
    target_db = tmp_path / "restored.sqlite3"
    fake_data = b"SQLite format 3\x00test-data"

    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = (fake_data, "2026-11-05T00:00:00Z")
    mock_conn = MagicMock()
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    with patch("psycopg.connect", return_value=mock_conn):
        restored = restore_database("postgresql://user:pass@localhost:5432/db", target_db)
        assert restored is True
        assert target_db.exists()
        assert target_db.read_bytes() == fake_data


def test_restore_database_not_found(tmp_path):
    target_db = tmp_path / "not_found.sqlite3"

    mock_cur = MagicMock()
    mock_cur.fetchone.return_value = None
    mock_conn = MagicMock()
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    with patch("psycopg.connect", return_value=mock_conn):
        restored = restore_database("postgresql://user:pass@localhost:5432/db", target_db)
        assert restored is False
        assert not target_db.exists()


def test_checkpoint_database_success(tmp_path):
    source_db = tmp_path / "source.sqlite3"
    with sqlite3.connect(source_db) as conn:
        conn.execute("CREATE TABLE test (id INT);")
        conn.commit()

    mock_cur = MagicMock()
    mock_conn = MagicMock()
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    with patch("psycopg.connect", return_value=mock_conn):
        saved = checkpoint_database("postgresql://user:pass@localhost:5432/db", source_db)
        assert saved is True
        assert mock_cur.execute.called
        assert mock_conn.commit.called


def test_periodic_checkpoint_lifecycle(tmp_path):
    source_db = tmp_path / "periodic.sqlite3"
    with sqlite3.connect(source_db) as conn:
        conn.execute("CREATE TABLE test (id INT);")
        conn.commit()

    with patch("psycopg.connect"):
        start_periodic_checkpoint("postgresql://user:pass@localhost:5432/db", source_db, interval=0.1)
        stop_periodic_checkpoint()
