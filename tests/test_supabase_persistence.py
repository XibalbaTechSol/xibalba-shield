"""Tests for the Shield Supabase persistence bridge.

Unit tests mock psycopg. The ownership tests at the bottom exercise the real compare-and-swap
against Postgres and run only when SHIELD_TEST_PG_DSN points at a disposable database.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shield.backend import supabase_persistence as sp


@pytest.fixture(autouse=True)
def _reset_superseded():
    sp._superseded = False
    sp._stop_event.clear()
    yield
    sp._superseded = False
    sp._stop_event.set()


def _mock_conn(cur: MagicMock) -> MagicMock:
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.cursor.return_value.__enter__.return_value = cur
    return conn


def _make_db(path: Path, marker: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS t (v TEXT)")
        conn.execute("DELETE FROM t")
        conn.execute("INSERT INTO t VALUES (?)", (marker,))
        conn.commit()


def _read_marker(path: Path) -> str:
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT v FROM t").fetchone()[0]


def test_get_configured_dsn(monkeypatch):
    for key in ("DATABASE_URL", "SHIELD_DATABASE_URL", "SUPABASE_DATABASE_URL", "CORTEX_MANAGED_DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)
    assert sp.get_configured_dsn() is None
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db")
    assert sp.get_configured_dsn() == "postgresql://user:pass@localhost:5432/db"


def test_restore_writes_snapshot_and_claims_ownership(tmp_path):
    target = tmp_path / "restored.sqlite3"
    cur = MagicMock()
    cur.fetchone.return_value = (b"SQLite format 3\x00data", "2026-11-05T00:00:00Z")
    with patch("psycopg.connect", return_value=_mock_conn(cur)):
        assert sp.restore_database("dsn", target, instance_id="me") is True
    assert target.read_bytes() == b"SQLite format 3\x00data"
    claim_sql, claim_params = cur.execute.call_args_list[-1].args
    assert "owner" in claim_sql and claim_params[1:] == ("me", "me")


def test_restore_without_snapshot_still_claims(tmp_path):
    target = tmp_path / "none.sqlite3"
    cur = MagicMock()
    cur.fetchone.return_value = None
    with patch("psycopg.connect", return_value=_mock_conn(cur)):
        assert sp.restore_database("dsn", target, instance_id="me") is False
    assert not target.exists()
    assert "INSERT INTO shield.system_state" in cur.execute.call_args_list[-1].args[0]


def test_checkpoint_is_conditional_on_owner(tmp_path):
    src = tmp_path / "src.sqlite3"
    _make_db(src, "a")
    cur = MagicMock()
    cur.rowcount = 1
    with patch("psycopg.connect", return_value=_mock_conn(cur)):
        assert sp.checkpoint_database("dsn", src, instance_id="me") is True
    sql, params = cur.execute.call_args.args
    assert "meta->>'owner' = %s" in sql and params[-1] == "me"


def test_superseded_checkpoint_stops_worker(tmp_path):
    src = tmp_path / "src.sqlite3"
    _make_db(src, "a")
    cur = MagicMock()
    cur.rowcount = 0
    with patch("psycopg.connect", return_value=_mock_conn(cur)) as connect:
        assert sp.checkpoint_database("dsn", src, instance_id="old") is False
        assert sp._superseded and sp._stop_event.is_set()
        # once superseded, no further connections are attempted
        assert sp.checkpoint_database("dsn", src, instance_id="old") is False
        assert connect.call_count == 1


PG_DSN = os.environ.get("SHIELD_TEST_PG_DSN")


@pytest.mark.skipif(not PG_DSN, reason="SHIELD_TEST_PG_DSN not set")
def test_old_instance_cannot_overwrite_new_instance(tmp_path):
    import psycopg

    with psycopg.connect(PG_DSN) as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS shield")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS shield.system_state (key TEXT PRIMARY KEY, data BYTEA, meta JSONB, updated_at TIMESTAMPTZ DEFAULT NOW())"
        )
        conn.execute("DELETE FROM shield.system_state WHERE key = %s", (sp.STATE_KEY,))
        conn.commit()

    old_db, new_db, probe = tmp_path / "old.sqlite3", tmp_path / "new.sqlite3", tmp_path / "probe.sqlite3"

    # old instance boots on an empty store and writes state
    sp.restore_database(PG_DSN, old_db, instance_id="old")
    _make_db(old_db, "old-1")
    assert sp.checkpoint_database(PG_DSN, old_db, instance_id="old") is True

    # new instance boots mid-deploy, restores old's state, and writes its own
    assert sp.restore_database(PG_DSN, new_db, instance_id="new") is True
    assert _read_marker(new_db) == "old-1"
    _make_db(new_db, "new-1")
    assert sp.checkpoint_database(PG_DSN, new_db, instance_id="new") is True

    # old instance's shutdown checkpoint must not clobber new's write
    _make_db(old_db, "old-2-stale")
    assert sp.checkpoint_database(PG_DSN, old_db, instance_id="old") is False

    sp._superseded = False
    sp.restore_database(PG_DSN, probe, instance_id="probe")
    assert _read_marker(probe) == "new-1"
