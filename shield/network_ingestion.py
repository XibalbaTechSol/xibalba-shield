"""Bounded local ingestion for redacted network telemetry."""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .hermes_transport import HermesSpool
from .network_contract import NetworkContractError, build_network_event


class NetworkIngestionError(ValueError):
    pass


class NetworkEventIngestor:
    """Normalize and enqueue network events without depending on Hermes/Cortex availability."""

    def __init__(self, spool: HermesSpool, *, ref_key: bytes | None = None, max_clock_skew_seconds: int = 300, dedup_window_seconds: int = 86400, clock: callable = time.time) -> None:
        self.spool = spool
        self.ref_key = ref_key
        self.max_clock_skew_seconds = max(0, int(max_clock_skew_seconds))
        self.dedup_window_seconds = max(1, int(dedup_window_seconds))
        self._clock = clock
        self.state_path = spool.root / "network-ingestion.sqlite3"
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS sequences (sensor_ref TEXT PRIMARY KEY, sequence INTEGER NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS seen (event_id TEXT PRIMARY KEY, observed_at REAL NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS metrics (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.state_path, timeout=1.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _metric(self, name: str) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO metrics(name,value) VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1", (name,))

    def metrics(self) -> dict[str, int]:
        with self._connect() as conn:
            return {str(k): int(v) for k, v in conn.execute("SELECT name,value FROM metrics")}

    @staticmethod
    def _timestamp(value: str) -> float:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError) as exc:
            raise NetworkIngestionError("observed_at must be an ISO-8601 timestamp") from exc

    def ingest(self, observed: Mapping[str, Any], *, policy: Mapping[str, Any] | None = None, enforcement: Mapping[str, Any] | None = None, **identity: Any) -> str | None:
        """Return the delivery id, or None when a duplicate is safely acknowledged."""
        now = float(self._clock())
        observed_at = str(observed.get("observed_at") or "")
        observed_ts = self._timestamp(observed_at)
        if abs(now - observed_ts) > self.max_clock_skew_seconds:
            self._metric("clock_skew_dropped_total")
            raise NetworkIngestionError("network observation is outside the clock-skew window")
        event_id = str(observed.get("event_id") or "")
        sensor_id = str(identity.get("sensor_id") or "")
        sequence = int(identity.get("sequence", observed.get("sequence", 0)) or 0)
        if sequence < 0:
            self._metric("invalid_sequence_dropped_total")
            raise NetworkIngestionError("sequence must be non-negative")
        duplicate = False
        replay = False
        with self._connect() as conn:
            cutoff = now - self.dedup_window_seconds
            conn.execute("DELETE FROM seen WHERE observed_at < ?", (cutoff,))
            if event_id and conn.execute("SELECT 1 FROM seen WHERE event_id=?", (event_id,)).fetchone():
                duplicate = True
            previous = conn.execute("SELECT sequence FROM sequences WHERE sensor_ref=?", (sensor_id,)).fetchone()
            if previous is not None and sequence <= int(previous[0]):
                replay = True
        if duplicate:
            self._metric("duplicate_dropped_total")
            return None
        if replay:
            self._metric("replay_dropped_total")
            raise NetworkIngestionError("network sequence is not strictly increasing")
        try:
            builder_identity = dict(identity)
            builder_identity.pop("sequence", None)
            payload = build_network_event(observed, sequence=sequence, ref_key=self.ref_key, policy=policy, enforcement=enforcement, **builder_identity)
        except (TypeError, ValueError, NetworkContractError) as exc:
            self._metric("contract_dropped_total")
            raise NetworkIngestionError(str(exc)) from exc
        delivery_id = self.spool.publish_network(payload, delivery_id=payload["event_id"])
        if delivery_id is None:
            self._metric("capacity_dropped_total")
            return None
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO sequences(sensor_ref,sequence) VALUES(?,?)", (sensor_id, sequence))
            conn.execute("INSERT OR REPLACE INTO seen(event_id,observed_at) VALUES(?,?)", (payload["event_id"], observed_ts))
        self._metric("accepted_total")
        return delivery_id


__all__ = ["NetworkEventIngestor", "NetworkIngestionError"]
