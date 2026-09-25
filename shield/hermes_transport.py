"""Bounded authenticated local Shield -> Hermes spool transport.

The transport carries already-redacted contract envelopes. It cannot request or perform
enforcement, and a transport failure never affects local Shield policy or containment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from .hermes_contract import HermesContractError, assert_safe_payload, validate_event

MAX_PAYLOAD_BYTES = 64 * 1024
MAX_SPOOL_BYTES = 16 * 1024 * 1024
MAX_BATCH = 10


class HermesTransportError(RuntimeError):
    """Raised for local transport configuration or authentication failures."""


class HermesSpool:
    """Atomic-file producer/consumer with HMAC authentication and replay state."""

    def __init__(self, root: str | Path, *, key: bytes, max_bytes: int = MAX_SPOOL_BYTES, max_batch: int = MAX_BATCH) -> None:
        if len(key) < 32:
            raise ValueError("Hermes spool key must contain at least 32 bytes")
        if max_bytes < MAX_PAYLOAD_BYTES or max_batch < 1:
            raise ValueError("Hermes spool limits are too small")
        self.root = Path(root)
        self.pending = self.root / "pending"
        self.ack = self.root / "ack"
        self.dead = self.root / "dead-letter"
        self.state_path = self.root / "state.sqlite3"
        self.key = bytes(key)
        self.max_bytes = int(max_bytes)
        self.max_batch = min(int(max_batch), MAX_BATCH)
        self._ensure_dirs()

    @classmethod
    def from_key_path(cls, root: str | Path, key_path: str | Path, **kwargs: Any) -> "HermesSpool":
        key = Path(key_path).read_bytes()
        return cls(root, key=key, **kwargs)

    def _ensure_dirs(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in (self.pending, self.ack, self.dead):
            directory.mkdir(mode=0o700, exist_ok=True)
        mode = self.root.stat().st_mode & 0o077
        if mode:
            raise HermesTransportError("Hermes spool directory must not be group/world accessible")
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS deliveries (delivery_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at REAL NOT NULL, detail TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS metrics (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.state_path, timeout=1.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _metric(self, name: str, increment: int = 1) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO metrics(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value", (name, increment))

    def metrics(self) -> dict[str, int]:
        with self._connect() as conn:
            return {str(name): int(value) for name, value in conn.execute("SELECT name,value FROM metrics")}

    def status(self) -> dict[str, int]:
        pending = list(self.pending.glob("*.json"))
        return {"pending": len(pending), "pending_bytes": sum(path.stat().st_size for path in pending), **self.metrics()}

    @classmethod
    def inspect_status(cls, root: str | Path) -> dict[str, int | bool | str]:
        """Inspect an existing spool without creating directories or opening it writable.

        This is deliberately separate from ``status()``: the backend status endpoint must
        remain read-only and must not initialize a missing agent spool as a side effect.
        """
        spool_root = Path(root)
        pending = list((spool_root / "pending").glob("*.json")) if (spool_root / "pending").is_dir() else []
        dead = list((spool_root / "dead-letter").glob("*.json")) if (spool_root / "dead-letter").is_dir() else []
        metrics: dict[str, int] = {}
        acknowledged = 0
        state_path = spool_root / "state.sqlite3"
        if state_path.exists():
            try:
                uri = f"file:{state_path}?mode=ro"
                with sqlite3.connect(uri, uri=True, timeout=0.5) as conn:
                    metrics = {str(name): int(value) for name, value in conn.execute("SELECT name,value FROM metrics")}
                    acknowledged = int(conn.execute("SELECT COUNT(*) FROM deliveries WHERE status='acknowledged'").fetchone()[0])
            except sqlite3.Error:
                metrics = {"state_unreadable": 1}
        return {
            "configured": spool_root.exists(),
            "spool_path": str(spool_root),
            "pending": len(pending),
            "spool_depth": len(pending),
            "pending_bytes": sum(path.stat().st_size for path in pending),
            "dead_letters": len(dead),
            "dead_letter_bytes": sum(path.stat().st_size for path in dead),
            "acknowledged": acknowledged,
            "acknowledgements": acknowledged,
            **metrics,
        }

    def _pending_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.pending.glob("*.json"))

    def publish(self, payload: Mapping[str, Any], *, delivery_id: str | None = None) -> str | None:
        validate_event(payload)
        assert_safe_payload(payload)
        return self._publish_validated(payload, delivery_id=delivery_id)

    def publish_network(self, payload: Mapping[str, Any], *, delivery_id: str | None = None) -> str | None:
        """Publish a validated redacted network event into the same bounded local spool."""
        from .network_contract import assert_safe_network_payload, validate_network_event

        validate_network_event(payload)
        assert_safe_network_payload(payload)
        return self._publish_validated(payload, delivery_id=delivery_id)

    def _publish_validated(self, payload: Mapping[str, Any], *, delivery_id: str | None = None) -> str | None:
        canonical = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(canonical) > MAX_PAYLOAD_BYTES:
            self._metric("oversize_dropped_total")
            return None
        delivery_id = delivery_id or str(payload.get("delivery_id") or secrets.token_hex(16))
        envelope = {"delivery_id": delivery_id, "attempt": int(payload.get("delivery", {}).get("attempt", 0)), "payload": dict(payload)}
        body = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        envelope["signature"] = "hmac-sha256:" + hmac.new(self.key, body, hashlib.sha256).hexdigest()
        encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        if len(encoded) > MAX_PAYLOAD_BYTES or self._pending_bytes() + len(encoded) > self.max_bytes:
            self._metric("capacity_dropped_total")
            return None
        destination = self.pending / f"{delivery_id}.json"
        temporary = self.pending / f".{delivery_id}.{os.getpid()}.tmp"
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except FileExistsError:
            self._metric("duplicate_publish_total")
            return delivery_id
        finally:
            temporary.unlink(missing_ok=True)
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO deliveries(delivery_id,status,updated_at,detail) VALUES(?,?,?,?)", (delivery_id, "pending", time.time(), None))
        self._metric("queued_total")
        return delivery_id

    def consume_network_once(self, handler: Callable[[dict[str, Any]], None], *, limit: int | None = None) -> dict[str, int]:
        """Consume only network events; endpoint envelopes are left untouched."""
        from .network_contract import NetworkContractError, assert_safe_network_payload, validate_network_event

        return self._consume_validated(handler, validate_network_event, assert_safe_network_payload, limit=limit)

    def consume_once(self, handler: Callable[[dict[str, Any]], None], *, limit: int | None = None) -> dict[str, int]:
        return self._consume_validated(handler, validate_event, assert_safe_payload, limit=limit)

    def _consume_validated(self, handler: Callable[[dict[str, Any]], None], validator: Callable[[Mapping[str, Any]], None], scanner: Callable[[Mapping[str, Any]], None], *, limit: int | None = None) -> dict[str, int]:
        processed = acknowledged = malformed = failed = replayed = 0
        for path in sorted(self.pending.glob("*.json"))[: min(limit or self.max_batch, self.max_batch)]:
            processed += 1
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
                delivery_id = str(envelope["delivery_id"])
                payload = envelope["payload"]
                signature = str(envelope["signature"])
                body = json.dumps({"delivery_id": delivery_id, "attempt": int(envelope.get("attempt", 0)), "payload": payload}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                expected = "hmac-sha256:" + hmac.new(self.key, body, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature, expected):
                    raise HermesTransportError("invalid HMAC")
                validator(payload)
                scanner(payload)
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, HermesContractError, HermesTransportError) as exc:
                malformed += 1
                self._move(path, self.dead)
                self._record(path.stem, "dead_letter", str(exc))
                self._metric("malformed_total")
                continue
            with self._connect() as conn:
                existing = conn.execute("SELECT status FROM deliveries WHERE delivery_id=?", (delivery_id,)).fetchone()
            if existing and existing[0] == "acknowledged":
                replayed += 1
                self._move(path, self.ack)
                self._metric("replay_total")
                continue
            try:
                handler(payload)
            except Exception as exc:  # noqa: BLE001 -- consumer decides whether to retry later
                failed += 1
                self._record(delivery_id, "pending", str(exc))
                self._metric("handler_failure_total")
                continue
            acknowledged += 1
            self._record(delivery_id, "acknowledged", None)
            self._move(path, self.ack)
            self._metric("acknowledged_total")
        return {"processed": processed, "acknowledged": acknowledged, "malformed": malformed, "failed": failed, "replayed": replayed}

    def _record(self, delivery_id: str, status: str, detail: str | None) -> None:
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO deliveries(delivery_id,status,updated_at,detail) VALUES(?,?,?,?)", (delivery_id, status, time.time(), detail[:500] if detail else None))

    @staticmethod
    def _move(path: Path, directory: Path) -> None:
        destination = directory / path.name
        os.replace(path, destination)


__all__ = ["HermesSpool", "HermesTransportError", "MAX_BATCH", "MAX_PAYLOAD_BYTES", "MAX_SPOOL_BYTES"]
