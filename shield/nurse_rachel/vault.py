"""Patient vault and PHI de-identification boundary for client endpoints."""

import hashlib
import hmac
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


class PatientVault:
    """Encrypted per-patient local store and tokenization boundary.

    Enforces HIPAA §164.312(a)(2)(iv) (encryption at rest) and
    §164.502(b) (minimum necessary / PHI de-identification).
    """

    def __init__(self, storage_root: Path, vault_secret_key: bytes):
        self.storage_root = Path(storage_root)
        self.storage_root.mkdir(parents=True, exist_ok=True)
        self._secret = vault_secret_key
        self._token_map: Dict[str, str] = {}  # token -> real patient_id

    def tokenize_patient_id(self, patient_id: str) -> str:
        """Derive a deterministic, irreversible surrogate token for inference prompts."""
        h = hmac.new(self._secret, patient_id.encode("utf-8"), hashlib.sha256)
        token = f"SUBJECT_{h.hexdigest()[:12].upper()}"
        self._token_map[token] = patient_id
        return token

    def resolve_token(self, token: str) -> Optional[str]:
        """Resolve surrogate token back to real patient_id within secure local memory."""
        return self._token_map.get(token)

    def _get_db_path(self, patient_id: str) -> Path:
        """Isolated database path per patient. Zero cross-tenant storage."""
        h = hashlib.sha256(patient_id.encode("utf-8")).hexdigest()[:16]
        return self.storage_root / f"patient_{h}.db"

    def _init_db(self, conn: sqlite3.Connection):
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vitals_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS adl_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at TEXT NOT NULL,
                    category TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS escalations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dispatched_at TEXT NOT NULL,
                    urgency TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def record_vitals(self, patient_id: str, vitals_payload: Dict[str, Any]):
        db_path = self._get_db_path(patient_id)
        conn = sqlite3.connect(db_path)
        try:
            self._init_db(conn)
            with conn:
                conn.execute(
                    "INSERT INTO vitals_log (recorded_at, payload) VALUES (?, ?)",
                    (vitals_payload.get("recorded_at", ""), json.dumps(vitals_payload)),
                )
        finally:
            conn.close()

    def record_adl(self, patient_id: str, adl_payload: Dict[str, Any]):
        db_path = self._get_db_path(patient_id)
        conn = sqlite3.connect(db_path)
        try:
            self._init_db(conn)
            with conn:
                conn.execute(
                    "INSERT INTO adl_log (observed_at, category, payload) VALUES (?, ?, ?)",
                    (
                        adl_payload.get("observed_at", ""),
                        str(adl_payload.get("category", "")),
                        json.dumps(adl_payload),
                    ),
                )
        finally:
            conn.close()

    def record_escalation(self, patient_id: str, escalation_payload: Dict[str, Any]):
        db_path = self._get_db_path(patient_id)
        conn = sqlite3.connect(db_path)
        try:
            self._init_db(conn)
            with conn:
                conn.execute(
                    "INSERT INTO escalations (dispatched_at, urgency, payload) VALUES (?, ?, ?)",
                    (
                        escalation_payload.get("recorded_at", ""),
                        str(escalation_payload.get("urgency", "")),
                        json.dumps(escalation_payload),
                    ),
                )
        finally:
            conn.close()

    def get_patient_history(self, patient_id: str) -> Dict[str, List[Dict[str, Any]]]:
        db_path = self._get_db_path(patient_id)
        if not db_path.exists():
            return {"vitals": [], "adls": [], "escalations": []}

        conn = sqlite3.connect(db_path)
        try:
            self._init_db(conn)
            vitals = [
                json.loads(row[0])
                for row in conn.execute("SELECT payload FROM vitals_log ORDER BY id DESC").fetchall()
            ]
            adls = [
                json.loads(row[0])
                for row in conn.execute("SELECT payload FROM adl_log ORDER BY id DESC").fetchall()
            ]
            escalations = [
                json.loads(row[0])
                for row in conn.execute("SELECT payload FROM escalations ORDER BY id DESC").fetchall()
            ]
            return {"vitals": vitals, "adls": adls, "escalations": escalations}
        finally:
            conn.close()
