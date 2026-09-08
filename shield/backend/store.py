"""SQLite persistence for the Shield platform MVP backend."""

from __future__ import annotations

import os
import hashlib
import json
import secrets
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config.loader import ConfigError, PolicyBundle, load_policy_bundle


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _password_hash(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if len(password) < 10:
        raise ValueError("password must be at least 10 characters")
    salt = salt or secrets.token_bytes(16)
    return salt.hex(), hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()

def _password_matches(password: str, salt_hex: str, digest_hex: str) -> bool:
    try:
        _, candidate = _password_hash(password, bytes.fromhex(salt_hex))
        return secrets.compare_digest(candidate, digest_hex)
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Enrollment:
    tenant_id: str
    device_id: str
    device_role: str
    device_token: str
    device_config: dict[str, Any]


class ShieldStore:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        if self.db_path != Path(":memory:"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_schema()

    def close(self) -> None:
        self._conn.close()

    def init_schema(self) -> None:
        self._conn.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT "active",
                role TEXT NOT NULL DEFAULT "tenant_admin",
                email_verified INTEGER NOT NULL DEFAULT 1,
                approval_status TEXT NOT NULL DEFAULT "approved",
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS account_tenant_memberships (
                account_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'tenant_admin',
                created_at TEXT NOT NULL,
                PRIMARY KEY (account_id, tenant_id),
                FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE,
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS auth_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT,
                email TEXT,
                event_type TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS tenant_admin_tokens (
                tenant_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                expires_at TEXT,
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS devices (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_role TEXT NOT NULL DEFAULT '',
                device_token_hash TEXT NOT NULL,
                agent_label TEXT NOT NULL DEFAULT 'xibalba-shield',
                last_seen_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS policies (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS policy_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                action TEXT NOT NULL,
                event_class TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                export_ok INTEGER NOT NULL,
                synthetic INTEGER NOT NULL DEFAULT 0,
                received_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS detection_quality (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                quality_json TEXT NOT NULL,
                shield_adr REAL,
                precision REAL,
                blocking_false_positive_rate REAL,
                mean_time_to_contain_sec REAL,
                synthetic INTEGER NOT NULL DEFAULT 0,
                received_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS exporter_status (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                status_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id),
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS exporter_remediation_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                status TEXT NOT NULL DEFAULT 'queued',
                created_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS enforcement_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                agent_id TEXT,
                outcome_json TEXT NOT NULL,
                action TEXT NOT NULL,
                completed INTEGER NOT NULL,
                escalated INTEGER NOT NULL DEFAULT 0,
                received_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            -- Generic cross-system test-run log (~/.claude/plans/velvet-giggling-quill.md),
            -- deliberately NOT tied to devices(tenant_id, device_id) like enforcement_outcomes
            -- is -- this records "the dashboard ran a test against this system", not "an
            -- enrolled device did something", so no device enrollment should be required
            -- just to log a test result. Same role here as integrity-oracle's audit_log or
            -- xibalba-cortex's otel_events: a loosely-coupled, agent_id-tagged event log.
            CREATE TABLE IF NOT EXISTS test_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL DEFAULT 'dashboard',
                agent_id TEXT,
                test_name TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                recorded_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS integrations (
                tenant_id TEXT NOT NULL,
                integration_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                config_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, integration_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS transaction_intents (
                intent_hash TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                intent_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS transaction_approvals (
                approval_id TEXT PRIMARY KEY,
                intent_hash TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                consumed_at TEXT,
                FOREIGN KEY (intent_hash) REFERENCES transaction_intents(intent_hash) ON DELETE CASCADE
            );
            """
        )
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(tenant_admin_tokens)")}
        if "last_used_at" not in columns:
            self._conn.execute("ALTER TABLE tenant_admin_tokens ADD COLUMN last_used_at TEXT")
        if "expires_at" not in columns:
            self._conn.execute("ALTER TABLE tenant_admin_tokens ADD COLUMN expires_at TEXT")
        account_columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(accounts)")}
        if "role" not in account_columns:
            self._conn.execute("ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'tenant_admin'")
        if "failed_attempts" not in account_columns:
            self._conn.execute("ALTER TABLE accounts ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
        if "locked_until" not in account_columns:
            self._conn.execute("ALTER TABLE accounts ADD COLUMN locked_until TEXT")
        if "email_verified" not in account_columns:
            self._conn.execute("ALTER TABLE accounts ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
        if "approval_status" not in account_columns:
            self._conn.execute("ALTER TABLE accounts ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'approved'")
        self._conn.commit()
        # Backfill membership rows for accounts created before the membership table existed.
        self._conn.execute("INSERT OR IGNORE INTO account_tenant_memberships(account_id,tenant_id,role,created_at) SELECT account_id,tenant_id,role,created_at FROM accounts")
        self._conn.commit()

    def enroll_device(
        self,
        *,
        tenant_id: str,
        device_id: str,
        device_role: str = "",
        base_url: str,
        agent_label: str = "xibalba-shield",
    ) -> Enrollment:
        self._validate_id("tenant_id", tenant_id)
        self._validate_id("device_id", device_id)
        token = secrets.token_urlsafe(32)
        now = _now()
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, created_at) VALUES (?, ?)",
                (tenant_id, now),
            )
            self._conn.execute(
                """
                INSERT INTO devices
                    (tenant_id, device_id, device_role, device_token_hash, agent_label, last_seen_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, device_id) DO UPDATE SET
                    device_role=excluded.device_role,
                    device_token_hash=excluded.device_token_hash,
                    agent_label=excluded.agent_label,
                    last_seen_at=excluded.last_seen_at
                """,
                (tenant_id, device_id, device_role, _hash_token(token), agent_label, now, now),
            )
        policy_url = f"{base_url.rstrip('/')}/api/shield/policies/{tenant_id}/{device_id}"
        return Enrollment(
            tenant_id=tenant_id,
            device_id=device_id,
            device_role=device_role,
            device_token=token,
            device_config={
                "device_id": device_id,
                "tenant_id": tenant_id,
                "device_role": device_role,
                "tenant_policy_url": policy_url,
                "backend_url": base_url,
                "device_token": token,
                "feature_flags": {},
                "sensitive_paths": [],
                "trusted_policy_hashes": [],
            },
        )

    def authenticate_device(self, *, tenant_id: str, device_id: str, token: str) -> bool:
        row = self._conn.execute(
            "SELECT device_token_hash FROM devices WHERE tenant_id=? AND device_id=?",
            (tenant_id, device_id),
        ).fetchone()
        return bool(row and secrets.compare_digest(row["device_token_hash"], _hash_token(token)))

    def create_account(self, *, tenant_id: str, email: str, password: str, display_name: str) -> dict[str, Any]:
        tenant_id = tenant_id.strip()
        email = email.strip().lower()
        display_name = display_name.strip()
        if not tenant_id or "@" not in email or not display_name:
            raise ValueError("valid email and display name are required")
        salt, digest = _password_hash(password)
        account_id = secrets.token_hex(16)
        now = _now()
        with self._conn:
            self._conn.execute("INSERT OR IGNORE INTO tenants (tenant_id, created_at) VALUES (?, ?)", (tenant_id, now))
            try:
                self._conn.execute("INSERT INTO accounts(account_id,tenant_id,email,display_name,password_hash,password_salt,created_at) VALUES(?,?,?,?,?,?,?)", (account_id, tenant_id, email, display_name, digest, salt, now))
            except sqlite3.IntegrityError as exc:
                raise ValueError("an account with that email already exists") from exc
            self._conn.execute("INSERT INTO account_tenant_memberships(account_id,tenant_id,role,created_at) VALUES(?,?,?,?)", (account_id, tenant_id, "tenant_admin", now))
        return {"id": account_id, "tenant_id": tenant_id, "email": email, "display_name": display_name, "role": "tenant_admin", "status": "active", "email_verified": True, "approval_status": "approved", "created_at": now, "tenants": [{"tenant_id": tenant_id, "role": "tenant_admin", "created_at": now}]}

    def record_auth_event(self, *, event_type: str, email: str | None = None, tenant_id: str | None = None, detail: str | None = None) -> None:
        with self._conn:
            self._conn.execute("INSERT INTO auth_events(tenant_id,email,event_type,detail,created_at) VALUES(?,?,?,?,?)", (tenant_id, email.strip().lower() if email else None, event_type, detail, _now()))

    def list_auth_events(self, *, tenant_id: str, email: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT event_type,email,detail,created_at FROM auth_events WHERE tenant_id=?"
        params: list[Any] = [tenant_id]
        if email:
            query += " AND email=?"
            params.append(email.strip().lower())
        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        return [dict(row) for row in self._conn.execute(query, tuple(params)).fetchall()]

    def authenticate_account(self, *, email: str, password: str) -> tuple[dict[str, Any], str] | None:
        normalized = email.strip().lower()
        row = self._conn.execute('SELECT * FROM accounts WHERE email=? AND status="active"', (normalized,)).fetchone()
        now = datetime.now(timezone.utc)
        if row is None:
            self.record_auth_event(event_type="login_failed", email=normalized, detail="unknown account")
            return None
        if not row["email_verified"] or row["approval_status"] != "approved":
            self.record_auth_event(event_type="login_blocked", email=normalized, tenant_id=row["tenant_id"], detail="verification or administrator approval required")
            return None
        locked_until = row["locked_until"]
        if locked_until:
            try:
                if datetime.fromisoformat(locked_until.replace("Z", "+00:00")) > now:
                    self.record_auth_event(event_type="login_blocked", email=normalized, tenant_id=row["tenant_id"], detail="account lockout")
                    return None
            except ValueError:
                pass
        if not _password_matches(password, row["password_salt"], row["password_hash"]):
            attempts = int(row["failed_attempts"] or 0) + 1
            lock = (now + timedelta(minutes=15)).isoformat() if attempts >= 5 else None
            with self._conn:
                self._conn.execute("UPDATE accounts SET failed_attempts=?, locked_until=? WHERE account_id=?", (attempts, lock, row["account_id"]))
            self.record_auth_event(event_type="login_failed", email=normalized, tenant_id=row["tenant_id"], detail="locked" if lock else "invalid password")
            return None
        with self._conn:
            self._conn.execute("UPDATE accounts SET failed_attempts=0, locked_until=NULL WHERE account_id=?", (row["account_id"],))
        self.record_auth_event(event_type="login_succeeded", email=normalized, tenant_id=row["tenant_id"])
        account = {"id": row["account_id"], "tenant_id": row["tenant_id"], "email": row["email"], "display_name": row["display_name"], "role": row["role"], "status": row["status"], "email_verified": bool(row["email_verified"]), "approval_status": row["approval_status"], "created_at": row["created_at"], "tenants": self.list_account_tenants(account_id=row["account_id"])}
        return account, self.mint_tenant_admin_token(tenant_id=row["tenant_id"])

    def get_account_for_tenant(self, *, tenant_id: str, email: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT account_id,tenant_id,email,display_name,status,role,created_at FROM accounts WHERE tenant_id=? AND email=?", (tenant_id, email.strip().lower())).fetchone()
        return dict(row) if row else None

    def list_account_tenants(self, *, account_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT tenant_id,role,created_at FROM account_tenant_memberships WHERE account_id=? ORDER BY tenant_id", (account_id,)).fetchall()
        return [dict(row) for row in rows]

    def approve_account(self, *, tenant_id: str, email: str, verified: bool = True) -> bool:
        row = self._conn.execute("SELECT account_id FROM accounts WHERE tenant_id=? AND email=?", (tenant_id, email.strip().lower())).fetchone()
        if row is None:
            return False
        with self._conn:
            self._conn.execute("UPDATE accounts SET email_verified=?,approval_status='approved' WHERE account_id=?", (1 if verified else 0, row["account_id"]))
        self.record_auth_event(event_type="account_approved", email=email, tenant_id=tenant_id)
        return True

    def switch_account_tenant(self, *, current_tenant_id: str, email: str, target_tenant_id: str) -> tuple[dict[str, Any], str] | None:
        account = self.get_account_for_tenant(tenant_id=current_tenant_id, email=email)
        if account is None:
            return None
        membership = self._conn.execute("SELECT role FROM account_tenant_memberships WHERE account_id=? AND tenant_id=?", (account["account_id"], target_tenant_id)).fetchone()
        if membership is None:
            return None
        account["tenant_id"] = target_tenant_id
        account["role"] = membership["role"]
        self.record_auth_event(event_type="tenant_switched", email=account["email"], tenant_id=target_tenant_id, detail=f"from={current_tenant_id}")
        return account, self.mint_tenant_admin_token(tenant_id=target_tenant_id)

    def change_account_password(self, *, tenant_id: str, email: str, current_password: str, new_password: str) -> bool:
        normalized = email.strip().lower()
        row = self._conn.execute('SELECT * FROM accounts WHERE tenant_id=? AND email=? AND status="active"', (tenant_id, normalized)).fetchone()
        if row is None or not _password_matches(current_password, row["password_salt"], row["password_hash"]):
            self.record_auth_event(event_type="password_change_failed", email=normalized, tenant_id=tenant_id, detail="invalid current password")
            return False
        salt, digest = _password_hash(new_password)
        with self._conn:
            self._conn.execute("UPDATE accounts SET password_hash=?, password_salt=?, failed_attempts=0, locked_until=NULL WHERE account_id=?", (digest, salt, row["account_id"]))
        self.record_auth_event(event_type="password_changed", email=normalized, tenant_id=tenant_id)
        return True

    def request_password_reset(self, *, email: str, ttl_minutes: int = 30) -> str | None:
        normalized = email.strip().lower()
        row = self._conn.execute("SELECT account_id,tenant_id,email FROM accounts WHERE email=? AND status=\"active\"", (normalized,)).fetchone()
        if row is None:
            self.record_auth_event(event_type="password_reset_requested", email=normalized, detail="unknown account")
            return None
        raw = secrets.token_urlsafe(32)
        token_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc)
        with self._conn:
            self._conn.execute("INSERT INTO password_reset_tokens(id,account_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)", (token_id, row["account_id"], _hash_token(raw), (now + timedelta(minutes=ttl_minutes)).isoformat(), _now()))
        from .email_delivery import send_email
        reset_url = os.environ.get("SHIELD_PASSWORD_RESET_URL", "").strip()
        if not reset_url:
            with self._conn:
                self._conn.execute("DELETE FROM password_reset_tokens WHERE id=?", (token_id,))
            raise RuntimeError("SHIELD_PASSWORD_RESET_URL is required for password reset delivery")
        separator = "&" if "?" in reset_url else "?"
        try:
            send_email(row["email"], "Reset your Xibalba Shield password", f"Use this time-limited link to reset your password:\n\n{reset_url}{separator}token={raw}\n")
        except Exception as exc:
            with self._conn:
                self._conn.execute("DELETE FROM password_reset_tokens WHERE id=?", (token_id,))
            raise RuntimeError("password reset email delivery failed") from exc
        self.record_auth_event(event_type="password_reset_requested", email=normalized, tenant_id=row["tenant_id"], detail="email delivered")
        return raw

    def reset_password(self, *, reset_token: str, new_password: str) -> bool:
        row = self._conn.execute("SELECT id,account_id,expires_at FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL", (_hash_token(reset_token),)).fetchone()
        if row is None or datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc):
            return False
        salt, digest = _password_hash(new_password)
        with self._conn:
            self._conn.execute("UPDATE accounts SET password_hash=?,password_salt=?,failed_attempts=0,locked_until=NULL WHERE account_id=?", (digest, salt, row["account_id"]))
            self._conn.execute("UPDATE password_reset_tokens SET used_at=? WHERE id=?", (_now(), row["id"]))
            account = self._conn.execute("SELECT email,tenant_id FROM accounts WHERE account_id=?", (row["account_id"],)).fetchone()
        self.record_auth_event(event_type="password_reset_completed", email=account["email"] if account else None, tenant_id=account["tenant_id"] if account else None)
        return True

    def mint_tenant_admin_token(self, *, tenant_id: str, ttl_hours: int | None = 24) -> str:
        """Issue a fresh admin token scoped to one tenant, replacing any prior token."""
        self._validate_id("tenant_id", tenant_id)
        token = secrets.token_urlsafe(32)
        now = _now()
        expires_at = None if ttl_hours is None else (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, created_at) VALUES (?, ?)",
                (tenant_id, now),
            )
            self._conn.execute(
                """
                INSERT INTO tenant_admin_tokens (tenant_id, token_hash, created_at, last_used_at, expires_at)
                VALUES (?, ?, ?, NULL, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    token_hash=excluded.token_hash,
                    created_at=excluded.created_at,
                    last_used_at=NULL,
                    expires_at=excluded.expires_at
                """,
                (tenant_id, _hash_token(token), now, expires_at),
            )
        return token

    def authenticate_tenant_admin(self, *, tenant_id: str, token: str) -> bool:
        """Check a tenant-scoped admin token. Never grants access to a different tenant_id."""
        row = self._conn.execute(
            "SELECT token_hash FROM tenant_admin_tokens WHERE tenant_id=? AND (expires_at IS NULL OR expires_at > ?)",
            (tenant_id, _now()),
        ).fetchone()
        valid = bool(row and secrets.compare_digest(row["token_hash"], _hash_token(token)))
        if valid:
            with self._conn:
                self._conn.execute("UPDATE tenant_admin_tokens SET last_used_at=? WHERE tenant_id=?", (_now(), tenant_id))
        return valid

    def list_tenant_admin_sessions(self, *, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT tenant_id,created_at,last_used_at,expires_at FROM tenant_admin_tokens WHERE tenant_id=?", (tenant_id,)).fetchall()
        return [dict(row) for row in rows]

    def tenant_admin_token_expiry(self, *, tenant_id: str) -> str | None:
        row = self._conn.execute("SELECT expires_at FROM tenant_admin_tokens WHERE tenant_id=?", (tenant_id,)).fetchone()
        return row["expires_at"] if row else None

    def revoke_tenant_admin_token(self, *, tenant_id: str, token: str) -> bool:
        with self._conn:
            cur = self._conn.execute("DELETE FROM tenant_admin_tokens WHERE tenant_id=? AND token_hash=?", (tenant_id, _hash_token(token)))
        return cur.rowcount > 0

    def put_policy(self, *, tenant_id: str, device_id: str, policy_doc: dict[str, Any]) -> PolicyBundle:
        self._validate_id("tenant_id", tenant_id)
        self._validate_id("device_id", device_id)
        raw = json.dumps(policy_doc, sort_keys=True).encode("utf-8")
        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
            tmp.write(raw)
            tmp_path = Path(tmp.name)
        try:
            bundle = load_policy_bundle(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, created_at) VALUES (?, ?)",
                (tenant_id, _now()),
            )
            previous = self._conn.execute("SELECT policy_version,policy_hash,policy_json,created_at FROM policies WHERE tenant_id=? AND device_id=?", (tenant_id, device_id)).fetchone()
            if previous:
                self._conn.execute("INSERT INTO policy_history(tenant_id,device_id,policy_version,policy_hash,policy_json,created_at) VALUES(?,?,?,?,?,?)", (tenant_id, device_id, previous["policy_version"], previous["policy_hash"], previous["policy_json"], previous["created_at"]))
            self._conn.execute(
                """
                INSERT INTO policies (tenant_id, device_id, policy_version, policy_hash, policy_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, device_id) DO UPDATE SET
                    policy_version=excluded.policy_version,
                    policy_hash=excluded.policy_hash,
                    policy_json=excluded.policy_json,
                    created_at=excluded.created_at
                """,
                (tenant_id, device_id, bundle.version, bundle.hash, raw.decode("utf-8"), _now()),
            )
        return bundle

    def list_policy_history(self, *, tenant_id: str, device_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT id,device_id,policy_version,policy_hash,created_at FROM policy_history WHERE tenant_id=? AND device_id=? ORDER BY id DESC", (tenant_id, device_id)).fetchall()
        return [dict(row) for row in rows]

    def rollback_policy(self, *, tenant_id: str, device_id: str, history_id: int) -> PolicyBundle:
        row = self._conn.execute("SELECT policy_version,policy_hash,policy_json FROM policy_history WHERE id=? AND tenant_id=? AND device_id=?", (history_id, tenant_id, device_id)).fetchone()
        if row is None:
            raise ValueError("policy history record not found")
        bundle = self.put_policy(tenant_id=tenant_id, device_id=device_id, policy_doc=json.loads(row["policy_json"]))
        return bundle

    def get_policy_doc(self, *, tenant_id: str, device_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT policy_json FROM policies
            WHERE tenant_id=? AND device_id IN (?, '*')
            ORDER BY CASE WHEN device_id=? THEN 0 ELSE 1 END
            LIMIT 1
            """,
            (tenant_id, device_id, device_id),
        ).fetchone()
        return json.loads(row["policy_json"]) if row else None

    def list_devices(self, *, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT d.tenant_id, d.device_id, d.device_role, d.agent_label, d.last_seen_at,
                   p.policy_version, p.policy_hash
            FROM devices d
            LEFT JOIN policies p ON p.tenant_id=d.tenant_id AND p.device_id IN (d.device_id, '*')
            WHERE d.tenant_id=?
            GROUP BY d.tenant_id, d.device_id
            ORDER BY d.device_id
            """,
            (tenant_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_device(self, *, tenant_id: str, device_id: str) -> dict[str, Any] | None:
        rows = [row for row in self.list_devices(tenant_id=tenant_id) if row["device_id"] == device_id]
        return rows[0] if rows else None

    def record_decision(self, *, tenant_id: str, device_id: str, decision: dict[str, Any]) -> int:
        self._require_device(tenant_id, device_id)
        action = str(decision.get("decision", {}).get("action", ""))
        event_class = str(decision.get("event_ref", {}).get("class", decision.get("class", "")))
        rule_id = str(decision.get("rule", {}).get("rule_id", ""))
        severity = str(decision.get("decision", {}).get("severity", "low"))
        export = decision.get("export", {})
        export_ok = bool(export.get("decision_exported") or export.get("authorized"))
        synthetic = bool(decision.get("synthetic") or decision.get("_demo"))
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO decisions
                    (tenant_id, device_id, decision_json, action, event_class, rule_id, severity, export_ok, synthetic, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, device_id, json.dumps(decision, sort_keys=True), action, event_class, rule_id, severity, int(export_ok), int(synthetic), _now()),
            )
            self._touch_device(tenant_id, device_id)
        return int(cursor.lastrowid)

    def record_enforcement_outcome(self, *, tenant_id: str, device_id: str, outcome: dict[str, Any]) -> int:
        """Forward-link counterpart to record_decision: what happened when a decision's
        chosen action was actually carried out, keyed by the same event_id PolicyDecision
        already carries backward to its triggering event. See
        shield/schemas/events.py's EnforcementOutcome and agent_core/router.py's
        _report_enforcement_outcome for where this data comes from."""
        self._require_device(tenant_id, device_id)
        event_id = str(outcome.get("event_id", ""))
        if not event_id:
            raise ValueError("outcome.event_id is required")
        agent_id = outcome.get("agent_id")
        action = str(outcome.get("action", ""))
        completed = bool(outcome.get("completed"))
        escalated = bool(outcome.get("escalated"))
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO enforcement_outcomes
                    (tenant_id, device_id, event_id, agent_id, outcome_json, action, completed, escalated, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, device_id, event_id, agent_id, json.dumps(outcome, sort_keys=True), action, int(completed), int(escalated), _now()),
            )
            self._touch_device(tenant_id, device_id)
        return int(cursor.lastrowid)

    def list_enforcement_outcomes(self, *, tenant_id: str, device_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        if device_id is not None:
            rows = self._conn.execute(
                "SELECT outcome_json, received_at FROM enforcement_outcomes WHERE tenant_id=? AND device_id=? ORDER BY id DESC LIMIT ?",
                (tenant_id, device_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT outcome_json, received_at FROM enforcement_outcomes WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [{"received_at": row["received_at"], "outcome": json.loads(row["outcome_json"])} for row in rows]

    def record_test_event(
        self, *, tenant_id: str = "dashboard", agent_id: str | None = None,
        test_name: str, status: str, detail: str | None = None, metadata: dict[str, Any] | None = None,
    ) -> int:
        """Generic cross-system test-run log -- no device enrollment required, see the
        test_events table's own comment in init_schema. Called directly by the dashboard's
        fan-out helper (testResults.ts), not by anything inside Shield itself."""
        if not test_name:
            raise ValueError("test_name is required")
        if not status:
            raise ValueError("status is required")
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO test_events (tenant_id, agent_id, test_name, status, detail, metadata_json, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, agent_id, test_name, status, detail, json.dumps(metadata or {}, sort_keys=True), _now()),
            )
        return int(cursor.lastrowid)

    def list_test_events(self, *, tenant_id: str = "dashboard", agent_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        if agent_id is not None:
            rows = self._conn.execute(
                "SELECT id, tenant_id, agent_id, test_name, status, detail, metadata_json, recorded_at FROM test_events WHERE tenant_id=? AND agent_id=? ORDER BY id DESC LIMIT ?",
                (tenant_id, agent_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id, tenant_id, agent_id, test_name, status, detail, metadata_json, recorded_at FROM test_events WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"], "tenant_id": row["tenant_id"], "agent_id": row["agent_id"],
                "test_name": row["test_name"], "status": row["status"], "detail": row["detail"],
                "metadata": json.loads(row["metadata_json"]), "recorded_at": row["recorded_at"],
            }
            for row in rows
        ]

    def record_metrics(self, *, tenant_id: str, device_id: str, metrics: dict[str, Any]) -> int:
        self._require_device(tenant_id, device_id)
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO metrics (tenant_id, device_id, metrics_json, received_at) VALUES (?, ?, ?, ?)",
                (tenant_id, device_id, json.dumps(metrics, sort_keys=True), _now()),
            )
            self._touch_device(tenant_id, device_id)
        return int(cursor.lastrowid)

    def record_detection_quality(self, *, tenant_id: str, device_id: str, quality: dict[str, Any]) -> int:
        self._require_device(tenant_id, device_id)
        normalized = _normalize_detection_quality(quality)
        aggregate = normalized["aggregate"]
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO detection_quality
                    (tenant_id, device_id, quality_json, shield_adr, precision, blocking_false_positive_rate,
                     mean_time_to_contain_sec, synthetic, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    device_id,
                    json.dumps(normalized, sort_keys=True),
                    aggregate["shield_adr"],
                    aggregate["precision"],
                    aggregate["blocking_false_positive_rate"],
                    aggregate["mean_time_to_contain_sec"],
                    int(bool(normalized.get("synthetic"))),
                    _now(),
                ),
            )
            self._touch_device(tenant_id, device_id)
        return int(cursor.lastrowid)

    def list_detection_quality(self, *, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT device_id, quality_json, received_at
            FROM detection_quality
            WHERE tenant_id=?
            ORDER BY id DESC
            LIMIT 25
            """,
            (tenant_id,),
        ).fetchall()
        return [
            {"device_id": row["device_id"], "quality": json.loads(row["quality_json"]), "received_at": row["received_at"]}
            for row in rows
        ]

    def upsert_exporter_status(self, *, tenant_id: str, device_id: str, status: dict[str, Any]) -> None:
        """Shallow-merges `status` onto whatever was previously stored for this device,
        rather than replacing it wholesale. A real device's watchdog publishes only
        `{"policy": ..., "opa": ..., "sensors": ..., "exporter": ...}` on each tick; the
        demo-seed path writes sibling keys into the same document (`did_registered`,
        `bcc_middleware`, `oracle_readback`, `synthetic`, `endpoint_posture`). A wholesale
        replace would let either writer silently erase the other's fields -- merging keeps
        both live without requiring every caller to know the other's full key set."""
        self._require_device(tenant_id, device_id)
        with self._conn:
            existing_row = self._conn.execute(
                "SELECT status_json FROM exporter_status WHERE tenant_id=? AND device_id=?",
                (tenant_id, device_id),
            ).fetchone()
            merged = dict(json.loads(existing_row["status_json"])) if existing_row else {}
            merged.update(status)
            self._conn.execute(
                """
                INSERT INTO exporter_status (tenant_id, device_id, status_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(tenant_id, device_id) DO UPDATE SET
                    status_json=excluded.status_json,
                    updated_at=excluded.updated_at
                """,
                (tenant_id, device_id, json.dumps(merged, sort_keys=True), _now()),
            )

    def list_exporter_status(self, *, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT device_id, status_json, updated_at FROM exporter_status WHERE tenant_id=? ORDER BY device_id",
            (tenant_id,),
        ).fetchall()
        return [
            {"device_id": row["device_id"], "status": json.loads(row["status_json"]), "updated_at": row["updated_at"]}
            for row in rows
        ]

    def request_exporter_remediation(self, *, tenant_id: str, device_id: str, action: str, reason: str = "") -> dict[str, Any]:
        if action not in {"retry", "reconnect", "flush"}:
            raise ValueError("unsupported exporter remediation action")
        self._validate_id("tenant_id", tenant_id)
        self._validate_id("device_id", device_id)
        now = _now()
        with self._conn:
            cur = self._conn.execute("INSERT INTO exporter_remediation_requests(tenant_id,device_id,action,reason,status,created_at) VALUES(?,?,?,?,?,?)", (tenant_id, device_id, action, reason.strip(), "queued", now))
        return {"id": cur.lastrowid, "tenant_id": tenant_id, "device_id": device_id, "action": action, "reason": reason.strip(), "status": "queued", "created_at": now, "execution": "queued_for_exporter_worker"}

    def list_exporter_remediation_requests(self, *, tenant_id: str, device_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT id,tenant_id,device_id,action,reason,status,created_at FROM exporter_remediation_requests WHERE tenant_id=?"
        params: tuple[Any, ...] = (tenant_id,)
        if device_id:
            query += " AND device_id=?"
            params += (device_id,)
        query += " ORDER BY id DESC"
        return [dict(row) for row in self._conn.execute(query, params).fetchall()]

    def put_integration(
        self,
        *,
        tenant_id: str,
        kind: str,
        config: dict[str, Any],
        integration_id: str | None = None,
    ) -> str:
        self._validate_id("tenant_id", tenant_id)
        integration_id = integration_id or f"{kind}-{secrets.token_hex(6)}"
        self._validate_id("integration_id", integration_id)
        now = _now()
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, created_at) VALUES (?, ?)",
                (tenant_id, now),
            )
            self._conn.execute(
                """
                INSERT INTO integrations (tenant_id, integration_id, kind, config_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, integration_id) DO UPDATE SET
                    kind=excluded.kind,
                    config_json=excluded.config_json
                """,
                (tenant_id, integration_id, kind, json.dumps(config, sort_keys=True), now),
            )
        return integration_id

    def list_integrations(self, *, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT integration_id, kind, config_json, created_at FROM integrations WHERE tenant_id=? ORDER BY integration_id",
            (tenant_id,),
        ).fetchall()
        return [
            {
                "integration_id": row["integration_id"],
                "kind": row["kind"],
                "config": json.loads(row["config_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def record_transaction_intent(
        self, *, tenant_id: str, device_id: str, intent: dict[str, Any], decision: dict[str, Any]
    ) -> None:
        self._require_device(tenant_id, device_id)
        intent_hash = str(decision.get("intent_hash", ""))
        request_id = str(intent.get("request_id", ""))
        if not intent_hash or not request_id:
            raise ValueError("transaction intent hash and request_id are required")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO transaction_intents
                    (intent_hash, tenant_id, device_id, request_id, intent_json, decision_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(intent_hash) DO UPDATE SET
                    decision_json=excluded.decision_json
                """,
                (intent_hash, tenant_id, device_id, request_id, json.dumps(intent, sort_keys=True), json.dumps(decision, sort_keys=True), _now()),
            )

    def create_transaction_approval(
        self, *, tenant_id: str, device_id: str, intent_hash: str, approver_id: str, expires_at: str
    ) -> dict[str, Any]:
        self._validate_id("approver_id", approver_id)
        self._require_device(tenant_id, device_id)
        try:
            datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("expires_at must be an ISO-8601 timestamp") from exc
        row = self._conn.execute(
            "SELECT decision_json, device_id FROM transaction_intents WHERE intent_hash=? AND tenant_id=?",
            (intent_hash, tenant_id),
        ).fetchone()
        if not row or row["device_id"] != device_id:
            raise KeyError("transaction intent not found")
        decision = json.loads(row["decision_json"])
        if decision.get("action") != "escalate":
            raise ValueError("only escalated transaction intents may receive approval")
        approval = {
            "approval_id": "approval-" + secrets.token_hex(12),
            "intent_hash": intent_hash,
            "tenant_id": tenant_id,
            "device_id": device_id,
            "approver_id": approver_id,
            "expires_at": expires_at,
            "created_at": _now(),
            "consumed_at": None,
        }
        with self._conn:
            self._conn.execute(
                "INSERT INTO transaction_approvals (approval_id, intent_hash, tenant_id, device_id, approver_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                tuple(approval[key] for key in ("approval_id", "intent_hash", "tenant_id", "device_id", "approver_id", "expires_at", "created_at")),
            )
        return approval

    def verify_transaction_approval(self, *, tenant_id: str, device_id: str, intent_hash: str) -> dict[str, Any]:
        self._require_device(tenant_id, device_id)
        row = self._conn.execute(
            "SELECT approval_id, intent_hash, approver_id, expires_at, created_at, consumed_at FROM transaction_approvals WHERE tenant_id=? AND device_id=? AND intent_hash=? ORDER BY created_at DESC LIMIT 1",
            (tenant_id, device_id, intent_hash),
        ).fetchone()
        if not row:
            return {"authorized": False, "reason": "approval not found", "intent_hash": intent_hash}
        approval = dict(row)
        try:
            expired = datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc)
        except ValueError:
            expired = True
        if expired:
            return {"authorized": False, "reason": "approval expired", **approval}
        if approval["consumed_at"]:
            return {"authorized": False, "reason": "approval already consumed", **approval}
        return {"authorized": True, **approval}

    def consume_transaction_approval(
        self, *, tenant_id: str, device_id: str, approval_id: str, intent_hash: str
    ) -> dict[str, Any]:
        """Atomically consume an approval and return the exact approved intent.

        Consumption happens before signing so an approval cannot be replayed if a signer or
        transport is retried. A failed signing attempt requires a new approval.
        """
        self._require_device(tenant_id, device_id)
        now = datetime.now(timezone.utc)
        with self._conn:
            row = self._conn.execute(
                """
                SELECT a.approval_id, a.intent_hash, a.tenant_id, a.device_id, a.approver_id,
                       a.expires_at, a.created_at, a.consumed_at, i.intent_json, i.decision_json
                FROM transaction_approvals a
                JOIN transaction_intents i ON i.intent_hash=a.intent_hash
                WHERE a.approval_id=? AND a.intent_hash=? AND a.tenant_id=? AND a.device_id=?
                """,
                (approval_id, intent_hash, tenant_id, device_id),
            ).fetchone()
            if not row:
                raise KeyError("transaction approval not found")
            if row["consumed_at"]:
                raise ValueError("transaction approval already consumed")
            try:
                expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except ValueError as exc:
                raise ValueError("transaction approval has invalid expiry") from exc
            if expires_at <= now:
                raise ValueError("transaction approval expired")
            consumed_at = now.isoformat().replace("+00:00", "Z")
            updated = self._conn.execute(
                "UPDATE transaction_approvals SET consumed_at=? WHERE approval_id=? AND consumed_at IS NULL",
                (consumed_at, approval_id),
            )
            if updated.rowcount != 1:
                raise ValueError("transaction approval already consumed")
        return {
            "approval_id": row["approval_id"],
            "intent_hash": row["intent_hash"],
            "tenant_id": row["tenant_id"],
            "device_id": row["device_id"],
            "approver_id": row["approver_id"],
            "consumed_at": consumed_at,
            "intent": json.loads(row["intent_json"]),
            "decision": json.loads(row["decision_json"]),
        }

    def dashboard_summary(self, *, tenant_id: str) -> dict[str, Any]:
        devices = self.list_devices(tenant_id=tenant_id)
        decision_rows = self._conn.execute(
            """
            SELECT action, COUNT(*) AS count
            FROM decisions
            WHERE tenant_id=?
            GROUP BY action
            """,
            (tenant_id,),
        ).fetchall()
        latest_rows = self._conn.execute(
            """
            SELECT decision_json, received_at
            FROM decisions
            WHERE tenant_id=?
            ORDER BY id DESC
            LIMIT 25
            """,
            (tenant_id,),
        ).fetchall()
        metrics_row = self._conn.execute(
            """
            SELECT metrics_json, received_at
            FROM metrics
            WHERE tenant_id=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (tenant_id,),
        ).fetchone()
        quality_row = self._conn.execute(
            """
            SELECT quality_json, received_at
            FROM detection_quality
            WHERE tenant_id=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (tenant_id,),
        ).fetchone()
        return {
            "tenant_id": tenant_id,
            "device_count": len(devices),
            "devices": devices,
            "decisions_by_action": {row["action"]: row["count"] for row in decision_rows},
            "latest_decisions": [
                {"received_at": row["received_at"], "decision": json.loads(row["decision_json"])}
                for row in latest_rows
            ],
            "latest_metrics": json.loads(metrics_row["metrics_json"]) if metrics_row else None,
            "latest_detection_quality": json.loads(quality_row["quality_json"]) if quality_row else None,
            "exporter_status": self.list_exporter_status(tenant_id=tenant_id),
            "integrations": self.list_integrations(tenant_id=tenant_id),
        }

    def _touch_device(self, tenant_id: str, device_id: str) -> None:
        self._conn.execute(
            "UPDATE devices SET last_seen_at=? WHERE tenant_id=? AND device_id=?",
            (_now(), tenant_id, device_id),
        )

    def _require_device(self, tenant_id: str, device_id: str) -> None:
        if self.get_device(tenant_id=tenant_id, device_id=device_id) is None:
            raise KeyError(f"unknown device {tenant_id}/{device_id}")

    @staticmethod
    def _validate_id(label: str, value: str) -> None:
        if not value or any(ch in value for ch in "/?#"):
            raise ConfigError(f"{label} must be non-empty and must not contain '/', '?', or '#'")


_DETECTION_LABELS = {"malicious", "benign", "ambiguous", "synthetic"}
_SECURITY_ACTIONS = {"deny", "contain", "escalate"}
_BLOCKING_ACTIONS = {"deny", "contain"}


def _normalize_detection_quality(doc: dict[str, Any]) -> dict[str, Any]:
    samples = doc.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("detection quality requires a non-empty samples list")

    normalized_samples = [_normalize_detection_quality_sample(sample) for sample in samples]
    aggregate = _detection_quality_aggregate(normalized_samples)
    synthetic = bool(doc.get("synthetic")) or any(sample["label"] == "synthetic" for sample in normalized_samples)
    return {
        "schema": "shield.detection_quality.v1",
        "synthetic": synthetic,
        "aggregate": aggregate,
        "samples": normalized_samples,
    }


def _normalize_detection_quality_sample(sample: Any) -> dict[str, Any]:
    if not isinstance(sample, dict):
        raise ValueError("each detection quality sample must be an object")
    event_id = str(sample.get("event_id", "")).strip()
    label = str(sample.get("label", "")).strip().lower()
    label_source = str(sample.get("label_source", "")).strip()
    action = str(sample.get("decision_action", sample.get("action", ""))).strip().lower()
    if not event_id:
        raise ValueError("detection quality sample missing event_id")
    if label not in _DETECTION_LABELS:
        raise ValueError(f"detection quality sample {event_id} has invalid label {label!r}")
    if not label_source:
        raise ValueError(f"detection quality sample {event_id} missing label_source")
    if not action:
        raise ValueError(f"detection quality sample {event_id} missing decision_action")

    receipt = sample.get("integrity_receipt") if isinstance(sample.get("integrity_receipt"), dict) else {}
    normalized = {
        "event_id": event_id,
        "label": label,
        "label_source": label_source,
        "decision_action": action,
        "policy_hash": sample.get("policy_hash"),
        "rule_id": sample.get("rule_id"),
        "export_attempted": bool(sample.get("export_attempted", sample.get("exported", False))),
        "export_success": bool(sample.get("export_success", sample.get("decision_exported", False))),
        "integrity_receipt": sample.get("integrity_receipt"),
        "verification_token": sample.get("verification_token", receipt.get("verification_token")),
        "batch_index": sample.get("batch_index", receipt.get("batch_index")),
        "agent_id": sample.get("agent_id", receipt.get("agent_id")),
        "nonce": sample.get("nonce", receipt.get("nonce")),
        "intended_state_hash": sample.get("intended_state_hash", receipt.get("intended_state_hash")),
        "first_observed_timestamp": sample.get("first_observed_timestamp"),
        "containment_timestamp": sample.get("containment_timestamp"),
    }
    return normalized


def _detection_quality_aggregate(samples: list[dict[str, Any]]) -> dict[str, Any]:
    malicious = [sample for sample in samples if sample["label"] == "malicious"]
    benign = [sample for sample in samples if sample["label"] == "benign"]
    true_positive = [sample for sample in malicious if sample["decision_action"] in _SECURITY_ACTIONS]
    security_decisions = [sample for sample in samples if sample["decision_action"] in _SECURITY_ACTIONS]
    blocking_false_positive = [sample for sample in benign if sample["decision_action"] in _BLOCKING_ACTIONS]
    export_attempted = [sample for sample in samples if sample["export_attempted"]]
    export_success = [sample for sample in export_attempted if sample["export_success"]]
    contain_latencies = [
        latency
        for sample in true_positive
        if sample["decision_action"] == "contain"
        for latency in [_seconds_between(sample.get("first_observed_timestamp"), sample.get("containment_timestamp"))]
        if latency is not None
    ]
    return {
        "sample_count": len(samples),
        "labeled_malicious_events": len(malicious),
        "true_positive_security_decisions": len(true_positive),
        "shield_adr": _rate(len(true_positive), len(malicious)),
        "labeled_benign_events": len(benign),
        "benign_events_blocked_or_contained": len(blocking_false_positive),
        "blocking_false_positive_rate": _rate(len(blocking_false_positive), len(benign)),
        "all_deny_contain_escalate_decisions": len(security_decisions),
        "precision": _rate(len(true_positive), len(security_decisions)),
        "mean_time_to_contain_sec": round(sum(contain_latencies) / len(contain_latencies), 6) if contain_latencies else None,
        "export_attempted_decisions": len(export_attempted),
        "successful_exports": len(export_success),
        "evidence_export_success": _rate(len(export_success), len(export_attempted)),
    }


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _seconds_between(start: Any, end: Any) -> float | None:
    if not start or not end:
        return None
    try:
        start_dt = _parse_timestamp(str(start))
        end_dt = _parse_timestamp(str(end))
    except ValueError:
        return None
    return max(0.0, (end_dt - start_dt).total_seconds())


def _parse_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
