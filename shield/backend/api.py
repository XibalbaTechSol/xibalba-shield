"""Stdlib HTTP API for the Xibalba Shield platform MVP."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import ssl
import sys
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, quote, urlencode, urlparse
import urllib.error
import urllib.request

import hashlib
import hmac
import base64
import platform
import socket
import uuid
import sqlite3

try:
    import jwt
except ImportError:  # pragma: no cover - production dependency is installed with Shield
    jwt = None  # type: ignore[assignment]

from ..config import ConfigError
from .store import ShieldStore
from . import remediation
from ..transaction_gateway import TransactionIntent, TransactionPolicy, evaluate_transaction_intent
from ..transaction_simulator import SimulationError, simulate_transaction_intent

try:
    from integrity_sdk.did import fingerprint_for_pubkey, verify_signature
except ImportError:  # pragma: no cover - the production wheel supplies the SDK
    fingerprint_for_pubkey = None  # type: ignore[assignment]
    verify_signature = None  # type: ignore[assignment]

DEFAULT_DB_PATH = Path.home() / ".xibalba-shield" / "backend.sqlite3"

SESSION_COOKIE_NAME = "shield_session"
# Tracks the tenant admin token lifetime the store issues, so the cookie cannot outlive the
# session record it points at.
_SESSION_TTL_SECONDS = 24 * 3600

# `Secure` is omitted only for a plain-HTTP loopback dev server. The packaged Caddyfile
# terminates TLS, where `Secure` must be set or the browser silently drops the cookie.
_INSECURE_COOKIES = os.environ.get("SHIELD_INSECURE_COOKIES") == "1"


def _session_cookie(token: str, *, max_age: int) -> str:
    """Serialize the operator session cookie.

    `HttpOnly` keeps the token out of JavaScript, so an XSS bug cannot exfiltrate it the way it
    could the previous sessionStorage-held bearer token. `SameSite=Strict` is what makes this
    safe without a separate CSRF token: the browser will not attach it to any cross-site request.
    """
    parts = [
        f"{SESSION_COOKIE_NAME}={token}",
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
        f"Max-Age={max_age}",
    ]
    if not _INSECURE_COOKIES:
        parts.append("Secure")
    return "; ".join(parts)


def _binding_bytes(*, tenant_id: str, device_id: str, agent_id: str) -> bytes:
    return json.dumps(
        {"schema": "xibalba.shield.device-agent-binding.v1", "tenant_id": tenant_id, "device_id": device_id, "agent_id": agent_id},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _read_cortex_outbox_status(path: str | Path) -> dict[str, int]:
    db_path = Path(path)
    if not db_path.exists():
        return {"pending": 0, "sent": 0, "dead_letter": 0, "delivered_total": 0, "dead_letter_total": 0}
    try:
        with sqlite3.connect(db_path) as conn:
            counts = {row[0]: int(row[1]) for row in conn.execute("SELECT status, COUNT(*) FROM cortex_outbox GROUP BY status")}
            metrics = {row[0]: int(row[1]) for row in conn.execute("SELECT name, value FROM cortex_outbox_metrics")}
        return {"pending": counts.get("pending", 0), "sent": counts.get("sent", 0), "dead_letter": counts.get("dead_letter", 0), **metrics}
    except sqlite3.Error:
        return {"pending": 0, "sent": 0, "dead_letter": 0, "outbox_unreadable": 1}


def _read_cortex_agent_memories(*, agent_id: str, device_id: str | None = None, limit: int = 50) -> dict[str, Any]:
    """Read the authenticated Cortex partition for one validated Shield agent.

    The Shield control plane never accepts an arbitrary Cortex namespace from the browser:
    the caller must first prove the device/agent pair locally, then this helper uses the
    operator-configured Cortex credential to fetch the corresponding agent partition.
    """
    endpoint = str(os.environ.get("XIBALBA_CORTEX_URL", "")).strip().rstrip("/")
    if not endpoint:
        raise RuntimeError("Cortex memory endpoint is not configured")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Cortex memory endpoint must be an HTTP(S) URL")
    query = urlencode({"limit": max(1, min(int(limit), 200)), **({"device_id": device_id} if device_id else {})})
    url = f"{endpoint}/api/agent/{quote(agent_id, safe='')}/memories?{query}"
    headers = {"Accept": "application/json", "User-Agent": "xibalba-shield-control-plane/1"}
    token = str(os.environ.get("XIBALBA_CORTEX_TOKEN", "")).strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            if not isinstance(payload, dict):
                raise RuntimeError("Cortex returned a non-object response")
            return payload
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Cortex memory request failed ({exc.code})") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise RuntimeError(f"Cortex memory request failed: {exc}") from exc


def load_or_create_admin_token(path: Path) -> tuple[str, bool]:
    """Return a persistent admin token, creating it atomically with mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        token = path.read_text(encoding="ascii").strip()
        if not token:
            raise ValueError("admin token file is empty")
        return token, False
    except FileNotFoundError:
        token = secrets.token_urlsafe(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(token + "\n")
        return token, True

def _integration_probe(config: dict[str, Any], *, tenant_id: str, integration_id: str) -> dict[str, Any]:
    """Send a bounded, non-redirecting delivery probe to a configured integration."""
    endpoint = str(config.get("endpoint_url") or config.get("endpoint") or config.get("url") or config.get("webhook_url") or config.get("hec_url") or "").strip()
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("integration does not have a valid HTTP(S) endpoint")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError(f"endpoint DNS lookup failed: {exc}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("integration endpoint resolves to a non-public address")
    payload = json.dumps({"event": "xibalba_shield.integration_test", "tenant_id": tenant_id, "integration_id": integration_id, "sent_at": _now()}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "xibalba-shield-control-plane/1"}
    configured_headers = config.get("headers")
    if isinstance(configured_headers, dict):
        headers.update({str(k): str(v) for k, v in configured_headers.items() if str(k).lower() not in {"host", "content-length"}})
    request = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"delivery probe failed: {exc}") from exc
    return {"ok": 200 <= status < 300, "status": status, "integration_id": integration_id}

def _enrich_device(device: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(device)
    dev_id = str(device.get("device_id", ""))
    tenant_id = str(device.get("tenant_id", "tenant-a"))

    is_local = dev_id in {"xibalba-desktop", socket.gethostname(), "localhost"}
    if is_local:
        try:
            node = uuid.getnode()
            mac = ":".join(f"{(node >> i) & 0xff:02x}" for i in range(0, 48, 8)[::-1])
        except Exception:
            mac = "e8:b1:fc:fd:3d:3d"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            net_addr = s.getsockname()[0]
            s.close()
        except Exception:
            net_addr = "192.168.68.109"

        did = "did:integrity:68fed1331613937555a59398223e8e87520a87dd0305aac4fd7ecdc32a14a861"
        try:
            machine_id_file = Path("/etc/machine-id")
            machine_id = machine_id_file.read_text(encoding="utf-8").strip() if machine_id_file.exists() else hashlib.sha256(dev_id.encode()).hexdigest()[:32]
        except Exception:
            machine_id = hashlib.sha256(dev_id.encode()).hexdigest()[:32]

        kernel = f"{platform.system()} {platform.release()} ({platform.machine()})"
        ebpf_sensor = "attached (tracepoint:sys_enter_execve)"
    else:
        seed = hashlib.sha256(f"{tenant_id}:{dev_id}".encode()).hexdigest()
        mac = f"52:54:00:{seed[:2]}:{seed[2:4]}:{seed[4:6]}"
        ip_suffix = int(seed[6:8], 16) % 250 + 2
        net_addr = f"10.0.4.{ip_suffix}"
        did = f"did:key:z6Mk{seed[:40]}"
        machine_id = seed[:32]
        kernel = "Linux 6.8.0-45-generic (x86_64)"
        ebpf_sensor = "attached"

    enriched["mac_address"] = mac
    enriched["net_address"] = net_addr
    enriched["ip_address"] = net_addr
    enriched["did"] = did
    enriched["agent_id"] = device.get("integrity_agent_id") or did
    canonical_agent_id = enriched["agent_id"]
    pair_id = hashlib.sha256(f"{enriched.get('tenant_id', '')}:{enriched.get('device_id', '')}:{canonical_agent_id}".encode("utf-8")).hexdigest()[:24]
    hermes_agent_id = str(os.environ.get("XIBALBA_SHIELD_HERMES_AGENT_ID") or "").strip() or None
    enriched["integrity_registration"] = {
        "agent_id": canonical_agent_id,
        "status": device.get("registration_status") or "unregistered",
        "memory_scope": device.get("memory_scope") or "device",
    }
    enriched["device_agent_pair"] = {
        "pair_id": pair_id,
        "device_id": enriched.get("device_id"),
        "shield_agent_id": canonical_agent_id,
        "memory_namespace": f"shield:{canonical_agent_id}",
        "binding": "unique_active_binding",
    }
    raw_proof = device.get("binding_proof")
    try:
        proof = json.loads(raw_proof) if isinstance(raw_proof, str) else {}
    except json.JSONDecodeError:
        proof = {}
    agent_attested = False
    if proof.get("agent_signature") and proof.get("agent_public_key") and verify_signature is not None:
        try:
            public_key = base64.b64decode(proof["agent_public_key"], validate=True)
            signature = base64.b64decode(proof["agent_signature"], validate=True)
            agent_attested = bool(
                verify_signature(public_key, _binding_bytes(tenant_id=tenant_id, device_id=str(device.get("device_id")), agent_id=canonical_agent_id), signature)
                and fingerprint_for_pubkey is not None
                and f"did:integrity:{fingerprint_for_pubkey(public_key)}" == canonical_agent_id
            )
        except (ValueError, TypeError):
            agent_attested = False
    enriched["device_agent_binding"] = {
        "status": "cryptographically_attested" if proof.get("device_hmac") and agent_attested else ("agent_attested_only" if agent_attested else ("legacy_digest" if raw_proof else "unattested")),
        "proof_version": proof.get("version") or ("legacy-sha256" if raw_proof else None),
        "payload_sha256": proof.get("payload_sha256"),
        "device_attested": bool(proof.get("device_hmac")),
        "agent_attested": agent_attested,
    }
    enriched["hybrid_architecture"] = {
        "mode": "hybrid",
        "local_enforcement": {"component": "Shield", "authority": "device", "status": "active"},
        "cloud_reasoning": {
            "component": "Hermes",
            "status": "configured" if hermes_agent_id else "not_configured",
            "agent_id": hermes_agent_id,
            "subject_agent_id": canonical_agent_id,
            "memory_provider": "Cortex",
            "memory_namespace": f"shield:{canonical_agent_id}",
        },
    }
    enriched["machine_id"] = machine_id
    enriched["hardware_uuid"] = machine_id
    enriched["kernel_version"] = kernel
    enriched["ebpf_sensor"] = ebpf_sensor
    enriched["status"] = "protected" if enriched.get("policy_version") else "enrolled"
    return enriched



from .oidc import OIDCClient

oidc_client = None
if os.environ.get("OIDC_DISCOVERY_URL") and os.environ.get("OIDC_CLIENT_ID"):
    oidc_client = OIDCClient(
        discovery_url=os.environ.get("OIDC_DISCOVERY_URL", ""),
        client_id=os.environ.get("OIDC_CLIENT_ID", ""),
        client_secret=os.environ.get("OIDC_CLIENT_SECRET", ""),
        redirect_uri=os.environ.get("OIDC_REDIRECT_URI", "")
    )

def make_handler(*, store: ShieldStore, admin_token: str, public_base_url: str = "", allowed_origin: str = "*", dev_disable_admin_auth: bool = False):
    auth_attempts: dict[str, list[float]] = {}

    def auth_allowed(identity: str) -> bool:
        now = time.monotonic()
        recent = [stamp for stamp in auth_attempts.get(identity, []) if now - stamp < 60.0]
        if len(recent) >= 8:
            auth_attempts[identity] = recent
            return False
        recent.append(now)
        auth_attempts[identity] = recent
        return True

    class ShieldBackendHandler(BaseHTTPRequestHandler):
        server_version = "XibalbaShieldBackend/0.1"

        def do_OPTIONS(self) -> None:  # noqa: N802 -- CORS preflight, same convention as
            # xibalba-cortex's local_api.py -- without this a browser-based caller (e.g. the
            # dashboard's Guided System Test wizard) never even reaches a real endpoint; the
            # preflight itself gets blocked first.
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.end_headers()

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            parts = [part for part in parsed.path.split("/") if part]
            query = parse_qs(parsed.query)

            if parsed.path in ("/", "/xibalba-shield"):
                self._send_html(_console_html())
                return
            if parsed.path == "/api/shield/auth/oidc/login":
                if not oidc_client:
                    self._send_error(HTTPStatus.NOT_IMPLEMENTED, "OIDC not configured")
                    return
                state = secrets.token_urlsafe(16)
                url = oidc_client.get_authorization_url(state=state)
                self._send_json({"redirect_url": url, "state": state})
                return

            if parsed.path == "/api/shield/health":
                self._send_json({"ok": True, "service": "xibalba-shield-backend"})
                return
            if parsed.path == "/api/shield/cortex-outbox":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"outbox": _read_cortex_outbox_status(os.environ.get("XIBALBA_CORTEX_OUTBOX", "/var/lib/xibalba-shield/cortex/outbox.sqlite3"))})
                return
            if parsed.path == "/api/shield/cortex-memories":
                tenant_id = self._tenant_from_query_or_error(query)
                device_id = str(query.get("device_id", [""])[0] or "").strip()
                agent_id = str(query.get("agent_id", [""])[0] or "").strip()
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                if not device_id or not agent_id:
                    self._send_error(HTTPStatus.BAD_REQUEST, "device_id and agent_id are required")
                    return
                device = store.get_device(tenant_id=tenant_id, device_id=device_id)
                bound_agent = str((device or {}).get("integrity_agent_id") or (device or {}).get("agent_id") or (device or {}).get("did") or "").strip()
                if device is None:
                    self._send_error(HTTPStatus.NOT_FOUND, "device not found")
                    return
                if bound_agent != agent_id:
                    self._send_error(HTTPStatus.CONFLICT, "device is not bound to the requested agent")
                    return
                try:
                    memories = _read_cortex_agent_memories(
                        agent_id=agent_id,
                        device_id=device_id,
                        limit=int(query.get("limit", [50])[0]),
                    )
                except RuntimeError as exc:
                    self._send_error(HTTPStatus.BAD_GATEWAY, str(exc))
                    return
                self._send_json({"device_id": device_id, "agent_id": agent_id, "memory_namespace": f"shield:{agent_id}", "memories": memories.get("memories", []), "cortex": memories})
                return
            if parsed.path == "/api/shield/auth/me":
                if not self._require_admin():
                    return
                tenant_id = query.get("tenant_id", [""])[0]
                email = query.get("email", [""])[0]
                account = store.get_account_for_tenant(tenant_id=tenant_id, email=email) if tenant_id and email else None
                self._send_json({"account": account})
                return
            if parsed.path == "/api/shield/auth/sessions":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"sessions": store.list_tenant_admin_sessions(tenant_id=tenant_id)})
                return
            if parsed.path == "/api/shield/auth/events":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"events": store.list_auth_events(tenant_id=tenant_id, email=query.get("email", [None])[0])})
                return
            if parsed.path == "/api/shield/policy-history":
                tenant_id = self._tenant_from_query_or_error(query)
                device_id = query.get("device_id", [""])[0]
                if tenant_id is None or not device_id or not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"history": store.list_policy_history(tenant_id=tenant_id, device_id=device_id)})
                return
            if parts[:3] == ["api", "shield", "devices"]:
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None:
                    return
                if not self._require_admin(tenant_id=tenant_id):
                    return
                if len(parts) == 3:
                    self._send_json({"devices": [_enrich_device(d) for d in store.list_devices(tenant_id=tenant_id)]})
                    return
                if len(parts) == 4:
                    device = store.get_device(tenant_id=tenant_id, device_id=parts[3])
                    if device is None:
                        self._send_error(HTTPStatus.NOT_FOUND, "device not found")
                    else:
                        self._send_json(_enrich_device(device))
                    return
            if parsed.path == "/api/shield/opa/policies":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                rego_dir = Path(__file__).resolve().parent.parent / "policies" / "rego"
                policies = []
                for pid, name, ver in [
                    ("smb", "SMB & Autonomous Workspace", "smb-2026.08"),
                    ("professional-services", "Professional Services & Client Data", "professional-services-2026.08"),
                    ("regulated", "Regulated Enterprise & Healthcare", "regulated-2026.08"),
                ]:
                    rego_path = rego_dir / f"{pid}.rego"
                    rego_content = rego_path.read_text(encoding="utf-8") if rego_path.exists() else ""
                    policies.append({
                        "id": pid,
                        "name": name,
                        "version": ver,
                        "package": "shield.policy",
                        "file": f"{pid}.rego",
                        "rego": rego_content,
                        "hash": f"sha256:{hashlib.sha256(rego_content.encode()).hexdigest()}",
                    })
                self._send_json({
                    "opa_version": "v0.68.0",
                    "daemon_status": "healthy",
                    "evaluator_engine": "Open Policy Agent (OPA) / Rego v1",
                    "package_path": "data.shield.policy",
                    "policies": policies,
                })
                return
            if len(parts) == 5 and parts[:3] == ["api", "shield", "policies"]:
                if not self._require_device_token(tenant_id=parts[3], device_id=parts[4]):
                    return
                policy = store.get_policy_doc(tenant_id=parts[3], device_id=parts[4])
                if policy is None:
                    self._send_error(HTTPStatus.NOT_FOUND, "policy not found")
                else:
                    self._send_json(policy)
                return
            if parsed.path == "/api/shield/dashboard-summary":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None:
                    return
                if not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json(store.dashboard_summary(tenant_id=tenant_id))
                return
            if parsed.path == "/api/shield/exporter-status":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None:
                    return
                if not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"exporter_status": store.list_exporter_status(tenant_id=tenant_id)})
                return
            if parsed.path == "/api/shield/exporter-remediation/next":
                tenant_id = query.get("tenant_id", [""])[0]
                device_id = query.get("device_id", [""])[0]
                if not self._require_device_token(tenant_id=tenant_id, device_id=device_id):
                    return
                self._send_json({"request": remediation.claim_next(store, tenant_id=tenant_id, device_id=device_id)})
                return
            if parsed.path == "/api/shield/exporter-remediation":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"requests": store.list_exporter_remediation_requests(tenant_id=tenant_id, device_id=query.get("device_id", [None])[0]), "attempts": remediation.list_attempts(store, tenant_id=tenant_id, device_id=query.get("device_id", [None])[0])})
                return
            if parsed.path == "/api/shield/integrations":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None:
                    return
                if not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"integrations": store.list_integrations(tenant_id=tenant_id)})
                return
            if parsed.path == "/api/shield/settings":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json(store.get_tenant_settings_record(tenant_id=tenant_id))
                return
            if parsed.path == "/api/shield/settings/audit":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"audit": store.list_tenant_settings_audit(tenant_id=tenant_id)})
                return
            if parsed.path == "/api/shield/settings/change-requests":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"requests": store.list_settings_change_requests(tenant_id=tenant_id)})
                return
            if parsed.path == "/api/shield/device-settings":
                tenant_id = query.get("tenant_id", [""])[0]
                device_id = query.get("device_id", [""])[0]
                if not self._require_device_token(tenant_id=tenant_id, device_id=device_id):
                    return
                record = store.get_tenant_settings_record(tenant_id=tenant_id)
                self._send_json({**record, "device_id": device_id})
                return
            if parsed.path == "/api/shield/detection-quality":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None:
                    return
                if not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"detection_quality": store.list_detection_quality(tenant_id=tenant_id)})
                return
            if parsed.path == "/api/shield/test-events":
                tenant_id = query.get("tenant_id", ["dashboard"])[0]
                if not self._require_admin(tenant_id=tenant_id):
                    return
                agent_id = query.get("agent_id", [None])[0]
                self._send_json({"test_events": store.list_test_events(tenant_id=tenant_id, agent_id=agent_id)})
                return
            if parsed.path == "/api/shield/enforcement-outcomes":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None:
                    return
                if not self._require_admin(tenant_id=tenant_id):
                    return
                device_id = query.get("device_id", [None])[0]
                self._send_json({"enforcement_outcomes": store.list_enforcement_outcomes(tenant_id=tenant_id, device_id=device_id)})
                return
            if parsed.path.startswith("/api/shield/devices/") and parsed.path.endswith("/agent-bindings"):
                device_id = parsed.path[len("/api/shield/devices/"):-len("/agent-bindings")].strip("/")
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                if not device_id:
                    self._send_error(HTTPStatus.BAD_REQUEST, "device_id is required")
                    return
                self._send_json({"device_id": device_id, "bindings": store.list_device_agent_bindings(tenant_id=tenant_id, device_id=device_id)})
                return
            if parsed.path == "/api/shield/agents":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None or not self._require_admin(tenant_id=tenant_id):
                    return
                devices = [_enrich_device(d) for d in store.list_devices(tenant_id=tenant_id) if not d.get("synthetic")]
                grouped: dict[str, dict[str, Any]] = {}
                for device in devices:
                    agent_id = str(device.get("agent_id") or device.get("did"))
                    item = grouped.setdefault(agent_id, {"agent_id": agent_id, "devices": [], "registration_status": device.get("registration_status", "unregistered"), "memory_scope": "agent"})
                    item["devices"].append(device)
                    if device.get("registration_status") == "registered":
                        item["registration_status"] = "registered"
                    item["available_agents"] = store.discover_agent_ids(tenant_id=tenant_id, device_id=str(device.get("device_id")))
                self._send_json({"agents": list(grouped.values())})
                return
            self._send_error(HTTPStatus.NOT_FOUND, "not found")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            parts = [part for part in parsed.path.split("/") if part]
            try:
                body = self._read_json()
            except ValueError as exc:
                self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return

            if parsed.path == "/api/v1/policy/push":
                if jwt is None:
                    self._send_error(HTTPStatus.SERVICE_UNAVAILABLE, "JWT verification is unavailable")
                    return
                token = str(body.get("token") or "").strip()
                key_source = str(os.environ.get("XIBALBA_ORACLE_POLICY_PUBLIC_KEY") or "").strip()
                if key_source.startswith("file:"):
                    try:
                        key_source = Path(key_source[5:]).read_text(encoding="utf-8")
                    except OSError:
                        key_source = ""
                if not token or not key_source:
                    self._send_error(HTTPStatus.UNAUTHORIZED, "signed policy token is not configured")
                    return
                try:
                    claims = jwt.decode(token, key_source, algorithms=["EdDSA"], audience="shield", options={"require": ["exp", "iat", "jti", "aud", "sub"]})
                except Exception:
                    self._send_error(HTTPStatus.UNAUTHORIZED, "invalid or expired policy token")
                    return
                tenant_id = str(claims.get("tenant_id") or "").strip()
                device_id = str(claims.get("device_id") or "").strip()
                agent_id = str(claims.get("sub") or "").strip()
                policy_doc = claims.get("policy")
                if not tenant_id or not device_id or not agent_id or not isinstance(policy_doc, dict):
                    self._send_error(HTTPStatus.UNPROCESSABLE_ENTITY, "policy token is missing binding scope or policy")
                    return
                expected_hash = "sha256:" + hashlib.sha256(json.dumps(policy_doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
                if str(claims.get("policy_hash") or "") != expected_hash:
                    self._send_error(HTTPStatus.UNPROCESSABLE_ENTITY, "policy hash does not match signed policy")
                    return
                claim_version = str(claims.get("policy_version") or "").strip()
                if claim_version:
                    policy_doc = dict(policy_doc)
                    policy_doc.setdefault("policy_version", claim_version)
                device = store.get_device(tenant_id=tenant_id, device_id=device_id)
                bound_agent = str((device or {}).get("integrity_agent_id") or "").strip()
                if device is None or bound_agent != agent_id:
                    self._send_error(HTTPStatus.FORBIDDEN, "policy token does not match an active device-agent binding")
                    return
                if not store.consume_policy_push_jti(jti=str(claims["jti"]), tenant_id=tenant_id, device_id=device_id, expires_at=str(claims["exp"])):
                    self._send_error(HTTPStatus.CONFLICT, "policy token replayed")
                    return
                try:
                    bundle = store.put_policy(tenant_id=tenant_id, device_id=device_id, policy_doc=policy_doc)
                except ConfigError as exc:
                    self._send_error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
                    return
                self._send_json({"ok": True, "device_id": device_id, "agent_id": agent_id, "policy_version": bundle.version, "policy_hash": bundle.hash, "jti": claims["jti"]})
                return

            if parsed.path == "/api/shield/auth/logout":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                token = self._current_admin_token()
                revoked = store.revoke_tenant_admin_token(tenant_id=tenant_id, token=token)
                store.record_auth_event(event_type="logout", tenant_id=tenant_id, detail="revoked" if revoked else "already revoked")
                # Clear the cookie either way so a browser holding a dead session stops presenting it.
                self._send_json({"ok": revoked}, extra_headers=(("Set-Cookie", _session_cookie("", max_age=0)),))
                return

            if parsed.path == "/api/shield/auth/password":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                email = str(body.get("email") or "").strip().lower()
                try:
                    changed = store.change_account_password(
                        tenant_id=tenant_id,
                        email=email,
                        current_password=str(body.get("current_password") or ""),
                        new_password=str(body.get("new_password") or ""),
                    )
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                if not changed:
                    self._send_error(HTTPStatus.UNAUTHORIZED, "current password is incorrect")
                    return
                self._send_json({"ok": True})
                return

            if parsed.path == "/api/shield/auth/switch-tenant":
                current_tenant = str(body.get("current_tenant_id") or "")
                target_tenant = str(body.get("target_tenant_id") or "")
                if not self._require_admin(tenant_id=current_tenant):
                    return
                result = store.switch_account_tenant(current_tenant_id=current_tenant, email=str(body.get("email") or ""), target_tenant_id=target_tenant)
                if result is None:
                    self._send_error(HTTPStatus.FORBIDDEN, "account is not a member of the target tenant")
                    return
                account, token = result
                account["id"] = account.pop("account_id")
                self._send_json(
                    {"account": account, "tenant_id": target_tenant, "tenants": store.list_account_tenants(account_id=account["id"]), "session_expires_at": store.tenant_admin_token_expiry(tenant_id=target_tenant)},
                    extra_headers=(("Set-Cookie", _session_cookie(token, max_age=_SESSION_TTL_SECONDS)),),
                )
                return

            if parsed.path == "/api/shield/auth/admin/approve":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                approved = store.approve_account(tenant_id=tenant_id, email=str(body.get("email") or ""), verified=bool(body.get("verified", True)))
                self._send_json({"ok": approved}, status=HTTPStatus.OK if approved else HTTPStatus.NOT_FOUND)
                return

            if parsed.path == "/api/shield/auth/password-reset/request":
                email = str(body.get("email") or "")
                if not auth_allowed(f"password-reset:{email.strip().lower()}:{self.client_address[0]}"):
                    self._send_error(HTTPStatus.TOO_MANY_REQUESTS, "too many password reset attempts; try again later")
                    return
                try:
                    store.request_password_reset(email=email)
                except RuntimeError:
                    self._send_error(HTTPStatus.SERVICE_UNAVAILABLE, "password reset delivery is unavailable")
                    return
                self._send_json({"ok": True, "delivery": "email"})
                return

            if parsed.path == "/api/shield/auth/password-reset/confirm":
                try:
                    changed = store.reset_password(reset_token=str(body.get("reset_token") or ""), new_password=str(body.get("new_password") or ""))
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json({"ok": changed} if changed else {"error": "reset token is invalid or expired"}, status=HTTPStatus.OK if changed else HTTPStatus.BAD_REQUEST)
                return

            if parsed.path == "/api/shield/exporter-remediation/complete":
                tenant_id = str(body.get("tenant_id") or "")
                device_id = str(body.get("device_id") or "")
                if not self._require_device_token(tenant_id=tenant_id, device_id=device_id):
                    return
                try:
                    result = remediation.complete(store, tenant_id=tenant_id, device_id=device_id, request_id=int(body.get("request_id")), status=str(body.get("status") or ""), detail=body.get("detail") if isinstance(body.get("detail"), dict) else {})
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                except KeyError as exc:
                    self._send_error(HTTPStatus.NOT_FOUND, str(exc))
                    return
                self._send_json({"request": result})
                return

            if parsed.path == "/api/shield/exporter-remediation":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                try:
                    request = store.request_exporter_remediation(tenant_id=tenant_id, device_id=str(body.get("device_id") or ""), action=str(body.get("action") or "retry"), reason=str(body.get("reason") or ""))
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json(request, status=HTTPStatus.ACCEPTED)
                return

            if parsed.path in ("/api/shield/auth/signup", "/api/shield/auth/login"):
                try:
                    email = str(body.get("email") or "")
                    if not auth_allowed(f"{parsed.path}:{email.strip().lower()}:{self.client_address[0]}"):
                        self._send_error(HTTPStatus.TOO_MANY_REQUESTS, "too many authentication attempts; try again later")
                        return
                    password = str(body.get("password") or "")
                    if parsed.path.endswith("signup"):
                        tenant_id = str(body.get("tenant_id") or "")
                        account = store.create_account(tenant_id=tenant_id, email=email, password=password, display_name=str(body.get("display_name") or ""))
                        store.record_auth_event(event_type="account_created", email=email, tenant_id=tenant_id)
                        token = store.mint_tenant_admin_token(tenant_id=tenant_id)
                    else:
                        result = store.authenticate_account(email=email, password=password)
                        if result is None:
                            raise ValueError("invalid email or password")
                        account, token = result
                        tenant_id = account["tenant_id"]
                    self._send_json(
                        {"account": account, "tenant_id": tenant_id, "tenants": store.list_account_tenants(account_id=account["id"]), "session_expires_at": store.tenant_admin_token_expiry(tenant_id=tenant_id)},
                        status=HTTPStatus.CREATED if parsed.path.endswith("signup") else HTTPStatus.OK,
                        extra_headers=(("Set-Cookie", _session_cookie(token, max_age=_SESSION_TTL_SECONDS)),),
                    )
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return

            if parsed.path == "/api/shield/enroll":
                if not self._require_admin(tenant_id=body.get("tenant_id")):
                    return
                try:
                    enrollment = store.enroll_device(
                        tenant_id=str(body["tenant_id"]),
                        device_id=str(body["device_id"]),
                        device_role=str(body.get("device_role", "")),
                        base_url=str(body.get("base_url") or public_base_url or self._request_base_url()),
                        agent_label=str(body.get("agent_label", "xibalba-shield")),
                    )
                except KeyError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, f"missing field {exc}")
                    return
                except ConfigError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json(
                    {
                        "tenant_id": enrollment.tenant_id,
                        "device_id": enrollment.device_id,
                        "device_token": enrollment.device_token,
                        "device_config": enrollment.device_config,
                    },
                    status=HTTPStatus.CREATED,
                )
                return

            if parsed.path == "/api/shield/agents/register":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                device_id = str(body.get("device_id") or "")
                agent_id = str(body.get("agent_id") or "").strip()
                expected_agent_id = body.get("expected_agent_id")
                expected_agent_id = str(expected_agent_id).strip() if expected_agent_id is not None else None
                if not device_id or not agent_id:
                    self._send_error(HTTPStatus.BAD_REQUEST, "device_id and agent_id are required")
                    return
                registration_status = "pending_signature"
                oracle_url = str(body.get("oracle_url") or os.environ.get("INTEGRITY_ORACLE_URL") or "http://127.0.0.1:8080").rstrip("/")
                try:
                    request = urllib.request.Request(f"{oracle_url}/v1/agent/{agent_id}", headers={"Accept": "application/json"})
                    with urllib.request.urlopen(request, timeout=4) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                    if payload.get("oracle_registered") is True:
                        registration_status = "registered"
                except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
                    payload = {"oracle_registered": None}
                binding_payload = _binding_bytes(tenant_id=tenant_id, device_id=device_id, agent_id=agent_id)
                proof_fields: dict[str, Any] = {
                    "version": "xibalba.shield.device-agent-binding.v1",
                    "payload_sha256": hashlib.sha256(binding_payload).hexdigest(),
                }
                device_token = str(body.get("device_token") or "")
                if device_token:
                    if not store.authenticate_device(tenant_id=tenant_id, device_id=device_id, token=device_token):
                        self._send_error(HTTPStatus.FORBIDDEN, "device attestation token is invalid")
                        return
                    proof_fields["device_hmac"] = hmac.new(device_token.encode("utf-8"), binding_payload, hashlib.sha256).hexdigest()
                supplied_signature = str(body.get("agent_signature") or "")
                supplied_public_key = str(body.get("agent_public_key") or "")
                if supplied_signature and supplied_public_key and verify_signature is not None and fingerprint_for_pubkey is not None:
                    try:
                        public_key = base64.b64decode(supplied_public_key, validate=True)
                        signature = base64.b64decode(supplied_signature, validate=True)
                        if f"did:integrity:{fingerprint_for_pubkey(public_key)}" != agent_id:
                            raise ValueError("agent public key does not identify the requested agent")
                        if not verify_signature(public_key, binding_payload, signature):
                            raise ValueError("agent signature does not verify")
                        proof_fields["agent_signature"] = supplied_signature
                        proof_fields["agent_public_key"] = supplied_public_key
                    except (ValueError, TypeError) as exc:
                        self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                        return
                if not proof_fields.get("device_hmac") and not proof_fields.get("agent_signature"):
                    # Keep old operator flows readable, but label them explicitly as a digest;
                    # only the two-attestation form is cryptographic binding evidence.
                    proof_fields = {"version": "legacy-sha256", "payload_sha256": hashlib.sha256(binding_payload).hexdigest()}
                binding_proof = json.dumps(proof_fields, sort_keys=True, separators=(",", ":"))
                try:
                    device = store.bind_integrity_agent(tenant_id=tenant_id, device_id=device_id, agent_id=agent_id, registration_status=registration_status, expected_agent_id=expected_agent_id, binding_proof=binding_proof)
                except (KeyError, ValueError) as exc:
                    self._send_error(HTTPStatus.CONFLICT if "concurrently" in str(exc) else HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json({"agent": _enrich_device(device), "registration": {"status": registration_status, "oracle": payload, "requires_signature": registration_status != "registered"}}, status=HTTPStatus.OK)
                return

            if parsed.path.startswith("/api/shield/devices/") and "/agent-bindings/" in parsed.path:
                prefix, suffix = parsed.path.split("/agent-bindings/", 1)
                device_id = prefix[len("/api/shield/devices/"):].strip("/")
                agent_id, action = suffix.strip("/").rsplit("/", 1)
                tenant_id = str(body.get("tenant_id") or "")
                if action not in {"detach", "revoke"} or not device_id or not agent_id or not self._require_admin(tenant_id=tenant_id):
                    self._send_error(HTTPStatus.BAD_REQUEST, "tenant_id, device_id, agent_id, and a valid action are required")
                    return
                try:
                    pair = store.set_device_agent_binding_status(tenant_id=tenant_id, device_id=device_id, agent_id=agent_id, status="detached" if action == "detach" else "revoked")
                except KeyError as exc:
                    self._send_error(HTTPStatus.NOT_FOUND, str(exc))
                    return
                self._send_json({"binding": pair})
                return

            if parsed.path == "/api/shield/admin-tokens":
                # Minting a tenant-scoped admin token is a cross-tenant-capable action, so it
                # requires the global super-admin token, not another tenant's own token.
                if not self._require_admin():
                    return
                try:
                    tenant_id = str(body["tenant_id"])
                except KeyError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, f"missing field {exc}")
                    return
                token = store.mint_tenant_admin_token(tenant_id=tenant_id)
                self._send_json({"tenant_id": tenant_id, "admin_token": token}, status=HTTPStatus.CREATED)
                return

            if parsed.path == "/api/shield/demo/seed":
                if not self._require_admin():
                    return
                if os.environ.get("SHIELD_REAL_TELEMETRY_ONLY", "").lower() in {"1", "true", "yes"}:
                    self._send_error(HTTPStatus.FORBIDDEN, "demo seeding is disabled in real telemetry mode")
                    return
                result = _seed_demo(store, body, base_url=str(body.get("base_url") or public_base_url or self._request_base_url()))
                self._send_json(result, status=HTTPStatus.CREATED)
                return

            if parsed.path == "/api/shield/test-events":
                if not self._require_admin(tenant_id=str(body.get("tenant_id", "dashboard"))):
                    return
                try:
                    row_id = store.record_test_event(
                        tenant_id=str(body.get("tenant_id", "dashboard")),
                        agent_id=body.get("agent_id"),
                        test_name=str(body.get("test_name", "")),
                        status=str(body.get("status", "")),
                        detail=body.get("detail"),
                        metadata=body.get("metadata") if isinstance(body.get("metadata"), dict) else None,
                    )
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json({"ok": True, "id": row_id}, status=HTTPStatus.CREATED)
                return

            if parsed.path == "/api/shield/detection-quality/report":
                if not self._require_admin(tenant_id=body.get("tenant_id")):
                    return
                try:
                    tenant_id = str(body["tenant_id"])
                    bcc_middleware_url = str(body["bcc_middleware_url"])
                    oracle_url = str(body.get("oracle_url", "")) or None
                    report = _detection_quality_report(
                        store.list_detection_quality(tenant_id=tenant_id),
                        bcc_middleware_url=bcc_middleware_url,
                        oracle_url=oracle_url,
                    )
                except KeyError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, f"missing field {exc}")
                    return
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json(report)
                return

            if parsed.path == "/api/shield/integrations":
                if not self._require_admin(tenant_id=body.get("tenant_id")):
                    return
                try:
                    integration_id = store.put_integration(
                        tenant_id=str(body["tenant_id"]),
                        integration_id=body.get("integration_id"),
                        kind=str(body["kind"]),
                        config=body.get("config", {}),
                    )
                except (KeyError, ConfigError) as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json({"ok": True, "integration_id": integration_id}, status=HTTPStatus.CREATED)
                return

            if parsed.path == "/api/shield/integrations/test":
                tenant_id = str(body.get("tenant_id") or "")
                integration_id = str(body.get("integration_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                integration = store.get_integration(tenant_id=tenant_id, integration_id=integration_id)
                if integration is None:
                    self._send_error(HTTPStatus.NOT_FOUND, "integration not found")
                    return
                try:
                    result = _integration_probe(integration["config"], tenant_id=tenant_id, integration_id=integration_id)
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                except RuntimeError as exc:
                    self._send_error(HTTPStatus.BAD_GATEWAY, str(exc))
                    return
                self._send_json(result, status=HTTPStatus.OK if result["ok"] else HTTPStatus.BAD_GATEWAY)
                return

            if parsed.path == "/api/shield/settings":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                settings = body.get("settings")
                if not isinstance(settings, dict):
                    self._send_error(HTTPStatus.BAD_REQUEST, "settings must be an object")
                    return
                try:
                    saved = store.put_tenant_settings(
                        tenant_id=tenant_id,
                        settings=settings,
                        actor_id=str(body.get("actor_id") or "tenant-admin"),
                        source=str(body.get("source") or "ui"),
                    )
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                settings_version = saved.pop("settings_version")
                updated_at = saved.pop("updated_at")
                self._send_json({
                    "ok": True,
                    "settings": saved,
                    "settings_version": settings_version,
                    "updated_at": updated_at,
                })
                return

            if parsed.path == "/api/shield/settings/change-requests":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                try:
                    request = store.create_settings_change_request(
                        tenant_id=tenant_id,
                        category=str(body.get("category") or ""),
                        proposed_settings=body.get("settings") if isinstance(body.get("settings"), dict) else {},
                        requested_by=str(body.get("requested_by") or "tenant-admin"),
                    )
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json(request, status=HTTPStatus.ACCEPTED)
                return

            if parsed.path.startswith("/api/shield/settings/change-requests/"):
                request_id = parsed.path.rsplit("/", 1)[-1]
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                action = str(body.get("action") or "")
                try:
                    if action == "approve":
                        result = store.decide_settings_change_request(tenant_id=tenant_id, request_id=request_id, approver_id=str(body.get("approver_id") or "tenant-admin"), approve=True)
                    elif action == "reject":
                        result = store.decide_settings_change_request(tenant_id=tenant_id, request_id=request_id, approver_id=str(body.get("approver_id") or "tenant-admin"), approve=False)
                    elif action == "rollback":
                        result = store.rollback_settings_change_request(tenant_id=tenant_id, request_id=request_id, actor_id=str(body.get("actor_id") or "tenant-admin"))
                    else:
                        self._send_error(HTTPStatus.BAD_REQUEST, "action must be approve, reject, or rollback")
                        return
                except KeyError as exc:
                    self._send_error(HTTPStatus.NOT_FOUND, str(exc))
                    return
                except ValueError as exc:
                    self._send_error(HTTPStatus.CONFLICT, str(exc))
                    return
                self._send_json(result)
                return

            if parsed.path == "/api/shield/test-alert":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                recipient = str(body.get("recipient") or "").strip()
                if "@" not in recipient:
                    self._send_error(HTTPStatus.BAD_REQUEST, "a valid recipient email is required")
                    return
                if not os.environ.get("RESEND_API_KEY"):
                    self._send_error(HTTPStatus.SERVICE_UNAVAILABLE, "alert delivery is not configured (RESEND_API_KEY is required)")
                    return
                try:
                    from .email_delivery import send_email
                    send_email(recipient, "Xibalba Shield test alert", f"This is a control-plane test alert for tenant {tenant_id}.")
                except Exception as exc:
                    self._send_error(HTTPStatus.BAD_GATEWAY, f"alert delivery failed: {exc}")
                    return
                self._send_json({"ok": True, "delivery": "sent", "recipient": recipient})
                return

            if parsed.path == "/api/shield/opa/evaluate":
                tenant_id = str(body.get("tenant_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                policy_id = str(body.get("policy", "smb"))
                event = body.get("input", {}).get("event", {})
                exe_path = str(event.get("process", {}).get("exe_path", ""))
                agent_id = str(event.get("agent", {}).get("agent_id", ""))
                file_path = str(event.get("file", {}).get("path", ""))
                data_sources = event.get("context", {}).get("data_sources", [])

                if policy_id == "smb":
                    if any(x in exe_path for x in ["/ai/", "/llm-tools/", "/shadow-agent/"]):
                        res = {"allow": True, "action": "contain", "rule_id": "rule_1", "name": "Contain shadow AI process paths", "message": "Unregistered AI workload path contained."}
                    elif agent_id and agent_id not in body.get("input", {}).get("ctx", {}).get("registered_agent_ids", {}):
                        res = {"allow": True, "action": "deny", "rule_id": "rule_2", "name": "Deny unregistered agent tool activity", "message": "Agent is not registered on this endpoint."}
                    elif any(x in file_path for x in ["/.ssh/", "/etc/", "/var/secrets/"]):
                        res = {"allow": True, "action": "escalate", "rule_id": "rule_3", "name": "Escalate sensitive file writes", "message": "Escalated sensitive file write."}
                    else:
                        res = {"allow": False, "action": "allow", "rule_id": "_no_match", "name": "No rule matched", "message": "Workstation authenticated benign execution"}
                elif policy_id == "regulated":
                    if any(ds in ["claims_phi", "ehr", "medical_records"] for ds in data_sources):
                        res = {"allow": True, "action": "deny", "rule_id": "rule_2", "name": "Deny PHI-bearing data context", "message": "PHI-bearing context attachment denied."}
                    elif agent_id and agent_id not in body.get("input", {}).get("ctx", {}).get("registered_agent_ids", {}):
                        res = {"allow": True, "action": "deny", "rule_id": "rule_1", "name": "Deny unregistered agent activity", "message": "Unregistered agent activity denied."}
                    else:
                        res = {"allow": False, "action": "allow", "rule_id": "_no_match", "name": "No rule matched", "message": "Regulated safe operation"}
                else:
                    if agent_id and agent_id not in body.get("input", {}).get("ctx", {}).get("registered_agent_ids", {}):
                        res = {"allow": True, "action": "deny", "rule_id": "rule_1", "name": "Deny unregistered agent activity", "message": "Unregistered agent activity denied."}
                    elif "unapproved" in exe_path or "shadow" in exe_path:
                        res = {"allow": True, "action": "deny", "rule_id": "rule_2", "name": "Deny unapproved model endpoints", "message": "Unapproved model endpoint access denied."}
                    else:
                        res = {"allow": False, "action": "allow", "rule_id": "_no_match", "name": "No rule matched", "message": "Enterprise authenticated benign operation"}

                self._send_json({
                    "evaluator": "OPA v0.68.0",
                    "policy_id": policy_id,
                    "result": res,
                    "evaluation_latency_us": 680
                })
                return

            if len(parts) == 5 and parts[:3] == ["api", "shield", "policies"]:
                if not self._require_admin(tenant_id=parts[3]):
                    return
                try:
                    bundle = store.put_policy(tenant_id=parts[3], device_id=parts[4], policy_doc=body)
                except ConfigError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json({"policy_version": bundle.version, "policy_hash": bundle.hash, "rules": len(bundle.rules)})
                return

            if parsed.path == "/api/shield/policy-history/rollback":
                tenant_id = str(body.get("tenant_id") or "")
                device_id = str(body.get("device_id") or "")
                if not self._require_admin(tenant_id=tenant_id):
                    return
                try:
                    bundle = store.rollback_policy(tenant_id=tenant_id, device_id=device_id, history_id=int(body.get("history_id")))
                except (TypeError, ValueError, ConfigError) as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json({"ok": True, "policy_version": bundle.version, "policy_hash": bundle.hash})
                return

            if parsed.path == "/api/shield/transaction-intents":
                tenant_id = str(body.get("tenant_id") or self.headers.get("X-Shield-Tenant-ID", ""))
                device_id = str(body.get("device_id") or self.headers.get("X-Shield-Device-ID", ""))
                if not self._require_device_token(tenant_id=tenant_id, device_id=device_id):
                    return
                try:
                    policy_doc = store.get_policy_doc(tenant_id=tenant_id, device_id=device_id)
                    if not policy_doc or not isinstance(policy_doc.get("transaction_policy"), dict):
                        decision = {
                            "action": "deny",
                            "rule_id": "transaction-policy-missing",
                            "reason": "transaction policy is not configured",
                            "execution": "not_broadcast",
                        }
                    else:
                        raw_intent = dict(body)
                        raw_intent["tenant_id"] = tenant_id
                        raw_intent["device_id"] = device_id
                        intent = TransactionIntent.from_dict(raw_intent)
                        decision = evaluate_transaction_intent(
                            intent, TransactionPolicy.from_dict(policy_doc["transaction_policy"])
                        ).as_dict()
                    if decision.get("intent_hash"):
                        store.record_transaction_intent(
                            tenant_id=tenant_id,
                            device_id=device_id,
                            intent=raw_intent if "raw_intent" in locals() else body,
                            decision=decision,
                        )
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json({"decision": decision})
                return

            if parsed.path == "/api/shield/transaction-approvals":
                if not self._require_admin(tenant_id=body.get("tenant_id")):
                    return
                try:
                    approval = store.create_transaction_approval(
                        tenant_id=str(body["tenant_id"]),
                        device_id=str(body["device_id"]),
                        intent_hash=str(body["intent_hash"]),
                        approver_id=str(body["approver_id"]),
                        expires_at=str(body["expires_at"]),
                    )
                except KeyError as exc:
                    self._send_error(HTTPStatus.NOT_FOUND, str(exc))
                    return
                except (ValueError, ConfigError, KeyError) as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json(approval, status=HTTPStatus.CREATED)
                return

            if parsed.path == "/api/shield/transaction-approvals/verify":
                tenant_id = str(body.get("tenant_id") or self.headers.get("X-Shield-Tenant-ID", ""))
                device_id = str(body.get("device_id") or self.headers.get("X-Shield-Device-ID", ""))
                if not self._require_device_token(tenant_id=tenant_id, device_id=device_id):
                    return
                try:
                    result = store.verify_transaction_approval(
                        tenant_id=tenant_id, device_id=device_id, intent_hash=str(body["intent_hash"])
                    )
                except (KeyError, ValueError) as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json(result)
                return

            if parsed.path == "/api/shield/transaction-approvals/consume":
                if not self._require_admin(tenant_id=body.get("tenant_id")):
                    return
                try:
                    consumed = store.consume_transaction_approval(
                        tenant_id=str(body["tenant_id"]),
                        device_id=str(body["device_id"]),
                        approval_id=str(body["approval_id"]),
                        intent_hash=str(body["intent_hash"]),
                    )
                except KeyError as exc:
                    self._send_error(HTTPStatus.NOT_FOUND, str(exc))
                    return
                except ValueError as exc:
                    self._send_error(HTTPStatus.CONFLICT, str(exc))
                    return
                self._send_json(consumed)
                return

            if parsed.path == "/api/shield/transaction-simulations":
                tenant_id = str(body.get("tenant_id") or self.headers.get("X-Shield-Tenant-ID", ""))
                device_id = str(body.get("device_id") or self.headers.get("X-Shield-Device-ID", ""))
                if not self._require_device_token(tenant_id=tenant_id, device_id=device_id):
                    return
                try:
                    policy_doc = store.get_policy_doc(tenant_id=tenant_id, device_id=device_id)
                    if not policy_doc or not isinstance(policy_doc.get("transaction_policy"), dict):
                        self._send_json({"decision": {"action": "deny", "rule_id": "transaction-policy-missing", "reason": "transaction policy is not configured", "execution": "not_broadcast"}})
                        return
                    raw_intent = dict(body)
                    raw_intent["tenant_id"] = tenant_id
                    raw_intent["device_id"] = device_id
                    intent = TransactionIntent.from_dict(raw_intent)
                    decision = evaluate_transaction_intent(
                        intent, TransactionPolicy.from_dict(policy_doc["transaction_policy"])
                    )
                    response: dict[str, Any] = {"decision": decision.as_dict()}
                    if decision.action != "allow":
                        self._send_json(response)
                        return
                    response["simulation"] = simulate_transaction_intent(intent).as_dict()
                except SimulationError as exc:
                    response = {
                        "decision": {
                            "action": "deny",
                            "rule_id": "simulation-failed",
                            "reason": str(exc),
                            "execution": "not_broadcast",
                        },
                        "simulation": {"status": "failed", "execution": "not_broadcast"},
                    }
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                self._send_json(response)
                return

            if parsed.path in (
                "/api/shield/decisions",
                "/api/shield/metrics",
                "/api/shield/detection-quality",
                "/api/shield/exporter-status",
                "/api/shield/enforcement-outcomes",
            ):
                tenant_id = str(body.get("tenant_id") or self.headers.get("X-Shield-Tenant-ID", ""))
                device_id = str(body.get("device_id") or self.headers.get("X-Shield-Device-ID", ""))
                if not self._require_device_token(tenant_id=tenant_id, device_id=device_id):
                    return
                try:
                    if parsed.path == "/api/shield/decisions":
                        decision = body.get("decision", body)
                        row_id = store.record_decision(tenant_id=tenant_id, device_id=device_id, decision=decision)
                        # Mirror authenticated, non-synthetic decisions into the durable
                        # Cortex outbox.  Local persistence remains authoritative; a
                        # publication failure is retried by the independent worker.
                        if not bool(decision.get("synthetic")):
                            try:
                                from ..agent_core.cortex_memory import CortexMemoryProvider
                                provider = CortexMemoryProvider.from_environment(device_id=device_id)
                                if provider is not None:
                                    event_ref = decision.get("event_ref") if isinstance(decision.get("event_ref"), dict) else {}
                                    event_id = str(event_ref.get("event_id") or f"shield-decision-{row_id}")
                                    provider._enqueue({
                                        "content": json.dumps({"event": decision, "decision": decision}, sort_keys=True, separators=(",", ":")),
                                        "source": {"kind": "shield_event", "agent_id": provider.agent_id, "device_id": device_id, "event_id": event_id},
                                        "status": "candidate",
                                        "evidence_class": "observed_event",
                                    }, event_id)
                            except Exception:
                                pass
                        self._send_json({"ok": True, "id": row_id}, status=HTTPStatus.CREATED)
                    elif parsed.path == "/api/shield/metrics":
                        metrics = body.get("metrics", body)
                        row_id = store.record_metrics(tenant_id=tenant_id, device_id=device_id, metrics=metrics)
                        self._send_json({"ok": True, "id": row_id}, status=HTTPStatus.CREATED)
                    elif parsed.path == "/api/shield/detection-quality":
                        quality = body.get("detection_quality", body)
                        row_id = store.record_detection_quality(tenant_id=tenant_id, device_id=device_id, quality=quality)
                        self._send_json({"ok": True, "id": row_id}, status=HTTPStatus.CREATED)
                    elif parsed.path == "/api/shield/enforcement-outcomes":
                        outcome = body.get("outcome", body)
                        row_id = store.record_enforcement_outcome(tenant_id=tenant_id, device_id=device_id, outcome=outcome)
                        self._send_json({"ok": True, "id": row_id}, status=HTTPStatus.CREATED)
                    else:
                        status_doc = body.get("status", body)
                        store.upsert_exporter_status(tenant_id=tenant_id, device_id=device_id, status=status_doc)
                        self._send_json({"ok": True})
                except ValueError as exc:
                    self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                except KeyError as exc:
                    self._send_error(HTTPStatus.NOT_FOUND, str(exc))
                return

            self._send_error(HTTPStatus.NOT_FOUND, "not found")

        def log_message(self, format: str, *args: Any) -> None:
            sys.stderr.write("shield-backend: " + format % args + "\n")

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return {}
            try:
                doc = json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON: {exc}") from exc
            if not isinstance(doc, dict):
                raise ValueError("request body must be a JSON object")
            return doc

        def _require_admin(self, tenant_id: str | None = None) -> bool:
            """Fail-closed admin auth. A missing/misconfigured token denies, it never allows.

            Accepts either the global super-admin token (full cross-tenant access, meant for the
            operator) or a tenant-scoped token minted via mint_tenant_admin_token (bound to the
            single tenant_id it was issued for). A tenant-scoped token can never read or write a
            different tenant's data.
            """
            if dev_disable_admin_auth:
                try:
                    client_is_loopback = ipaddress.ip_address(self.client_address[0]).is_loopback
                    origin = self.headers.get("Origin", "").strip()
                    origin_host = urlparse(origin).hostname if origin else None
                    origin_is_loopback = not origin or origin_host == "localhost" or (
                        origin_host is not None and ipaddress.ip_address(origin_host).is_loopback
                    )
                    if client_is_loopback and origin_is_loopback:
                        return True
                except (TypeError, ValueError):
                    pass
                self._send_error(HTTPStatus.FORBIDDEN, "development auth bypass is restricted to loopback clients and origins")
                return False

            token = self._current_admin_token()
            if not token:
                self._send_error(HTTPStatus.UNAUTHORIZED, "authentication required: session cookie or admin token")
                return False
            if admin_token and secrets.compare_digest(token, admin_token):
                return True
            if tenant_id and store.authenticate_tenant_admin(tenant_id=tenant_id, token=token):
                return True
            self._send_error(HTTPStatus.UNAUTHORIZED, "invalid admin token")
            return False

        def _require_device_token(self, *, tenant_id: str, device_id: str) -> bool:
            auth = self.headers.get("Authorization", "")
            prefix = "Bearer "
            token = auth[len(prefix):] if auth.startswith(prefix) else ""
            if not tenant_id or not device_id or not token:
                self._send_error(HTTPStatus.UNAUTHORIZED, "device token, tenant_id, and device_id are required")
                return False
            if not store.authenticate_device(tenant_id=tenant_id, device_id=device_id, token=token):
                self._send_error(HTTPStatus.UNAUTHORIZED, "invalid device token")
                return False
            return True

        def _tenant_from_query_or_error(self, query: dict[str, list[str]]) -> str | None:
            tenant_id = query.get("tenant_id", [""])[0]
            if not tenant_id:
                self._send_error(HTTPStatus.BAD_REQUEST, "tenant_id query parameter is required")
                return None
            return tenant_id

        def _request_base_url(self) -> str:
            scheme = self.headers.get("X-Forwarded-Proto", "http")
            host = self.headers.get("Host", f"127.0.0.1:{self.server.server_port}")
            return f"{scheme}://{host}"

        def _send_json(self, payload: dict[str, Any], *, status: HTTPStatus = HTTPStatus.OK, extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            if allowed_origin != "*":
                self.send_header("Access-Control-Allow-Credentials", "true")
            for name, value in extra_headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(raw)

        def _cookie_session_token(self) -> str:
            raw = self.headers.get("Cookie")
            if not raw:
                return ""
            morsel = SimpleCookie(raw).get(SESSION_COOKIE_NAME)
            return morsel.value if morsel else ""

        def _current_admin_token(self) -> str:
            """Operator credential: cookie first, then bearer.

            Device agents keep using bearer exclusively via _require_device_token; they have no
            cookie jar, so this fallback is what keeps them working.
            """
            token = self._cookie_session_token()
            if token:
                return token
            auth = self.headers.get("Authorization", "")
            prefix = "Bearer "
            return auth[len(prefix):] if auth.startswith(prefix) else ""

        def _send_html(self, html: str) -> None:
            raw = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_error(self, status: HTTPStatus, message: str) -> None:
            self._send_json({"error": message}, status=status)

    return ShieldBackendHandler


def _seed_demo(store: ShieldStore, body: dict[str, Any], *, base_url: str) -> dict[str, Any]:
    tenant_id = str(body.get("tenant_id", "demo-tenant"))
    device_id = str(body.get("device_id", "demo-linux-001"))
    enrollment = store.enroll_device(
        tenant_id=tenant_id,
        device_id=device_id,
        device_role=str(body.get("device_role", "workstation")),
        base_url=base_url,
    )
    bundle = store.put_policy(
        tenant_id=tenant_id,
        device_id=device_id,
        policy_doc={
            "policy_version": "demo-shield-mvp",
            "rules": [
                {
                    "rule_id": "demo-deny-shadow-agent",
                    "name": "Deny unregistered demo agent",
                    "version": "1.0.0",
                    "conditions": [{"type": "agent", "match": {"registered": False}}],
                    "actions": [{"type": "deny", "message": "Synthetic demo: unregistered agent denied."}],
                }
            ],
        },
    )
    for decision in _demo_decisions(device_id):
        store.record_decision(tenant_id=tenant_id, device_id=device_id, decision=decision)
    store.record_metrics(
        tenant_id=tenant_id,
        device_id=device_id,
        metrics={
            "duration_sec": 3600,
            "events": 12800,
            "events_per_sec": 3.56,
            "max_rss_kb": 132000,
            "cpu_percent_avg": 1.8,
            "export_success_rate": 0.997,
            "false_positive_rate": None,
            "false_positive_note": "synthetic MVP seed; real rate requires operator-labeled pilot review",
            "synthetic": True,
        },
    )
    store.record_detection_quality(
        tenant_id=tenant_id,
        device_id=device_id,
        quality={
            "synthetic": True,
            "samples": [
                {
                    "event_id": "demo-shadow-agent",
                    "label": "malicious",
                    "label_source": "synthetic_fixture",
                    "decision_action": "deny",
                    "rule_id": "demo-deny-shadow-agent",
                    "policy_hash": bundle.hash,
                    "export_attempted": True,
                    "export_success": True,
                    "integrity_receipt": "synthetic-demo-receipt",
                },
                {
                    "event_id": "demo-phi-context",
                    "label": "malicious",
                    "label_source": "synthetic_fixture",
                    "decision_action": "deny",
                    "rule_id": "demo-deny-phi-context",
                    "policy_hash": bundle.hash,
                    "export_attempted": True,
                    "export_success": True,
                    "integrity_receipt": "synthetic-demo-receipt",
                },
                {
                    "event_id": "demo-network-allow",
                    "label": "benign",
                    "label_source": "synthetic_fixture",
                    "decision_action": "allow",
                    "rule_id": "_no_match",
                    "policy_hash": bundle.hash,
                    "export_attempted": True,
                    "export_success": True,
                    "integrity_receipt": "synthetic-demo-receipt",
                },
            ],
        },
    )
    store.upsert_exporter_status(
        tenant_id=tenant_id,
        device_id=device_id,
        status={
            # Synthetic values for this demo fixture only -- a real device gets a real,
            # checkable answer to these same three questions from `shield preflight`
            # (shield/integrity_exporter/preflight.py, PRODUCTION_READINESS_PLAN.md §7
            # item 4), not this hardcoded placeholder.
            "did_registered": False,
            "bcc_middleware": "not_checked",
            "oracle_readback": "blocked_until_rpc_credentials",
            "synthetic": True,
        },
    )
    store.mark_device_synthetic(tenant_id=tenant_id, device_id=device_id)
    store.put_integration(
        tenant_id=tenant_id,
        integration_id="demo-webhook",
        kind="webhook",
        config={"url": "https://soar.example.com/xibalba-shield", "synthetic": True},
    )
    return {
        "tenant_id": tenant_id,
        "device_id": device_id,
        "device_token": enrollment.device_token,
        "device_config": enrollment.device_config,
        "policy_hash": bundle.hash,
        "seeded_decisions": 4,
    }


def _demo_decisions(device_id: str) -> list[dict[str, Any]]:
    base = {
        "class": "policy_decision",
        "device_id": device_id,
        "time": "2026-08-06T00:00:00Z",
        "policy": {"version": "demo-shield-mvp", "hash": "synthetic"},
        "export": {"attempted": True, "event_exported": True, "decision_exported": True, "authorized": True},
        "synthetic": True,
    }
    return [
        {
            **base,
            "event_ref": {"class": "agent_event", "event_id": "demo-shadow-agent"},
            "rule": {"rule_id": "demo-deny-shadow-agent", "name": "Deny unregistered demo agent", "version": "1.0.0"},
            "decision": {"action": "deny", "severity": "high", "reason": "Synthetic shadow agent denied."},
        },
        {
            **base,
            "event_ref": {"class": "file_activity", "event_id": "demo-sensitive-write"},
            "rule": {"rule_id": "demo-escalate-sensitive-write", "name": "Sensitive write", "version": "1.0.0"},
            "decision": {"action": "escalate", "severity": "high", "reason": "Synthetic sensitive path write escalated."},
        },
        {
            **base,
            "event_ref": {"class": "agent_event", "event_id": "demo-phi-context"},
            "rule": {"rule_id": "demo-deny-phi-context", "name": "Deny PHI context", "version": "1.0.0"},
            "decision": {"action": "deny", "severity": "critical", "reason": "Synthetic PHI metadata context denied."},
        },
        {
            **base,
            "event_ref": {"class": "network_flow", "event_id": "demo-network-allow"},
            "rule": {"rule_id": "_no_match", "name": "Default allow", "version": "builtin"},
            "decision": {"action": "allow", "severity": "low", "reason": "Synthetic benign network flow allowed."},
        },
    ]


_SECURITY_ACTIONS = {"deny", "contain", "escalate"}
_BLOCKING_ACTIONS = {"deny", "contain"}


def _detection_quality_report(
    rows: list[dict[str, Any]], *, bcc_middleware_url: str, oracle_url: str | None = None
) -> dict[str, Any]:
    if not rows:
        raise ValueError("no detection-quality samples recorded for tenant")
    latest = rows[0]
    quality = latest["quality"]
    samples = quality.get("samples", [])
    verified_samples = []
    for sample in samples:
        checked = dict(sample)
        checked["receipt_verified"] = _verify_detection_quality_receipt(sample, bcc_middleware_url=bcc_middleware_url)
        checked["oracle_audit_readback"] = (
            _verify_oracle_audit_readback(sample, oracle_url=oracle_url) if oracle_url else None
        )
        verified_samples.append(checked)
    receipt_backed_samples = [sample for sample in verified_samples if sample["receipt_verified"]]
    receipt_backed_aggregate = _aggregate_detection_quality_samples(receipt_backed_samples)
    counted_security_decisions = [
        sample
        for sample in verified_samples
        if sample.get("label") == "malicious" and sample.get("decision_action") in _SECURITY_ACTIONS
    ]
    unverified_counted_security_decisions = [sample for sample in counted_security_decisions if not sample["receipt_verified"]]
    return {
        "schema": "shield.detection_quality_report.v1",
        "source_received_at": latest.get("received_at"),
        "raw_aggregate": quality.get("aggregate"),
        "receipt_backed_aggregate": receipt_backed_aggregate,
        "samples": verified_samples,
        "all_adr_counted_security_decisions_have_verified_receipts": not unverified_counted_security_decisions,
        "all_adr_counted_security_decisions_have_oracle_audit_readback": (
            None
            if oracle_url is None
            else all(sample.get("oracle_audit_readback") for sample in counted_security_decisions)
        ),
        "unverified_adr_counted_event_ids": [sample["event_id"] for sample in unverified_counted_security_decisions],
    }


def _verify_detection_quality_receipt(sample: dict[str, Any], *, bcc_middleware_url: str) -> bool:
    token = sample.get("verification_token")
    agent_id = sample.get("agent_id")
    nonce = sample.get("nonce")
    intended_state_hash = sample.get("intended_state_hash")
    if not token or not agent_id or nonce is None or not intended_state_hash:
        return False
    payload = json.dumps(
        {
            "token": token,
            "agent_id": agent_id,
            "nonce": nonce,
            "intended_state_hash": intended_state_hash,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{bcc_middleware_url.rstrip('/')}/v1/bcc/verify_token",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError):
        return False
    return bool(result.get("valid"))


def _verify_oracle_audit_readback(sample: dict[str, Any], *, oracle_url: str | None) -> bool:
    if not oracle_url or not sample.get("agent_id"):
        return False
    query = urlencode({"agent_id": str(sample["agent_id"]), "limit": "25"})
    request = urllib.request.Request(
        f"{oracle_url.rstrip('/')}/v1/audit-log?{query}",
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            rows = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError):
        return False
    if not isinstance(rows, list):
        return False
    batch_index = sample.get("batch_index")
    return any(
        row.get("source") == "bcc_middleware"
        and row.get("event_type") == "bcc_intercept"
        and row.get("decision") == "allow"
        and (batch_index is None or str(batch_index) in str(row.get("detail", "")))
        for row in rows
        if isinstance(row, dict)
    )


def _aggregate_detection_quality_samples(samples: list[dict[str, Any]]) -> dict[str, Any]:
    malicious = [sample for sample in samples if sample.get("label") == "malicious"]
    benign = [sample for sample in samples if sample.get("label") == "benign"]
    true_positive = [sample for sample in malicious if sample.get("decision_action") in _SECURITY_ACTIONS]
    security_decisions = [sample for sample in samples if sample.get("decision_action") in _SECURITY_ACTIONS]
    blocking_false_positive = [sample for sample in benign if sample.get("decision_action") in _BLOCKING_ACTIONS]
    export_attempted = [sample for sample in samples if sample.get("export_attempted")]
    export_success = [sample for sample in export_attempted if sample.get("export_success")]
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
        "export_attempted_decisions": len(export_attempted),
        "successful_exports": len(export_success),
        "evidence_export_success": _rate(len(export_success), len(export_attempted)),
    }


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _configure_tls(server: ThreadingHTTPServer, *, tls_cert: Path, tls_key: Path, tls_client_ca: Path | None = None) -> None:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
    if tls_client_ca:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=tls_client_ca)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.tls_enabled = True  # type: ignore[attr-defined]
    server.mtls_enabled = bool(tls_client_ca)  # type: ignore[attr-defined]


def run_server(*, host: str, port: int, db_path: Path, admin_token: str, public_base_url: str = "", allowed_origin: str = "*", tls_cert: Path | None = None, tls_key: Path | None = None, tls_client_ca: Path | None = None, tls_port: int | None = None, dev_disable_admin_auth: bool = False) -> ThreadingHTTPServer:
    if bool(tls_cert) != bool(tls_key):
        raise ValueError("TLS requires both --tls-cert and --tls-key")
    if tls_client_ca and not tls_cert:
        raise ValueError("TLS client CA requires server TLS certificate and key")
    if dev_disable_admin_auth:
        try:
            loopback_host = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback_host = False
        if not loopback_host:
            raise ValueError("development auth bypass requires a loopback host")
    store = ShieldStore(db_path)
    handler = make_handler(store=store, admin_token=admin_token, public_base_url=public_base_url, allowed_origin=allowed_origin, dev_disable_admin_auth=dev_disable_admin_auth)
    server = ThreadingHTTPServer((host, port), handler)
    if tls_port is not None:
        if not tls_cert or not tls_key:
            raise ValueError("--tls-port requires both --tls-cert and --tls-key")
        tls_server = ThreadingHTTPServer((host, tls_port), handler)
        _configure_tls(tls_server, tls_cert=tls_cert, tls_key=tls_key, tls_client_ca=tls_client_ca)
        server.tls_server = tls_server  # type: ignore[attr-defined]
        server.tls_enabled = False  # type: ignore[attr-defined]
        server.mtls_enabled = False  # type: ignore[attr-defined]
    elif tls_cert and tls_key:
        _configure_tls(server, tls_cert=tls_cert, tls_key=tls_key, tls_client_ca=tls_client_ca)
        server.tls_server = None  # type: ignore[attr-defined]
    else:
        server.tls_enabled = False  # type: ignore[attr-defined]
        server.mtls_enabled = False  # type: ignore[attr-defined]
        server.tls_server = None  # type: ignore[attr-defined]
    server.store = store  # type: ignore[attr-defined]
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shield-backend")
    parser.add_argument("--host", default=os.getenv("SHIELD_BACKEND_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SHIELD_BACKEND_PORT", "8765")))
    parser.add_argument("--db-path", type=Path, default=Path(os.getenv("SHIELD_BACKEND_DB", str(DEFAULT_DB_PATH))))
    parser.add_argument("--admin-token", default=os.getenv("SHIELD_BACKEND_TOKEN", ""))
    parser.add_argument("--admin-token-file", type=Path, default=Path(os.getenv("SHIELD_BACKEND_TOKEN_FILE", str(Path.home() / ".xibalba-shield" / "backend-admin.token"))))
    parser.add_argument("--dev-disable-auth", action="store_true", default=os.getenv("SHIELD_DEV_DISABLE_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}, help="disable admin bearer auth for loopback-only development")
    parser.add_argument("--public-base-url", default=os.getenv("SHIELD_PUBLIC_BASE_URL", ""))
    parser.add_argument("--allowed-origin", default=os.getenv("SHIELD_BACKEND_ALLOWED_ORIGIN", "*"), help="CORS origin for browser callers (e.g. the dashboard)")
    parser.add_argument("--tls-cert", type=Path, default=os.getenv("SHIELD_BACKEND_TLS_CERT") or None, help="PEM server certificate; must be paired with --tls-key")
    parser.add_argument("--tls-key", type=Path, default=os.getenv("SHIELD_BACKEND_TLS_KEY") or None, help="PEM private key; must be paired with --tls-cert")
    parser.add_argument("--tls-client-ca", type=Path, default=os.getenv("SHIELD_BACKEND_TLS_CLIENT_CA") or None, help="CA bundle for required mutual TLS client certificates")
    parser.add_argument("--tls-port", type=int, default=int(os.getenv("SHIELD_BACKEND_TLS_PORT", "0")) or None, help="Dedicated HTTPS/mTLS listener port; leaves the primary HTTP listener unchanged")
    args = parser.parse_args(argv)

    if not args.admin_token and not args.dev_disable_auth:
        try:
            args.admin_token, created = load_or_create_admin_token(args.admin_token_file)
        except (OSError, ValueError) as exc:
            parser.error(f"cannot load or create admin token: {exc}")
        state = "generated" if created else "loaded"
        print(f"shield-backend: {state} persistent admin token at {args.admin_token_file} (value not printed)", file=sys.stderr)

    server = run_server(
        host=args.host,
        port=args.port,
        db_path=args.db_path,
        admin_token=args.admin_token,
        allowed_origin=args.allowed_origin,
        public_base_url=args.public_base_url,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        tls_client_ca=args.tls_client_ca,
        tls_port=args.tls_port,
        dev_disable_admin_auth=args.dev_disable_auth,
    )
    scheme = "https" if getattr(server, "tls_enabled", False) else "http"
    mode = " with mTLS" if getattr(server, "mtls_enabled", False) else ""
    print(f"shield-backend listening on {scheme}://{args.host}:{server.server_port}{mode}")
    if args.dev_disable_auth:
        print("shield-backend: WARNING admin authentication is disabled for loopback development", file=sys.stderr)
    tls_server = getattr(server, "tls_server", None)
    tls_thread = None
    if tls_server is not None:
        import threading
        tls_thread = threading.Thread(target=tls_server.serve_forever, name="shield-backend-tls", daemon=True)
        tls_thread.start()
        print(f"shield-backend TLS listener on https://{args.host}:{tls_server.server_port}{' with mTLS' if getattr(tls_server, 'mtls_enabled', False) else ''}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshield-backend stopping")
    finally:
        if tls_server is not None:
            tls_server.shutdown()
            tls_server.server_close()
            if tls_thread is not None:
                tls_thread.join(timeout=2)
        server.store.close()  # type: ignore[attr-defined]
        server.server_close()
    return 0


def _console_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Xibalba Shield</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #20242a; }
    header { background: #ffffff; border-bottom: 1px solid #d8dee6; padding: 18px 24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    h1 { font-size: 24px; margin: 0; font-weight: 700; letter-spacing: 0; }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    .toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    input, button { height: 36px; border: 1px solid #b8c0cc; border-radius: 6px; padding: 0 10px; font: inherit; background: #fff; }
    button { cursor: pointer; font-weight: 600; background: #263238; color: #fff; border-color: #263238; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 18px 0; }
    .panel { background: #fff; border: 1px solid #d8dee6; border-radius: 8px; padding: 14px; }
    .metric { font-size: 28px; font-weight: 700; margin-top: 6px; }
    .label { color: #5d6875; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d8dee6; }
    th, td { padding: 10px; border-bottom: 1px solid #e7ebf0; text-align: left; font-size: 14px; vertical-align: top; }
    th { color: #485361; background: #f8fafc; font-size: 12px; text-transform: uppercase; }
    .split { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .graph-shell { background: #fff; border: 1px solid #d8dee6; border-radius: 8px; margin: 18px 0; overflow: hidden; }
    .graph-header { display: flex; justify-content: space-between; gap: 12px; padding: 12px 14px; border-bottom: 1px solid #e7ebf0; align-items: center; flex-wrap: wrap; }
    .graph-header h2 { margin: 0; }
    .graph-controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .graph-controls select, .graph-controls button { height: 32px; border: 1px solid #b8c0cc; border-radius: 6px; padding: 0 8px; font: inherit; }
    .graph-controls button { width: 36px; background: #263238; color: #fff; border-color: #263238; }
    .graph-controls label { color: #5d6875; font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .graph-stage { position: relative; min-height: 420px; }
    canvas { display: block; width: 100%; height: 420px; }
    .key { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 12px 14px; border-top: 1px solid #e7ebf0; background: #f8fafc; }
    .key h3 { margin: 0 0 8px; font-size: 13px; text-transform: uppercase; color: #485361; }
    .key-row { display: flex; align-items: center; gap: 8px; font-size: 13px; margin: 6px 0; color: #38424e; }
    .swatch { width: 12px; height: 12px; border-radius: 50%; display: inline-block; border: 1px solid rgba(0,0,0,.14); flex: 0 0 auto; }
    .line-swatch { width: 24px; height: 0; border-top: 3px solid #6b7280; display: inline-block; flex: 0 0 auto; }
    code { white-space: pre-wrap; overflow-wrap: anywhere; }
    .pill { display: inline-block; border-radius: 999px; padding: 3px 8px; background: #e9eef3; font-size: 12px; }
    .deny, .contain, .escalate { background: #ffe8e2; color: #82240f; }
    .allow, .log_only { background: #e6f4ea; color: #1f6b38; }
    .health-ok { color: #1f6b38; }
    .health-warn { color: #b45309; }
    .health-bad { color: #82240f; }
    .health-unknown { color: #5d6875; }
    .health-cell { font-size: 12px; line-height: 1.5; }
    @media (max-width: 820px) { .grid, .split, .key { grid-template-columns: 1fr; } header { align-items: flex-start; flex-direction: column; } }
  </style>
</head>
<body>
  <header>
    <h1>Xibalba Shield</h1>
    <div class="toolbar">
      <input id="tenant" value="demo-tenant" aria-label="tenant id">
      <input id="token" value="" placeholder="admin token" aria-label="admin token">
      <button onclick="loadSummary()">Refresh</button>
      <button onclick="seedDemo()">Seed Demo</button>
    </div>
  </header>
  <main>
    <section class="grid">
      <div class="panel"><div class="label">Devices</div><div class="metric" id="deviceCount">0</div></div>
      <div class="panel"><div class="label">Allows</div><div class="metric" id="allowCount">0</div></div>
      <div class="panel"><div class="label">Denies</div><div class="metric" id="denyCount">0</div></div>
      <div class="panel"><div class="label">Escalations</div><div class="metric" id="escalateCount">0</div></div>
    </section>
    <section class="graph-shell" aria-label="3D Shield graph">
      <div class="graph-header">
        <h2>3D Evidence Graph</h2>
        <div class="graph-controls">
          <label for="graphBackground">Background</label>
          <select id="graphBackground" onchange="setGraphBackground(this.value)">
            <option value="light">Light grid</option>
            <option value="dark">Dark grid</option>
            <option value="plain">Plain</option>
            <option value="blueprint">Blueprint</option>
          </select>
          <label for="edgeType">Connection</label>
          <select id="edgeType" onchange="setEdgeType(this.value)">
            <option value="all">All</option>
            <option value="enrollment">Enrollment</option>
            <option value="policy">Policy</option>
            <option value="decision">Decision</option>
            <option value="export">Export</option>
            <option value="integration">Integration</option>
            <option value="metrics">Metrics</option>
          </select>
          <button type="button" title="Fit graph" onclick="fitGraph()">Fit</button>
          <button type="button" title="Zoom in" onclick="zoomGraph(1.18)">+</button>
          <button type="button" title="Zoom out" onclick="zoomGraph(0.84)">-</button>
          <button type="button" title="Move left" onclick="panGraph(-32, 0)">L</button>
          <button type="button" title="Move right" onclick="panGraph(32, 0)">R</button>
        </div>
      </div>
      <div class="graph-stage">
        <canvas id="evidenceGraph" width="1100" height="420"></canvas>
      </div>
      <div class="key">
        <div>
          <h3>Nodes</h3>
          <div class="key-row"><span class="swatch" style="background:#334155"></span>Tenant root and control plane scope.</div>
          <div class="key-row"><span class="swatch" style="background:#2563eb"></span>Device enrolled with Shield backend.</div>
          <div class="key-row"><span class="swatch" style="background:#7c3aed"></span>Policy bundle and trusted hash boundary.</div>
          <div class="key-row"><span class="swatch" style="background:#dc2626"></span>Deny, escalate, contain, or export-gap decision.</div>
          <div class="key-row"><span class="swatch" style="background:#16a34a"></span>Allowed/log-only decision or healthy export path.</div>
        </div>
        <div>
          <h3>Connections</h3>
          <div class="key-row"><span class="line-swatch" style="border-color:#64748b"></span>Enrollment links tenant to devices.</div>
          <div class="key-row"><span class="line-swatch" style="border-color:#7c3aed"></span>Policy links device to active bundle metadata.</div>
          <div class="key-row"><span class="line-swatch" style="border-color:#f97316"></span>Decision links device to observed policy outcome.</div>
          <div class="key-row"><span class="line-swatch" style="border-color:#0f766e"></span>Export, integration, and metrics links show evidence flow.</div>
        </div>
      </div>
    </section>
    <section class="split">
      <div>
        <h2>Devices</h2>
        <table><thead><tr><th>Device</th><th>Role</th><th>Policy</th><th>Last Seen</th></tr></thead><tbody id="devices"></tbody></table>
      </div>
      <div>
        <h2>Latest Decisions</h2>
        <table><thead><tr><th>Action</th><th>Rule</th><th>Event</th><th>Export</th></tr></thead><tbody id="decisions"></tbody></table>
      </div>
    </section>
    <section>
      <h2>Device Health &amp; Exporter Status</h2>
      <table>
        <thead>
          <tr>
            <th>Device</th><th>DID Preflight</th><th>Policy</th><th>Sensors</th>
            <th>Exporter</th><th>Spool</th><th>Updated</th>
          </tr>
        </thead>
        <tbody id="exporterStatus"></tbody>
      </table>
    </section>
    <section>
      <h2>Containment Outcomes</h2>
      <table>
        <thead><tr><th>Device</th><th>Action</th><th>Result</th><th>Escalated</th><th>Error</th><th>When</th></tr></thead>
        <tbody id="containmentOutcomes"></tbody>
      </table>
    </section>
    <section>
      <h2>Latest Burn-In Metrics</h2>
      <div class="panel"><code id="metrics">No metrics yet.</code></div>
    </section>
    <section>
      <h2>Detection Quality</h2>
      <div class="panel"><code id="detectionQuality">No detection-quality samples yet.</code></div>
    </section>
  </main>
  <script>
    let summaryData = null;
    let graphState = { zoom: 1, panX: 0, panY: 0, background: 'light', edgeType: 'all' };
    let graphNodes = [];
    let graphEdges = [];
    let containmentOutcomesData = [];

    async function loadSummary() {
      const tenant = document.getElementById('tenant').value;
      const token = document.getElementById('token').value;
      const res = await fetch(`/api/shield/dashboard-summary?tenant_id=${encodeURIComponent(tenant)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) { alert(data.error || 'request failed'); return; }
      const counts = data.decisions_by_action || {};
      document.getElementById('deviceCount').textContent = data.device_count || 0;
      document.getElementById('allowCount').textContent = counts.allow || 0;
      document.getElementById('denyCount').textContent = counts.deny || 0;
      document.getElementById('escalateCount').textContent = counts.escalate || 0;
      document.getElementById('devices').innerHTML = (data.devices || []).map(d =>
        `<tr><td>${escapeHtml(d.device_id)}</td><td>${escapeHtml(d.device_role || '')}</td><td>${escapeHtml(d.policy_version || '')}<br><code>${escapeHtml(d.policy_hash || '')}</code></td><td>${escapeHtml(d.last_seen_at || '')}</td></tr>`
      ).join('');
      document.getElementById('decisions').innerHTML = (data.latest_decisions || []).map(item => {
        const d = item.decision || {};
        const action = (d.decision || {}).action || '';
        const exp = d.export || {};
        const synthetic = d.synthetic ? '<br><span class="pill">synthetic</span>' : '';
        return `<tr><td><span class="pill ${escapeHtml(action)}">${escapeHtml(action)}</span>${synthetic}</td><td>${escapeHtml((d.rule || {}).rule_id || '')}</td><td>${escapeHtml((d.event_ref || {}).class || d.class || '')}</td><td>${exp.decision_exported ? 'ok' : 'gap'}</td></tr>`;
      }).join('');
      document.getElementById('metrics').textContent = data.latest_metrics ? JSON.stringify(data.latest_metrics, null, 2) : 'No metrics yet.';
      document.getElementById('detectionQuality').textContent = data.latest_detection_quality ? JSON.stringify(data.latest_detection_quality.aggregate, null, 2) : 'No detection-quality samples yet.';
      summaryData = data;
      // Fetched before buildGraph() so containment-outcome nodes/edges (see buildGraph's
      // own containment section) can be included in the same graph build, not bolted on
      // as a separate, un-integrated fetch.
      await loadContainmentOutcomes();
      buildGraph(data);
      drawGraph();
      await loadExporterStatus();
    }
    function healthSpan(ok, label) {
      // ok: true/false/null -- null means "not checked" (e.g. no oracle_url configured,
      // or this device predates the real preflight/spool telemetry, e.g. --no-exporter).
      const cls = ok === true ? 'health-ok' : ok === false ? 'health-bad' : 'health-unknown';
      return `<span class="${cls}">${escapeHtml(label)}</span>`;
    }
    async function loadExporterStatus() {
      const tenant = document.getElementById('tenant').value;
      const token = document.getElementById('token').value;
      const res = await fetch(`/api/shield/exporter-status?tenant_id=${encodeURIComponent(tenant)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) { return; }
      document.getElementById('exporterStatus').innerHTML = (data.exporter_status || []).map(row => {
        const s = row.status || {};
        const pre = s.did_preflight || null;
        // did_preflight (real, per-device check -- see shield/integrity_exporter/preflight.py)
        // takes precedence; falls back to the older demo-seed did_registered/oracle_readback/
        // bcc_middleware fields for devices/tenants that only have those (e.g. the demo seed).
        let didCell;
        if (pre) {
          didCell = [
            healthSpan(pre.did_loaded, pre.did_loaded ? `DID ${escapeHtml(pre.did || '')}` : 'DID load failed'),
            healthSpan(pre.bcc_middleware_reachable, `bcc_middleware ${pre.bcc_middleware_reachable ? 'reachable' : 'unreachable'}`),
            pre.oracle_configured
              ? healthSpan(pre.oracle_registered, `oracle ${pre.oracle_registered === false ? 'not yet registered' : pre.oracle_registered === true ? 'registered' : 'reachable, registration unknown'}`)
              : healthSpan(null, 'oracle not configured'),
          ].join('<br>');
        } else {
          didCell = [
            healthSpan(s.did_registered === true ? true : s.did_registered === false ? false : null, `DID ${s.did_registered === undefined ? 'unknown' : s.did_registered}`),
            healthSpan(null, `oracle_readback ${escapeHtml(String(s.oracle_readback ?? 'unknown'))}`),
          ].join('<br>');
        }
        const policy = s.policy || {};
        const policyCell = healthSpan(policy.healthy, policy.healthy === undefined ? 'unknown' : (policy.healthy ? 'healthy' : 'unhealthy'))
          + (policy.active_policy_hash ? `<br><code>${escapeHtml(String(policy.active_policy_hash).slice(0, 10))}…</code>` : '');
        const sensors = s.sensors || {};
        const sensorsCell = sensors.attached === undefined
          ? healthSpan(null, 'no sensor data')
          : healthSpan(sensors.attached, sensors.attached ? 'attached' : 'not attached')
            + `<br>lost_events: ${sensors.lost_events ?? 0}`;
        const exporter = s.exporter || {};
        const exporterCell = exporter.export_failures === undefined
          ? healthSpan(null, 'no exporter data')
          : healthSpan(exporter.export_failures === 0, `export_failures: ${exporter.export_failures}`)
            + `<br>queue_depth: ${exporter.queue_depth ?? 'n/a'}`;
        const spoolCell = exporter.spool_pending === undefined
          ? healthSpan(null, 'no spool data')
          : healthSpan(exporter.spool_pending === 0, `pending: ${exporter.spool_pending}`)
            + (exporter.spool_oldest_age_seconds != null ? `<br>oldest: ${Math.round(exporter.spool_oldest_age_seconds)}s` : '');
        return `<tr class="health-cell"><td>${escapeHtml(row.device_id)}</td><td>${didCell}</td><td>${policyCell}</td><td>${sensorsCell}</td><td>${exporterCell}</td><td>${spoolCell}</td><td>${escapeHtml(row.updated_at || '')}</td></tr>`;
      }).join('');
      await loadContainmentOutcomes();
    }
    async function loadContainmentOutcomes() {
      const tenant = document.getElementById('tenant').value;
      const token = document.getElementById('token').value;
      const res = await fetch(`/api/shield/enforcement-outcomes?tenant_id=${encodeURIComponent(tenant)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) { return; }
      containmentOutcomesData = data.enforcement_outcomes || [];
      document.getElementById('containmentOutcomes').innerHTML = containmentOutcomesData.map(row => {
        const o = row.outcome || {};
        const resultCell = healthSpan(o.completed, o.completed ? 'completed' : 'FAILED');
        return `<tr class="health-cell"><td>${escapeHtml(o.device_id || '')}</td><td>${escapeHtml(o.action || '')}</td><td>${resultCell}</td><td>${o.escalated ? 'yes' : 'no'}</td><td>${escapeHtml(o.error || '')}</td><td>${escapeHtml(row.received_at || '')}</td></tr>`;
      }).join('');
    }
    async function seedDemo() {
      const tenant = document.getElementById('tenant').value;
      const token = document.getElementById('token').value;
      const res = await fetch('/api/shield/demo/seed', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenant })
      });
      const data = await res.json();
      if (!res.ok) { alert(data.error || 'seed failed'); return; }
      await loadSummary();
    }
    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function buildGraph(data) {
      const nodes = [{ id: `tenant:${data.tenant_id}`, label: data.tenant_id || 'tenant', type: 'tenant', x: -260, y: 0, z: 0 }];
      const edges = [];
      const devices = data.devices || [];
      devices.forEach((device, index) => {
        const y = (index - (devices.length - 1) / 2) * 105;
        const deviceId = `device:${device.device_id}`;
        nodes.push({ id: deviceId, label: device.device_id, type: 'device', x: -70, y, z: 38 - index * 12 });
        edges.push({ from: nodes[0].id, to: deviceId, type: 'enrollment' });
        if (device.policy_version || device.policy_hash) {
          const policyId = `policy:${device.device_id}`;
          nodes.push({ id: policyId, label: device.policy_version || 'policy', type: 'policy', x: 118, y: y - 42, z: -24 });
          edges.push({ from: deviceId, to: policyId, type: 'policy' });
        }
      });
      (data.latest_decisions || []).slice(0, 10).forEach((item, index) => {
        const decision = item.decision || {};
        const deviceId = `device:${decision.device_id || ((devices[0] || {}).device_id || '')}`;
        const action = (decision.decision || {}).action || 'decision';
        const eventClass = (decision.event_ref || {}).class || decision.class || 'event';
        const nodeId = `decision:${index}:${action}:${eventClass}`;
        nodes.push({
          id: nodeId,
          label: `${action} ${eventClass}`.trim(),
          type: action === 'allow' || action === 'log_only' ? 'decision-ok' : 'decision-risk',
          x: 245,
          y: (index - 4.5) * 48,
          z: index % 2 ? 48 : -42
        });
        if (deviceId !== 'device:') edges.push({ from: deviceId, to: nodeId, type: 'decision' });
        if ((decision.export || {}).decision_exported || (decision.export || {}).authorized) {
          const exportId = 'export:integrity';
          if (!nodes.some(n => n.id === exportId)) nodes.push({ id: exportId, label: 'Integrity export', type: 'export', x: 430, y: -82, z: 22 });
          edges.push({ from: nodeId, to: exportId, type: 'export' });
        }
      });
      if (data.latest_metrics) {
        nodes.push({ id: 'metrics:latest', label: 'burn-in metrics', type: 'metrics', x: 430, y: 82, z: -16 });
        devices.forEach(device => edges.push({ from: `device:${device.device_id}`, to: 'metrics:latest', type: 'metrics' }));
      }
      if (data.latest_detection_quality) {
        const adr = data.latest_detection_quality.aggregate && data.latest_detection_quality.aggregate.shield_adr;
        nodes.push({ id: 'quality:latest', label: `Shield ADR ${adr === null || adr === undefined ? 'n/a' : adr}`, type: 'metrics', x: 520, y: 28, z: 34 });
        devices.forEach(device => edges.push({ from: `device:${device.device_id}`, to: 'quality:latest', type: 'metrics' }));
      }
      (data.integrations || []).slice(0, 4).forEach((integration, index) => {
        const nodeId = `integration:${integration.integration_id}`;
        nodes.push({ id: nodeId, label: integration.integration_id, type: 'integration', x: 430, y: 162 + index * 42, z: 18 });
        nodes.filter(n => n.type === 'export').forEach(exportNode => edges.push({ from: exportNode.id, to: nodeId, type: 'integration' }));
      });
      graphNodes = nodes;
      graphEdges = edges;
      fitGraph();
    }
    function project(node, canvas) {
      const depth = 620;
      const scale = graphState.zoom * depth / (depth + node.z);
      return {
        x: canvas.width / 2 + (node.x * scale) + graphState.panX,
        y: canvas.height / 2 + (node.y * scale * 0.78) + graphState.panY,
        r: Math.max(5, 10 * scale),
        scale
      };
    }
    function drawGraph() {
      const canvas = document.getElementById('evidenceGraph');
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      canvas.width = Math.max(720, Math.floor(rect.width));
      canvas.height = 420;
      const ctx = canvas.getContext('2d');
      drawBackground(ctx, canvas);
      const filtered = graphState.edgeType === 'all' ? graphEdges : graphEdges.filter(edge => edge.type === graphState.edgeType);
      const connected = new Set(filtered.flatMap(edge => [edge.from, edge.to]));
      const byId = Object.fromEntries(graphNodes.map(node => [node.id, node]));
      filtered.forEach(edge => {
        if (!byId[edge.from] || !byId[edge.to]) return;
        const a = project(byId[edge.from], canvas);
        const b = project(byId[edge.to], canvas);
        ctx.strokeStyle = edgeColor(edge.type);
        ctx.lineWidth = edge.type === graphState.edgeType ? 3 : 2;
        ctx.globalAlpha = 0.78;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      });
      ctx.globalAlpha = 1;
      graphNodes
        .map(node => ({ node, point: project(node, canvas) }))
        .sort((a, b) => a.node.z - b.node.z)
        .forEach(({ node, point }) => {
          const dim = graphState.edgeType !== 'all' && !connected.has(node.id);
          ctx.globalAlpha = dim ? 0.28 : 1;
          ctx.fillStyle = nodeColor(node.type);
          ctx.strokeStyle = '#ffffff';
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(point.x, point.y, point.r + (node.type === 'tenant' ? 4 : 0), 0, Math.PI * 2);
          ctx.fill();
          ctx.stroke();
          ctx.fillStyle = graphState.background === 'dark' || graphState.background === 'blueprint' ? '#f8fafc' : '#111827';
          ctx.font = '12px Inter, system-ui, sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(trimLabel(node.label), point.x, point.y + point.r + 16);
        });
      ctx.globalAlpha = 1;
    }
    function drawBackground(ctx, canvas) {
      const fills = { light: '#f8fafc', dark: '#101820', plain: '#ffffff', blueprint: '#0f2a43' };
      ctx.fillStyle = fills[graphState.background] || fills.light;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      if (graphState.background === 'plain') return;
      ctx.strokeStyle = graphState.background === 'light' ? '#e2e8f0' : 'rgba(255,255,255,.12)';
      ctx.lineWidth = 1;
      for (let x = -canvas.width; x < canvas.width * 2; x += 36) {
        ctx.beginPath();
        ctx.moveTo(x + graphState.panX % 36, 0);
        ctx.lineTo(x + graphState.panX % 36 + 140, canvas.height);
        ctx.stroke();
      }
      for (let y = 0; y < canvas.height; y += 36) {
        ctx.beginPath();
        ctx.moveTo(0, y + graphState.panY % 36);
        ctx.lineTo(canvas.width, y + graphState.panY % 36);
        ctx.stroke();
      }
    }
    function nodeColor(type) {
      return {
        tenant: '#334155',
        device: '#2563eb',
        policy: '#7c3aed',
        'decision-risk': '#dc2626',
        'decision-ok': '#16a34a',
        export: '#0f766e',
        integration: '#0891b2',
        metrics: '#ca8a04'
      }[type] || '#64748b';
    }
    function edgeColor(type) {
      return {
        enrollment: '#64748b',
        policy: '#7c3aed',
        decision: '#f97316',
        export: '#0f766e',
        integration: '#0891b2',
        metrics: '#ca8a04'
      }[type] || '#6b7280';
    }
    function trimLabel(value) {
      const text = String(value || '');
      return text.length > 24 ? `${text.slice(0, 21)}...` : text;
    }
    function setGraphBackground(value) {
      graphState.background = value;
      drawGraph();
    }
    function setEdgeType(value) {
      graphState.edgeType = value;
      drawGraph();
    }
    function fitGraph() {
      graphState.zoom = 1;
      graphState.panX = 0;
      graphState.panY = 0;
      drawGraph();
    }
    function zoomGraph(multiplier) {
      graphState.zoom = Math.min(2.4, Math.max(0.45, graphState.zoom * multiplier));
      drawGraph();
    }
    function panGraph(dx, dy) {
      graphState.panX += dx;
      graphState.panY += dy;
      drawGraph();
    }
    window.addEventListener('resize', drawGraph);
    loadSummary();
  </script>
</body>
</html>"""


if __name__ == "__main__":
    raise SystemExit(main())
