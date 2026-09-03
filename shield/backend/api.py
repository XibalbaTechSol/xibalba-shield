"""Stdlib HTTP API for the Xibalba Shield platform MVP."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse
import urllib.error
import urllib.request

from ..config import ConfigError
from .store import ShieldStore
from ..transaction_gateway import TransactionIntent, TransactionPolicy, evaluate_transaction_intent
from ..transaction_simulator import SimulationError, simulate_transaction_intent

DEFAULT_DB_PATH = Path.home() / ".xibalba-shield" / "backend.sqlite3"


def make_handler(*, store: ShieldStore, admin_token: str, public_base_url: str = "", allowed_origin: str = "*"):
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
            if parsed.path == "/api/shield/health":
                self._send_json({"ok": True, "service": "xibalba-shield-backend"})
                return
            if parts[:3] == ["api", "shield", "devices"]:
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None:
                    return
                if not self._require_admin(tenant_id=tenant_id):
                    return
                if len(parts) == 3:
                    self._send_json({"devices": store.list_devices(tenant_id=tenant_id)})
                    return
                if len(parts) == 4:
                    device = store.get_device(tenant_id=tenant_id, device_id=parts[3])
                    if device is None:
                        self._send_error(HTTPStatus.NOT_FOUND, "device not found")
                    else:
                        self._send_json(device)
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
            if parsed.path == "/api/shield/integrations":
                tenant_id = self._tenant_from_query_or_error(query)
                if tenant_id is None:
                    return
                if not self._require_admin(tenant_id=tenant_id):
                    return
                self._send_json({"integrations": store.list_integrations(tenant_id=tenant_id)})
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
            self._send_error(HTTPStatus.NOT_FOUND, "not found")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            parts = [part for part in parsed.path.split("/") if part]
            try:
                body = self._read_json()
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
            auth = self.headers.get("Authorization", "")
            prefix = "Bearer "
            token = auth[len(prefix):] if auth.startswith(prefix) else ""
            if not token:
                self._send_error(HTTPStatus.UNAUTHORIZED, "admin token required")
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

        def _send_json(self, payload: dict[str, Any], *, status: HTTPStatus = HTTPStatus.OK) -> None:
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.end_headers()
            self.wfile.write(raw)

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
            "did_registered": False,
            "bcc_middleware": "not_checked",
            "oracle_readback": "blocked_until_rpc_credentials",
            "synthetic": True,
        },
    )
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


def run_server(*, host: str, port: int, db_path: Path, admin_token: str, public_base_url: str = "", allowed_origin: str = "*") -> ThreadingHTTPServer:
    store = ShieldStore(db_path)
    handler = make_handler(store=store, admin_token=admin_token, public_base_url=public_base_url, allowed_origin=allowed_origin)
    server = ThreadingHTTPServer((host, port), handler)
    server.store = store  # type: ignore[attr-defined]
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shield-backend")
    parser.add_argument("--host", default=os.getenv("SHIELD_BACKEND_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SHIELD_BACKEND_PORT", "8765")))
    parser.add_argument("--db-path", type=Path, default=Path(os.getenv("SHIELD_BACKEND_DB", str(DEFAULT_DB_PATH))))
    parser.add_argument("--admin-token", default=os.getenv("SHIELD_BACKEND_TOKEN", ""))
    parser.add_argument("--public-base-url", default=os.getenv("SHIELD_PUBLIC_BASE_URL", ""))
    parser.add_argument("--allowed-origin", default=os.getenv("SHIELD_BACKEND_ALLOWED_ORIGIN", "*"), help="CORS origin for browser callers (e.g. the dashboard)")
    args = parser.parse_args(argv)

    if not args.admin_token:
        args.admin_token = secrets.token_urlsafe(32)
        print(
            "shield-backend: no SHIELD_BACKEND_TOKEN/--admin-token set — generated a random "
            f"super-admin token for this run (save it, it will not be shown again):\n"
            f"  {args.admin_token}",
            file=sys.stderr,
        )

    server = run_server(
        host=args.host,
        port=args.port,
        db_path=args.db_path,
        admin_token=args.admin_token,
        allowed_origin=args.allowed_origin,
        public_base_url=args.public_base_url,
    )
    print(f"shield-backend listening on http://{args.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshield-backend stopping")
    finally:
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
      buildGraph(data);
      drawGraph();
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
