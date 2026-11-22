"""
Unit and Integration Test Suite for ShieldSentryClient SDK & HITL Approval Pipeline.

Validates:
1. Ingress prompt interception, secret scrubbing, and zero-width canary trap injection.
2. Response auditing for leaked honeytoken canaries and automatic memory quarantine.
3. Proof-of-Justification (PoJ) tool authorization and single-use execution ticket lifecycle.
4. Human-in-the-Loop (HITL) cryptographic approval minting and enforcement for CRITICAL actions.
5. Drop-in tool wrapping via execute_guarded and @client.wrap_tool decorator.
6. End-to-end remote HTTP client invocation against Shield API server.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any
import pytest

from shield.backend.api import make_server
from shield.backend.store import ShieldStore
from shield.sentry import (
    ActionExecutionResult,
    CanaryCheckResult,
    ExecutionTicket,
    IngressResult,
    SentryClientError,
    SentryDefenseStore,
    SentryDeniedError,
    ShieldSentryClient,
    TaintLevel,
    ToolRiskLevel,
)


def test_client_initialization_local():
    client = ShieldSentryClient(
        tenant_id="tenant-local-01",
        agent_did="did:integrity:agent-local-01",
        secret_key="test-client-secret-key-12345",
    )
    assert client.base_url is None
    assert client.default_tenant_id == "tenant-local-01"
    assert client.default_agent_did == "did:integrity:agent-local-01"
    assert isinstance(client.store, SentryDefenseStore)


def test_client_intercept_prompt_and_scrubbing():
    client = ShieldSentryClient(
        tenant_id="tenant-scrub-test",
        agent_did="did:integrity:agent-scrub",
        secret_key="secret-key-456",
    )

    mock_secret = "sk-" + "proj-" + "1234567890abcdef1234567890"
    prompt = f"Please use my OpenAI key {mock_secret} to query the database."

    ingress = client.intercept_prompt(prompt, source_type="user_input", inject_canary=True)

    assert isinstance(ingress, IngressResult)
    assert mock_secret not in ingress.clean_content
    assert "[REDACTED:OPENAI_KEY:" in ingress.clean_content
    assert ingress.redacted_count >= 1
    assert "OPENAI_KEY" in ingress.redacted_types
    assert ingress.canary_token is not None
    assert ingress.taint_level == TaintLevel.UNTRUSTED_INGEST

    # Verify canary recorded in store
    canary = client.store.get_canary(ingress.canary_token)
    assert canary is not None
    assert canary["tripped"] is False


def test_client_audit_response_clean_and_tripped():
    client = ShieldSentryClient(
        tenant_id="tenant-canary-test",
        agent_did="did:integrity:agent-canary",
        secret_key="secret-key-789",
    )

    # 1. Clean response without canary
    clean_check = client.audit_response("This is a safe, clean response with no secrets.")
    assert isinstance(clean_check, CanaryCheckResult)
    assert clean_check.tripped is False
    assert len(clean_check.leaked_canaries) == 0

    # 2. Ingress with canary injection
    ingress = client.intercept_prompt("Normal prompt query", inject_canary=True)
    assert ingress.canary_token is not None

    # 3. Simulate response that leaks the injected text containing the zero-width canary
    leaked_response = f"Here is the answer based on: {ingress.clean_content}"
    audit_check = client.audit_response(leaked_response, sanitize=True)

    assert audit_check.tripped is True
    assert len(audit_check.leaked_canaries) >= 1
    assert audit_check.alert_event is not None
    assert audit_check.alert_event["activity_id"] == 4  # CANARY_TRIP

    # Verify store recorded trip
    canary_record = client.store.get_canary(ingress.canary_token)
    assert canary_record is not None
    assert canary_record["tripped"] is True

    # Verify canary token was stripped in clean_text
    assert audit_check.clean_text != leaked_response


def test_client_action_authorization_and_ticket_lifecycle():
    client = ShieldSentryClient(
        tenant_id="tenant-poj-test",
        agent_did="did:integrity:agent-poj",
        secret_key="secret-key-poj-999",
    )

    # 1. Low risk action succeeds with empty justification
    low_ticket = client.authorize_action("search", {"q": "system status"})
    assert isinstance(low_ticket, ExecutionTicket)
    assert low_ticket.tool_name == "search"
    assert low_ticket.risk_level == "LOW"

    # Verify and consume ticket
    consumed = client.verify_and_consume_ticket(low_ticket.ticket_id, "search", {"q": "system status"})
    assert consumed is True

    # Replay ticket must fail
    with pytest.raises(SentryDeniedError) as exc_info:
        client.verify_and_consume_ticket(low_ticket.ticket_id, "search", {"q": "system status"})
    assert "already been consumed" in str(exc_info.value)

    # 2. High risk action without causal memories must be denied
    with pytest.raises(SentryDeniedError) as exc_info:
        client.authorize_action("bash", {"cmd": "ls -la"})
    assert "requires non-empty causal memory" in str(exc_info.value)

    # 3. High risk action with causal memory succeeds
    high_ticket = client.authorize_action(
        "bash",
        {"cmd": "ls -la"},
        causal_memory_hashes=["sha256:anchor-memory-12345"],
    )
    assert high_ticket.risk_level == "HIGH"

    # Mismatched params during verification must fail
    with pytest.raises(SentryDeniedError) as exc_info:
        client.verify_and_consume_ticket(high_ticket.ticket_id, "bash", {"cmd": "rm -rf /"})
    assert "verification failed" in str(exc_info.value)

    # Correct params verification succeeds
    assert client.verify_and_consume_ticket(high_ticket.ticket_id, "bash", {"cmd": "ls -la"}) is True

    # 4. Untrusted ingest taint level denies high risk action without decontamination proof
    with pytest.raises(SentryDeniedError) as exc_info:
        client.authorize_action(
            "bash",
            {"cmd": "echo test"},
            causal_memory_hashes=["sha256:anchor-memory-12345"],
            taint_level=TaintLevel.UNTRUSTED_INGEST,
        )
    assert "UNTRUSTED_INGEST with no verified decontamination proof" in str(exc_info.value)


def test_client_human_in_the_loop_approval_lifecycle():
    client = ShieldSentryClient(
        tenant_id="tenant-hitl-test",
        agent_did="did:integrity:agent-hitl",
        secret_key="secret-hitl-test-key",
        require_human_approval_for_critical=True,
    )

    critical_tool = "transfer_funds"
    critical_params = {"recipient": "0x1234567890abcdef", "amount": 5000}
    anchor_hashes = ["sha256:approved-financial-directive"]

    # 1. Authorizing CRITICAL action without human approval must be denied
    with pytest.raises(SentryDeniedError) as exc_info:
        client.authorize_action(
            critical_tool,
            critical_params,
            causal_memory_hashes=anchor_hashes,
        )
    assert "requires cryptographic human approval" in str(exc_info.value)

    # 2. Mint human approval receipt
    approval = client.request_human_approval(
        approver_id="operator:alice@xibalba.io",
        tool_name=critical_tool,
        params=critical_params,
        reason="Verified quarterly operational vendor payout",
        ttl_seconds=300,
    )
    assert approval["approver_id"] == "operator:alice@xibalba.io"
    assert approval["tool_name"] == critical_tool
    assert "signature" in approval
    assert approval["expires_at"] > time.time()

    # 3. Tampered params in human approval must fail
    tampered_params = {"recipient": "0x1234567890abcdef", "amount": 999999}
    with pytest.raises(SentryDeniedError) as exc_info:
        client.authorize_action(
            critical_tool,
            tampered_params,
            causal_memory_hashes=anchor_hashes,
            human_approval=approval,
        )
    assert "requires cryptographic human approval" in str(exc_info.value)

    # 4. Correct human approval succeeds and issues execution ticket
    ticket = client.authorize_action(
        critical_tool,
        critical_params,
        causal_memory_hashes=anchor_hashes,
        human_approval=approval,
    )
    assert ticket.tool_name == critical_tool
    assert ticket.risk_level == "CRITICAL"

    # Ticket consumption
    assert client.verify_and_consume_ticket(ticket.ticket_id, critical_tool, critical_params) is True


def test_client_execute_guarded():
    client = ShieldSentryClient(
        tenant_id="tenant-guarded-test",
        agent_did="did:integrity:agent-guarded",
        secret_key="secret-guarded-key",
    )

    def mock_calc(a: int, b: int) -> int:
        return a + b

    def mock_risky_write(filepath: str, content: str) -> str:
        return f"Wrote {len(content)} bytes to {filepath}"

    # 1. Low risk tool execution succeeds directly
    res = client.execute_guarded(mock_calc, tool_name="status", params={"a": 10, "b": 32})
    assert isinstance(res, ActionExecutionResult)
    assert res.success is True
    assert res.result == 42
    assert res.ticket_id is not None
    assert res.risk_level == "LOW"

    # 2. High risk tool without justification is cleanly denied without throwing
    res_denied = client.execute_guarded(
        mock_risky_write,
        tool_name="write_file",
        params={"filepath": "/etc/hosts", "content": "127.0.0.1 bad"},
    )
    assert res_denied.success is False
    assert res_denied.denied is True
    assert "requires non-empty causal memory" in str(res_denied.error)

    # 3. High risk tool with justification executes successfully
    res_allowed = client.execute_guarded(
        mock_risky_write,
        tool_name="write_file",
        params={"filepath": "/tmp/test.txt", "content": "clean data"},
        causal_memory_hashes=["sha256:valid-file-write-instruction"],
    )
    assert res_allowed.success is True
    assert "Wrote 10 bytes to /tmp/test.txt" in str(res_allowed.result)


def test_client_wrap_tool_decorator():
    client = ShieldSentryClient(
        tenant_id="tenant-decorator-test",
        agent_did="did:integrity:agent-decorator",
        secret_key="secret-decorator-key",
    )

    @client.wrap_tool(tool_name="search")
    def search_kb(query: str, limit: int = 5) -> list[str]:
        return [f"result {i} for {query}" for i in range(limit)]

    @client.wrap_tool(tool_name="run_command")
    def execute_terminal(cmd: str) -> str:
        return f"Executed: {cmd}"

    # 1. Low-risk wrapped function executes cleanly
    results = search_kb("neural network", limit=2)
    assert len(results) == 2
    assert getattr(search_kb, "__sentry_guarded__", False) is True

    # 2. High-risk wrapped function denied when no causal memory justification
    with pytest.raises(SentryDeniedError) as exc_info:
        execute_terminal("pytest")
    assert "requires non-empty causal memory" in str(exc_info.value)

    # 3. High-risk wrapped function succeeds when justification passed via special kwarg
    output = execute_terminal("pytest", _sentry_causal_memory_hashes=["sha256:test-command-anchor"])
    assert output == "Executed: pytest"


def test_client_audit_summary_and_siem_events():
    client = ShieldSentryClient(
        tenant_id="tenant-telemetry-test",
        agent_did="did:integrity:agent-telemetry",
        secret_key="secret-telemetry-key",
    )

    # Generate events: ingress, canary trip, denied action, granted action
    ingress = client.intercept_prompt("Check secret token", inject_canary=True)
    client.audit_response(f"Leaking token {ingress.clean_content}")

    try:
        client.authorize_action("bash", {"cmd": "rm -rf"})
    except SentryDeniedError:
        pass

    ticket = client.authorize_action("search", {"q": "info"})
    client.verify_and_consume_ticket(ticket.ticket_id, "search", {"q": "info"})

    # Check SIEM events
    events = client.get_siem_events(limit=50, profile="ocsf")
    assert len(events) >= 3
    for ev in events:
        assert ev["class_uid"] == 6003

    # Check Audit Summary
    summary = client.get_audit_summary()
    assert summary["total_canaries"] >= 1
    assert summary["tripped_canaries"] >= 1
    assert summary["total_tickets"] >= 1
    assert summary["consumed_tickets"] >= 1
    assert summary["total_ocsf_events"] >= 3
    assert summary["denied_actions"] >= 1


def test_client_remote_http_api_end_to_end(tmp_path):
    """Tests the ShieldSentryClient interacting with a live ShieldAPIHandler HTTP server."""
    db_path = tmp_path / "shield_client_test.sqlite3"
    admin_token = "test-client-http-token"
    store = ShieldStore(db_path)

    server = make_server(
        store=store,
        admin_token=admin_token,
        host="127.0.0.1",
        port=0,
    )
    server.start_background()

    try:
        host, port = server.server_address
        base_url = f"http://{host}:{port}"

        client = ShieldSentryClient(
            base_url=base_url,
            api_token=admin_token,
            tenant_id="tenant-http-remote",
            agent_did="did:integrity:agent-remote",
        )

        # 1. Ingress prompt interception via HTTP
        mock_key = "sk-" + "proj-" + "9876543210fedcba9876543210"
        ingress = client.intercept_prompt(
            f"Please run inference with {mock_key}",
            source_type="user_input",
            inject_canary=True,
        )
        assert mock_key not in ingress.clean_content
        assert "[REDACTED:OPENAI_KEY:" in ingress.clean_content
        assert ingress.canary_token is not None

        # 2. Canary audit via HTTP
        audit = client.audit_response(f"Reflecting: {ingress.clean_content}", sanitize=True)
        assert audit.tripped is True
        assert len(audit.leaked_canaries) >= 1

        # 3. HITL approval minting via HTTP
        approval = client.request_human_approval(
            approver_id="security-lead@xibalba.io",
            tool_name="delete_database",
            params={"db": "legacy_orders"},
            reason="Approved decommissioning",
            ttl_seconds=120,
        )
        assert approval["approver_id"] == "security-lead@xibalba.io"
        assert approval["tool_name"] == "delete_database"
        assert "signature" in approval

        # 4. Action authorization requiring HITL approval via HTTP
        # Without approval -> denied
        with pytest.raises(SentryDeniedError) as exc_info:
            client.authorize_action(
                "delete_database",
                {"db": "legacy_orders"},
                causal_memory_hashes=["sha256:decom-order-99"],
                require_human_approval=True,
            )
        assert "requires cryptographic human approval" in str(exc_info.value)

        # With approval -> granted ticket
        ticket = client.authorize_action(
            "delete_database",
            {"db": "legacy_orders"},
            causal_memory_hashes=["sha256:decom-order-99"],
            human_approval=approval,
            require_human_approval=True,
        )
        assert ticket.tool_name == "delete_database"
        assert ticket.risk_level == "CRITICAL"

        # 5. Ticket verification & single-use consumption via HTTP
        assert client.verify_and_consume_ticket(ticket.ticket_id, "delete_database", {"db": "legacy_orders"}) is True

        # Replay rejected via HTTP
        with pytest.raises(SentryDeniedError):
            client.verify_and_consume_ticket(ticket.ticket_id, "delete_database", {"db": "legacy_orders"})

        # 6. Audit summary via HTTP
        summary = client.get_audit_summary()
        assert summary["total_canaries"] >= 1
        assert summary["tripped_canaries"] >= 1
        assert summary["total_tickets"] >= 1
        assert summary["consumed_tickets"] >= 1

        # 7. SIEM events via HTTP
        events = client.get_siem_events(limit=20)
        assert len(events) >= 3

    finally:
        server.shutdown()
        server.server_close()
        store.close()
