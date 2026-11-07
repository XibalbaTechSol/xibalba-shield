from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shield.backend.store import ShieldStore
from shield.edr import (
    AuthorizationError,
    ExecutionAuthorization,
    Host,
    ResponseIntent,
    ResponsePolicy,
    VerifiedDetection,
    evaluate_response_intent,
)
from shield.edr.connectors.crowdstrike import CrowdStrikeConnector, CrowdStrikeError
from shield.edr.provider import Detection, UnsupportedAction, normalize_severity
from shield.edr.simulated import SimulatedProvider

T0 = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
AGENT_DID = "did:integrity:" + "ab" * 32


def raw_intent(**overrides):
    values = {
        "tenant_id": "tenant-a",
        "request_id": "req-1",
        "actor_type": "agent",
        "actor_id": "hermes-analyst",
        "actor_did": AGENT_DID,
        "vendor": "simulated",
        "host_id": "host-1",
        "action": "contain_host",
        "justification": "credential dumping on EHR jump host",
        "detection_id": "det-1",
    }
    values.update(overrides)
    return values


def intent(**overrides) -> ResponseIntent:
    return ResponseIntent.from_dict(raw_intent(**overrides))


def critical(i: ResponseIntent) -> VerifiedDetection:
    return VerifiedDetection(vendor=i.vendor, detection_id=i.detection_id or "", host_id=i.host_id, severity="critical")


# -- intent validation ---------------------------------------------------------------


def test_intent_hash_is_stable_and_content_bound():
    a, b = intent(), intent()
    assert a.intent_hash() == b.intent_hash()
    assert a.intent_hash().startswith("sha256:")
    assert intent(host_id="host-2").intent_hash() != a.intent_hash()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"action": "wipe_disk"}, "action must be one of"),
        ({"actor_type": "robot"}, "actor_type must be one of"),
        ({"actor_did": None}, "agent actors must present an actor_did"),
        ({"justification": "  "}, "justification must not be empty"),
        ({"action": "kill_process", "params": {"pid": -1}}, "pid must be a positive integer"),
        ({"action": "kill_process", "params": {}}, "missing params"),
        ({"action": "contain_host", "params": {"force": True}}, "unexpected params"),
        ({"action": "quarantine_file", "params": {"sha256": "abc"}}, "sha256 must be"),
        ({"action": "rtr_command", "params": {"base_command": "ls", "command_string": "rm -rf /"}}, "must begin with"),
        ({"action": "rtr_command", "params": {"base_command": "ls", "command_string": "ls\nrm"}}, "single line"),
        ({"host_id": ""}, "host_id must be"),
    ],
)
def test_intent_rejects_malformed_input(overrides, message):
    with pytest.raises(ValueError, match=message):
        intent(**overrides)


# -- policy evaluation ---------------------------------------------------------------


def test_agent_contain_host_escalates_by_default_even_on_critical():
    i = intent()
    decision = evaluate_response_intent(i, ResponsePolicy(), verified_detection=critical(i))
    assert decision.action == "escalate"
    assert decision.rule_id == "agent-contain-host-escalate"
    assert decision.required_approvals == 1
    assert decision.execution == "not_executed"


def test_agent_contain_host_setting_auto_allow_critical_requires_verified_critical():
    policy = ResponsePolicy.from_dict({"agent_contain_host": "auto_allow_critical"})
    i = intent()
    assert evaluate_response_intent(i, policy, verified_detection=critical(i)).action == "allow"
    assert evaluate_response_intent(i, policy).action == "escalate"  # caller cannot assert severity
    high = VerifiedDetection(i.vendor, i.detection_id or "", i.host_id, "high")
    assert evaluate_response_intent(i, policy, verified_detection=high).action == "escalate"


def test_verified_detection_must_match_the_intent_host():
    i = intent()
    other_host = VerifiedDetection(i.vendor, i.detection_id or "", "host-9", "critical")
    with pytest.raises(ValueError, match="does not match"):
        evaluate_response_intent(i, ResponsePolicy(), verified_detection=other_host)


def test_agent_contain_host_setting_deny():
    decision = evaluate_response_intent(intent(), ResponsePolicy.from_dict({"agent_contain_host": "deny"}))
    assert (decision.action, decision.rule_id) == ("deny", "agent-contain-host-denied")


def test_agents_cannot_change_policy():
    i = intent(action="policy_change", params={"policy_id": "prevention-1", "change": {"ml": "off"}})
    assert evaluate_response_intent(i, ResponsePolicy()).rule_id == "agent-action-denied"


def test_rtr_requires_allowlisted_base_command():
    i = intent(actor_type="human", actor_id="alice", actor_did=None, action="rtr_command",
               params={"base_command": "netstat", "command_string": "netstat -an"})
    assert evaluate_response_intent(i, ResponsePolicy()).rule_id == "rtr-command-not-allowed"
    allowed = ResponsePolicy.from_dict({"rtr_allowed_base_commands": ["netstat"]})
    assert evaluate_response_intent(i, allowed).action == "escalate"


def test_two_person_rule_and_human_quarantine_allow():
    lift = intent(actor_type="human", actor_id="alice", actor_did=None, action="lift_containment")
    assert evaluate_response_intent(lift, ResponsePolicy()).required_approvals == 2
    quarantine = intent(actor_type="human", actor_id="alice", actor_did=None, action="quarantine_file",
                        params={"sha256": "a" * 64})
    assert evaluate_response_intent(quarantine, ResponsePolicy()).action == "allow"


def test_agent_actions_escalate_unless_auto_allowed():
    q = intent(action="quarantine_file", params={"sha256": "b" * 64})
    assert evaluate_response_intent(q, ResponsePolicy()).rule_id == "agent-default-escalate"
    policy = ResponsePolicy.from_dict({"agent_auto_allow_actions": ["quarantine_file"]})
    assert evaluate_response_intent(q, policy).action == "allow"


def test_disabled_vendor_is_denied():
    policy = ResponsePolicy.from_dict({"enabled_vendors": ["crowdstrike"]})
    assert evaluate_response_intent(intent(), policy).rule_id == "vendor-not-enabled"


@pytest.mark.parametrize(
    "raw",
    [
        {"agent_contain_host": "yolo"},
        {"approval_ttl_seconds": 5},
        {"escalate_actions": ["format_c"]},
        {"surprise": 1},
        {"enabled_vendors": []},
    ],
)
def test_policy_rejects_invalid_configuration(raw):
    with pytest.raises(ValueError):
        ResponsePolicy.from_dict(raw)


# -- provider execution guard --------------------------------------------------------


def provider() -> SimulatedProvider:
    return SimulatedProvider(hosts=[Host("simulated", "host-1", "ehr-jump-01", "Windows", "normal")])


def allow_auth(i: ResponseIntent, **overrides) -> ExecutionAuthorization:
    decision = evaluate_response_intent(i, ResponsePolicy.from_dict({"agent_contain_host": "auto_allow_critical"}),
                                        verified_detection=critical(i)).as_dict()
    values = {"intent_hash": i.intent_hash(), "decision": decision, "consumed_at": "2026-11-06T12:00:00Z"}
    values.update(overrides)
    return ExecutionAuthorization(**values)


def test_execute_runs_with_matching_consumed_authorization():
    p, i = provider(), intent()
    result = p.execute(i, allow_auth(i))
    assert result.status == "succeeded" and result.simulated is True
    assert p.get_host("host-1").containment == "contained"


def test_execute_rejects_authorization_for_a_different_intent():
    p = provider()
    with pytest.raises(AuthorizationError, match="does not match"):
        p.execute(intent(host_id="host-1"), allow_auth(intent(request_id="req-other")))
    assert p.performed == []


def test_execute_rejects_unconsumed_and_non_allow_decisions():
    p, i = provider(), intent()
    with pytest.raises(AuthorizationError, match="not been consumed"):
        p.execute(i, allow_auth(i, consumed_at=None))
    escalated = evaluate_response_intent(i, ResponsePolicy()).as_dict()
    with pytest.raises(AuthorizationError, match="distinct approver"):
        p.execute(i, ExecutionAuthorization(i.intent_hash(), escalated, (), "2026-11-06T12:00:00Z"))
    denied = evaluate_response_intent(i, ResponsePolicy.from_dict({"agent_contain_host": "deny"})).as_dict()
    with pytest.raises(AuthorizationError, match="does not authorize"):
        p.execute(i, ExecutionAuthorization(i.intent_hash(), denied, (), "2026-11-06T12:00:00Z"))
    assert p.performed == []


def test_execute_ignores_self_approval():
    p, i = provider(), intent()
    escalated = evaluate_response_intent(i, ResponsePolicy()).as_dict()
    self_approval = ({"approver_id": i.actor_id, "verdict": "approve", "intent_hash": i.intent_hash()},)
    with pytest.raises(AuthorizationError):
        p.execute(i, ExecutionAuthorization(i.intent_hash(), escalated, self_approval, "2026-11-06T12:00:00Z"))


def test_execute_rejects_vendor_mismatch():
    i = intent(vendor="crowdstrike")
    with pytest.raises(AuthorizationError, match="vendor"):
        provider().execute(i, allow_auth(i))


# -- store: state machine and ledger -------------------------------------------------


@pytest.fixture
def store(tmp_path):
    s = ShieldStore(tmp_path / "shield.sqlite3")
    s._conn.execute("INSERT INTO tenants (tenant_id, created_at) VALUES ('tenant-a', '2026-11-06T00:00:00Z')")
    s._conn.commit()
    yield s
    s.close()


def decide(store, i: ResponseIntent, policy: ResponsePolicy | None = None, now=T0, **kw):
    decision = evaluate_response_intent(i, policy or ResponsePolicy(), **kw).as_dict()
    return store.response.record_intent(intent=i.canonical(), decision=decision, now=now)


def test_escalated_intent_full_lifecycle_executes_once(store):
    i = intent()
    row = decide(store, i)
    assert row["status"] == "pending"
    with pytest.raises(ValueError, match="pending"):
        store.response.consume(tenant_id="tenant-a", intent_hash=i.intent_hash(), now=T0)
    approved = store.response.record_approval(tenant_id="tenant-a", intent_hash=i.intent_hash(),
                                              approver_id="alice", verdict="approve", reason="confirmed IOC", now=T0)
    assert approved["status"] == "approved"

    auth = store.response.consume(tenant_id="tenant-a", intent_hash=i.intent_hash(), now=T0 + timedelta(seconds=5))
    p = provider()
    result = p.execute(i, auth)
    store.response.record_result(tenant_id="tenant-a", intent_hash=i.intent_hash(), result=result.as_dict(),
                                 now=T0 + timedelta(seconds=6))

    with pytest.raises(ValueError, match="consumed|executed"):
        store.response.consume(tenant_id="tenant-a", intent_hash=i.intent_hash(), now=T0 + timedelta(seconds=7))

    chain = store.response.chain(tenant_id="tenant-a", intent_hash=i.intent_hash())
    assert chain["status"] == "executed"
    assert [e["event_type"] for e in chain["events"]] == ["decided", "approval_recorded", "consumed", "executed"]
    assert store.response.verify_chain(tenant_id="tenant-a")["valid"] is True


def test_actor_cannot_approve_own_intent_and_reason_is_required(store):
    i = intent()
    decide(store, i)
    with pytest.raises(PermissionError):
        store.response.record_approval(tenant_id="tenant-a", intent_hash=i.intent_hash(),
                                       approver_id=i.actor_id, verdict="approve", reason="me", now=T0)
    with pytest.raises(ValueError, match="reason"):
        store.response.record_approval(tenant_id="tenant-a", intent_hash=i.intent_hash(),
                                       approver_id="alice", verdict="approve", reason=" ", now=T0)


def test_two_person_rule_needs_distinct_approvers(store):
    i = intent(actor_type="human", actor_id="bob", actor_did=None, action="lift_containment")
    decide(store, i)
    h = i.intent_hash()
    assert store.response.record_approval(tenant_id="tenant-a", intent_hash=h, approver_id="alice",
                                          verdict="approve", reason="ok", now=T0)["status"] == "pending"
    with pytest.raises(ValueError, match="already recorded"):
        store.response.record_approval(tenant_id="tenant-a", intent_hash=h, approver_id="alice",
                                       verdict="approve", reason="again", now=T0)
    assert store.response.record_approval(tenant_id="tenant-a", intent_hash=h, approver_id="carol",
                                          verdict="approve", reason="ok", now=T0)["status"] == "approved"
    auth = store.response.consume(tenant_id="tenant-a", intent_hash=h, now=T0)
    auth.check(i)  # two distinct approvers satisfy the in-process guard too


def test_deny_verdict_is_terminal(store):
    i = intent()
    decide(store, i)
    row = store.response.record_approval(tenant_id="tenant-a", intent_hash=i.intent_hash(),
                                         approver_id="alice", verdict="deny", reason="false positive", now=T0)
    assert row["status"] == "denied"
    with pytest.raises(ValueError):
        store.response.consume(tenant_id="tenant-a", intent_hash=i.intent_hash(), now=T0)


def test_expired_intent_cannot_be_approved_or_consumed_and_expiry_persists(store):
    i = intent()
    decide(store, i)
    late = T0 + timedelta(seconds=901)
    with pytest.raises(ValueError, match="expired"):
        store.response.record_approval(tenant_id="tenant-a", intent_hash=i.intent_hash(),
                                       approver_id="alice", verdict="approve", reason="late", now=late)
    chain = store.response.chain(tenant_id="tenant-a", intent_hash=i.intent_hash())
    assert chain["status"] == "expired"
    assert chain["events"][-1]["event_type"] == "expired"


def test_allowed_intent_consumes_without_approval_and_only_once(store):
    i = intent(actor_type="human", actor_id="alice", actor_did=None, action="quarantine_file",
               params={"sha256": "c" * 64})
    assert decide(store, i)["status"] == "allowed"
    auth = store.response.consume(tenant_id="tenant-a", intent_hash=i.intent_hash(), now=T0)
    assert auth.approvals == ()
    with pytest.raises(ValueError):
        store.response.consume(tenant_id="tenant-a", intent_hash=i.intent_hash(), now=T0)


def test_request_id_is_idempotent_but_cannot_be_reused_for_other_intent(store):
    i = intent()
    first = decide(store, i)
    assert decide(store, i)["intent_hash"] == first["intent_hash"]
    with pytest.raises(ValueError, match="already used"):
        decide(store, intent(host_id="host-2"))
    assert store.response.verify_chain(tenant_id="tenant-a")["events"] == 1


def test_unknown_tenant_is_rejected(store):
    with pytest.raises(KeyError):
        decide(store, intent(tenant_id="tenant-zzz"))


def test_decision_must_be_bound_to_the_recorded_intent(store):
    i = intent()
    decision = evaluate_response_intent(intent(host_id="host-2"), ResponsePolicy()).as_dict()
    with pytest.raises(ValueError, match="not bound"):
        store.response.record_intent(intent=i.canonical(), decision=decision, now=T0)


def test_ledger_tampering_is_detected(store):
    i = intent()
    decide(store, i)
    store.response.record_approval(tenant_id="tenant-a", intent_hash=i.intent_hash(),
                                   approver_id="alice", verdict="approve", reason="ok", now=T0)
    store._conn.execute(
        "UPDATE response_events SET payload_json=? WHERE tenant_id='tenant-a' AND seq=2",
        ('{"approver_id": "mallory", "reason": "ok", "status": "approved", "verdict": "approve"}',),
    )
    store._conn.commit()
    report = store.response.verify_chain(tenant_id="tenant-a")
    assert report == {"valid": False, "events": 2, "broken_at": 2, "reason": "event_hash mismatch"}


def test_expire_due_sweeps_open_intents(store):
    decide(store, intent())
    decide(store, intent(request_id="req-2", host_id="host-2"))
    assert store.response.expire_due(tenant_id="tenant-a", now=T0 + timedelta(hours=1)) == 2
    assert {r["status"] for r in store.response.list_intents(tenant_id="tenant-a")} == {"expired"}
    assert store.response.verify_chain(tenant_id="tenant-a")["valid"] is True


# -- CrowdStrike connector against recorded falconpy response shapes ------------------


class FakeHosts:
    def __init__(self, status_code=202):
        self.calls = []
        self.status_code = status_code

    def get_device_details(self, ids):
        self.calls.append(("get_device_details", ids))
        return {"status_code": 200, "body": {"resources": [
            {"device_id": ids[0], "hostname": "ehr-jump-01", "platform_name": "Windows", "status": "normal"}
        ], "errors": []}}

    def perform_action(self, action_name, ids):
        self.calls.append(("perform_action", action_name, ids))
        if self.status_code >= 300:
            return {"status_code": self.status_code, "body": {"resources": [], "errors": [{"code": 403, "message": "access denied, authorization failed"}]}}
        return {"status_code": self.status_code, "body": {"resources": [{"id": ids[0], "path": ""}], "errors": []}}


class FakeAlerts:
    def query_alerts_v2(self, **params):
        self.query = params
        return {"status_code": 200, "body": {"resources": ["cid:ind:abc"], "errors": []}}

    def get_alerts_v2(self, composite_ids):
        return {"status_code": 200, "body": {"resources": [{
            "composite_id": composite_ids[0],
            "device": {"device_id": "aid-1"},
            "severity": 90,
            "severity_name": "Critical",
            "display_name": "CredentialDumping",
            "created_timestamp": "2026-11-06T11:59:00Z",
            "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/detections/cid:ind:abc",
        }], "errors": []}}


def cs_intent(**overrides) -> ResponseIntent:
    return intent(vendor="crowdstrike", host_id="aid-1", detection_id="cid:ind:abc", **overrides)


def test_crowdstrike_reads_normalize_hosts_and_detections():
    cs = CrowdStrikeConnector(hosts=FakeHosts(), alerts=FakeAlerts())
    host = cs.get_host("aid-1")
    assert (host.hostname, host.containment) == ("ehr-jump-01", "normal")
    detections = cs.list_detections(since=T0 - timedelta(hours=1))
    assert detections[0].severity == "critical"
    assert detections[0].host_id == "aid-1"
    assert detections[0].console_url.startswith("https://falcon.crowdstrike.com/")


def test_crowdstrike_contain_goes_through_execute_guard():
    hosts = FakeHosts()
    cs = CrowdStrikeConnector(hosts=hosts, alerts=FakeAlerts())
    i = cs_intent()
    with pytest.raises(AuthorizationError):
        cs.execute(i, allow_auth(cs_intent(request_id="other")))
    assert not any(c[0] == "perform_action" for c in hosts.calls)
    result = cs.execute(i, allow_auth(i))
    assert hosts.calls[-1] == ("perform_action", "contain", ["aid-1"])
    assert (result.status, result.simulated) == ("pending", False)


def test_crowdstrike_failure_is_reported_not_raised_and_unsupported_actions_refuse():
    cs = CrowdStrikeConnector(hosts=FakeHosts(status_code=403), alerts=FakeAlerts())
    i = cs_intent()
    result = cs.execute(i, allow_auth(i))
    assert result.status == "failed" and "access denied" in (result.detail or "")
    k = cs_intent(actor_type="human", actor_id="alice", actor_did=None, action="kill_process", params={"pid": 4})
    policy = ResponsePolicy.from_dict({"escalate_actions": []})
    auth = ExecutionAuthorization(k.intent_hash(), evaluate_response_intent(k, policy).as_dict(), (), "2026-11-06T12:00:00Z")
    with pytest.raises(UnsupportedAction):
        cs.execute(k, auth)


def test_crowdstrike_read_errors_raise():
    class BadHosts(FakeHosts):
        def get_device_details(self, ids):
            return {"status_code": 401, "body": {"errors": [{"message": "access denied, invalid bearer token"}]}}

    with pytest.raises(CrowdStrikeError, match="401"):
        CrowdStrikeConnector(hosts=BadHosts(), alerts=FakeAlerts()).get_host("aid-1")


@pytest.mark.parametrize(
    ("value", "expected"),
    [("Critical", "critical"), ("High", "high"), (95, "critical"), (55, "medium"), (None, "informational"), ("10", "informational")],
)
def test_normalize_severity(value, expected):
    assert normalize_severity(value) == expected


def test_simulated_detections_listing():
    d = Detection("simulated", "det-1", "host-1", "high", created_at="2026-11-06T12:00:00+00:00")
    p = SimulatedProvider(detections=[d])
    assert p.list_detections(since=T0 - timedelta(minutes=1)) == [d]
    assert p.list_detections(since=T0 + timedelta(minutes=1)) == []


# -- HTTP API endpoints -------------------------------------------------------------

import json
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from shield.backend.api import make_handler

API_ADMIN = "test-api-admin-token"


@pytest.fixture
def api_server(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store._conn.execute("INSERT INTO tenants (tenant_id, created_at) VALUES ('tenant-a', '2026-11-06T00:00:00Z')")
    store._conn.commit()
    handler = make_handler(store=store, admin_token=API_ADMIN)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    yield base_url, store
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def api_req(url, *, method="GET", body=None, token=API_ADMIN):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"error": raw}
        return exc.code, payload


def test_api_response_intent_lifecycle_and_invariants(api_server):
    base_url, store = api_server

    # 1. Submit intent -> escalates (HTTP 201)
    status, res = api_req(
        f"{base_url}/api/shield/response-intents",
        method="POST",
        body=raw_intent(),
    )
    assert status == 201
    decision = res["decision"]
    intent_record = res["intent"]
    assert decision["action"] == "escalate"
    intent_hash = decision["intent_hash"]
    assert intent_record["status"] == "pending"

    # 2. Listed in pending intents
    status, queue = api_req(f"{base_url}/api/shield/response-intents?tenant_id=tenant-a&status=pending")
    assert status == 200
    assert any(i["intent_hash"] == intent_hash for i in queue["intents"])

    # 3. Invariant 4: Agent cannot approve intents
    status, err = api_req(
        f"{base_url}/api/shield/response-approvals",
        method="POST",
        body={
            "tenant_id": "tenant-a",
            "intent_hash": intent_hash,
            "approver_id": "agent-1",
            "actor_type": "agent",
            "verdict": "approve",
            "reason": "i am an agent",
        },
    )
    assert status == 403

    # Actor cannot approve own intent (store rule)
    status, err = api_req(
        f"{base_url}/api/shield/response-approvals",
        method="POST",
        body={
            "tenant_id": "tenant-a",
            "intent_hash": intent_hash,
            "approver_id": "hermes-analyst",
            "verdict": "approve",
            "reason": "myself",
        },
    )
    assert status == 403

    # 4. Human admin approves
    status, app_res = api_req(
        f"{base_url}/api/shield/response-approvals",
        method="POST",
        body={
            "tenant_id": "tenant-a",
            "intent_hash": intent_hash,
            "approver_id": "secops-alice",
            "verdict": "approve",
            "reason": "verified malware outbreak",
        },
    )
    assert status == 200
    assert app_res["status"] == "approved"

    # 5. Consume and execute
    status, consume_res = api_req(
        f"{base_url}/api/shield/response-approvals/consume",
        method="POST",
        body={
            "tenant_id": "tenant-a",
            "intent_hash": intent_hash,
            "execute": True,
        },
    )
    assert status == 200
    assert consume_res["result"]["status"] == "succeeded"

    # Invariant: Replay consume fails with 409 Conflict
    status, conflict = api_req(
        f"{base_url}/api/shield/response-approvals/consume",
        method="POST",
        body={"tenant_id": "tenant-a", "intent_hash": intent_hash},
    )
    assert status == 409

    # 6. Retrieve full chain
    status, chain = api_req(f"{base_url}/api/shield/response-ledger/{intent_hash}?tenant_id=tenant-a")
    assert status == 200
    assert chain["status"] == "executed"
    assert [e["event_type"] for e in chain["events"]] == ["decided", "approval_recorded", "consumed", "executed"]

    # 7. Response ledger & chain verification
    status, ledger = api_req(f"{base_url}/api/shield/response-ledger?tenant_id=tenant-a")
    assert status == 200
    assert ledger["verify"]["valid"] is True
    assert ledger["verify"]["events"] == 4

    # 8. EDR connectors listing and test probe
    status, conn_res = api_req(f"{base_url}/api/shield/edr/connectors?tenant_id=tenant-a")
    assert status == 200
    assert any(c["kind"] == "simulated" for c in conn_res["connectors"])

    status, test_res = api_req(
        f"{base_url}/api/shield/edr/connectors/test",
        method="POST",
        body={"tenant_id": "tenant-a", "vendor": "simulated"},
    )
    assert status == 200
    assert test_res["ok"] is True

