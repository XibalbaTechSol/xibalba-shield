"""Plans catalog, tenant plans, backend entitlement issuing, and the device-side fetch.

Design: docs/superpowers/specs/2026-11-12-shield-plans-metering-design.md §1 (billing is never in the
decision path), §4.3 (ShieldPlan), §6 (entitlement), §9 (operator parameters).
"""

from __future__ import annotations

import base64
import json
import os
import socket
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from integrity_sdk.did import Keypair

from shield.backend.api import make_handler
from shield.backend.entitlement_issuer import (
    REASON_ENFORCE,
    REASON_LAPSED,
    REASON_NO_PERIOD,
    REASON_PLAN,
    REASON_PLAN_NOT_CONFIGURED,
    REASON_STATUS,
    REASON_SYNTHETIC,
    decide,
    issue_entitlement,
    load_issuer_config,
)
from shield.backend.plans import FREE_DEFAULTS, PlanConfigError, ShieldPlan, load_plan_catalog
from shield.backend.store import ShieldStore
from shield.cli import _gate_zone_mask
from shield.cli import main as cli_main
from shield.config import load_device_config
from shield.entitlement import (
    STATUS_EXPIRED,
    STATUS_OK,
    STATUS_PLAN,
    STATUS_WRONG_DEVICE,
    verify_entitlement,
)
from shield.entitlement_sync import (
    OUTCOME_REFUSED,
    OUTCOME_RETRY,
    OUTCOME_WRITTEN,
    fetch_entitlement,
    fetch_for_device_config,
    write_entitlement_atomic,
)
from shield.gate_daemon import GateRequest, evaluate_pre_tool_use
from shield.gate_receipts import RECEIPTS_FILENAME, GateReceiptWriter
from shield.gate_zone import GateZoneSettings, build_zone_mask
from shield.policy_engine.engine import EvaluationContext
from tests.test_gate_zone_ais import _DIGEST, _pack, _real_decision

ROOT = Path(__file__).resolve().parents[1]
TENANT, DEVICE, OTHER_DEVICE, AGENT = "t-plans", "dev-a", "dev-b", "agent-1"
BACKEND = Keypair.generate()
BACKEND_PEM = BACKEND.private_pem().decode("ascii")
BACKEND_KEY = base64.b64encode(BACKEND.public_bytes()).decode("ascii")
PRO_ENV = {
    "SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS": "1500",
    "SHIELD_PLAN_PRO_INCLUDED_DECISIONS_PER_DEVICE": "50000",
    "SHIELD_PLAN_PRO_OVERAGE_CENTS_PER_1K": "20",
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("SHIELD_ENTITLEMENT_", "SHIELD_PLAN_")):
            monkeypatch.delenv(name)


def _configure(monkeypatch, **extra):
    monkeypatch.setenv("SHIELD_ENTITLEMENT_SIGNING_KEY", BACKEND_PEM)
    for name, value in {**PRO_ENV, **extra}.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def backend(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store=store, admin_token="admin-token"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield SimpleNamespace(store=store, url=f"http://127.0.0.1:{server.server_port}")
    server.shutdown()
    server.server_close()
    store.close()


def _get(url, token):
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _entitlement_url(base, tenant=TENANT, device=DEVICE):
    return f"{base}/api/shield/entitlement?tenant_id={tenant}&device_id={device}"


def _future(days=20):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _enforce_gate(tmp_path, entitlement_file=None, keys=(BACKEND_KEY,)):
    settings = {"mode": "enforce", "zone": "red", "entitlement_keys": list(keys)}
    if entitlement_file is not None:
        settings["entitlement_file"] = str(entitlement_file)
    return build_zone_mask(GateZoneSettings.from_mapping(settings), tenant_id=TENANT, device_id=DEVICE)


# --------------------------------------------------------------------------- catalog (§4.3, §9)


def test_free_defaults_to_the_section_9_suggestions_and_paid_plans_are_not_configured():
    catalog = load_plan_catalog({})
    assert set(catalog) == {"free"}
    free = catalog["free"]
    assert (free.max_devices, free.included_decisions_per_device, free.zone_enforce) == (2, 5000, False)
    assert free.per_device_monthly_cents == 0 and free.overage_cents_per_1k is None


def test_a_paid_plan_loads_once_its_prices_are_set():
    catalog = load_plan_catalog(PRO_ENV)
    pro = catalog["pro"]
    assert pro == ShieldPlan(id="pro", name="Pro", per_device_monthly_cents=1500,
                             included_decisions_per_device=50000, overage_cents_per_1k=20,
                             max_devices=None, zone_enforce=True)
    assert "team" not in catalog


@pytest.mark.parametrize("env", [
    {**PRO_ENV, "SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS": "-5"},
    {**PRO_ENV, "SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS": "1_500"},
    {**PRO_ENV, "SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS": " 1500"},
    {**PRO_ENV, "SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS": "15.0"},
    {**PRO_ENV, "SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS": "0"},
    {**PRO_ENV, "SHIELD_PLAN_PRO_INCLUDED_DECISIONS_PER_DEVICE": "١٢"},  # Arabic-Indic digits
    {**PRO_ENV, "SHIELD_PLAN_PRO_ZONE_ENFORCE": "yes"},
    {k: v for k, v in PRO_ENV.items() if "OVERAGE" not in k},                   # partially configured
    {**PRO_ENV, "SHIELD_PLAN_PRO_MAX_DEVICES": "0"},
])
def test_an_invalid_paid_plan_is_not_loaded(env):
    catalog = load_plan_catalog(env)
    assert "pro" not in catalog and "free" in catalog


@pytest.mark.parametrize("env", [
    {"SHIELD_PLAN_FREE_ZONE_ENFORCE": "true"},
    {"SHIELD_PLAN_FREE_PER_DEVICE_MONTHLY_CENTS": "100"},
    {"SHIELD_PLAN_FREE_OVERAGE_CENTS_PER_1K": "5"},
    {"SHIELD_PLAN_FREE_MAX_DEVICES": "two"},
])
def test_free_can_never_be_priced_or_include_enforce(env):
    assert "free" not in load_plan_catalog(env)


@pytest.mark.parametrize("document", [
    {"pro": {"per_device_monthly_cents": True, "included_decisions_per_device": 1, "overage_cents_per_1k": 1}},
    {"pro": {"per_device_monthly_cents": 15.0, "included_decisions_per_device": 1, "overage_cents_per_1k": 1}},
    {"pro": {"per_device_monthly_cents": 1500, "included_decisions_per_device": 1, "overage_cents_per_1k": 1,
             "discount": 3}},
])
def test_the_json_catalog_is_validated_strictly(document):
    assert "pro" not in load_plan_catalog({"SHIELD_PLAN_CATALOG_JSON": json.dumps(document)})


def test_an_unparseable_json_catalog_loads_nothing():
    assert load_plan_catalog({"SHIELD_PLAN_CATALOG_JSON": "{not json"}) == {}
    assert load_plan_catalog({"SHIELD_PLAN_CATALOG_JSON": json.dumps({"enterprise": {}})}) == {}


def test_the_json_catalog_configures_plans():
    document = {"free": {"max_devices": 3}, "team": {"per_device_monthly_cents": 2500,
                "included_decisions_per_device": 80000, "overage_cents_per_1k": 15, "max_devices": 50}}
    catalog = load_plan_catalog({"SHIELD_PLAN_CATALOG_JSON": json.dumps(document)})
    assert catalog["free"].max_devices == 3 and catalog["team"].zone_enforce is True
    assert catalog["team"].max_devices == 50 and "pro" not in catalog


def test_a_paid_plan_constructed_directly_must_price_seats_and_overage():
    fields = dict(id="pro", name="Pro", per_device_monthly_cents=1500, included_decisions_per_device=1,
                  overage_cents_per_1k=20, max_devices=None, zone_enforce=True)
    ShieldPlan(**fields)
    with pytest.raises(PlanConfigError):
        ShieldPlan(**{**fields, "overage_cents_per_1k": None})
    with pytest.raises(PlanConfigError):
        ShieldPlan(**{**fields, "per_device_monthly_cents": 0})


def test_shield_plan_refuses_a_bool_as_an_int():
    with pytest.raises(PlanConfigError):
        ShieldPlan(**{**FREE_DEFAULTS, "id": "free", "included_decisions_per_device": True})


# --------------------------------------------------------------------------- tenant plans


def test_a_tenant_without_a_row_is_on_free(tmp_path):
    store = ShieldStore(tmp_path / "s.sqlite3")
    assert store.plans.get_tenant_plan("nobody")["plan_id"] == "free"
    row = store.plans.set_tenant_plan(tenant_id="t", plan_id="pro", status="active", period_end=_future())
    assert row["plan_id"] == "pro" and row["status"] == "active" and row["updated_at"]
    store.plans.set_tenant_plan(tenant_id="t", plan_id="pro", status="canceled")
    assert store.plans.get_tenant_plan("t")["status"] == "canceled"
    with pytest.raises(ValueError):
        store.plans.set_tenant_plan(tenant_id="t", plan_id="enterprise", status="active")
    with pytest.raises(ValueError):
        store.plans.set_tenant_plan(tenant_id="t", plan_id="pro", status="happy")
    with pytest.raises(ValueError):
        store.plans.set_tenant_plan(tenant_id="t", plan_id="pro", status="active", period_end="2026-12-01T00:00:00")
    store.close()


# --------------------------------------------------------------------------- issuing policy


NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
GRACE = timedelta(days=7)


def _decide(plan_id="pro", status="active", period_end=NOW + timedelta(days=10), synthetic=False, env=PRO_ENV):
    row = {"plan_id": plan_id, "status": status,
           "period_end": period_end.isoformat() if period_end else None}
    return decide(plan_row=row, catalog=load_plan_catalog(env), synthetic=synthetic, grace=GRACE, now=NOW)


def test_a_paid_active_plan_enforces_until_period_end_plus_grace():
    assert _decide() == (True, NOW + timedelta(days=17), REASON_ENFORCE)
    assert _decide(status="past_due")[0] is True
    assert _decide(status="trialing")[0] is True


@pytest.mark.parametrize("kwargs, reason", [
    ({"plan_id": "free"}, REASON_PLAN),
    ({"status": "canceled"}, REASON_STATUS),
    ({"status": "unpaid"}, REASON_STATUS),
    ({"period_end": None}, REASON_NO_PERIOD),
    ({"period_end": NOW - timedelta(days=8)}, REASON_LAPSED),
    ({"synthetic": True}, REASON_SYNTHETIC),
    ({"env": {}}, REASON_PLAN_NOT_CONFIGURED),
    ({"plan_id": "team"}, REASON_PLAN_NOT_CONFIGURED),
])
def test_everything_else_is_a_rolling_non_enforcing_document(kwargs, reason):
    assert _decide(**kwargs) == (False, NOW + GRACE, reason)


def test_a_lapsed_period_still_issues_rather_than_crashing_the_signer():
    config, _ = load_issuer_config({"SHIELD_ENTITLEMENT_SIGNING_KEY": BACKEND_PEM})
    document, reason = issue_entitlement(
        config=config, tenant_id=TENANT, device_id=DEVICE, catalog=load_plan_catalog(PRO_ENV), synthetic=False,
        plan_row={"plan_id": "pro", "status": "active", "period_end": (NOW - timedelta(days=30)).isoformat()},
        now=NOW)
    assert reason == REASON_LAPSED and document["zone_enforce"] is False


def test_an_entitlement_expires_at_period_end_plus_grace():
    config, _ = load_issuer_config({"SHIELD_ENTITLEMENT_SIGNING_KEY": BACKEND_PEM})
    document, _ = issue_entitlement(
        config=config, tenant_id=TENANT, device_id=DEVICE, catalog=load_plan_catalog(PRO_ENV), synthetic=False,
        plan_row={"plan_id": "pro", "status": "active", "period_end": (NOW + timedelta(days=1)).isoformat()},
        now=NOW)

    def verify(at):
        return verify_entitlement(document, trusted_keys=[BACKEND_KEY], tenant_id=TENANT, device_id=DEVICE, now=at)

    assert verify(NOW + timedelta(days=8) - timedelta(seconds=1)) == STATUS_OK
    assert verify(NOW + timedelta(days=8)) == STATUS_EXPIRED


# --------------------------------------------------------------------------- signing key


def test_no_key_means_issuing_is_not_configured():
    assert load_issuer_config({})[0] is None


@pytest.mark.parametrize("env", [
    {"SHIELD_ENTITLEMENT_SIGNING_KEY": "not a pem"},
    {"SHIELD_ENTITLEMENT_SIGNING_KEY": BACKEND_PEM, "SHIELD_ENTITLEMENT_SIGNING_KEY_FILE": "/x.pem"},
    {"SHIELD_ENTITLEMENT_SIGNING_KEY_FILE": "/definitely/not/here.pem"},
    {"SHIELD_ENTITLEMENT_SIGNING_KEY": BACKEND_PEM, "SHIELD_ENTITLEMENT_GRACE_DAYS": "0"},
    {"SHIELD_ENTITLEMENT_SIGNING_KEY": BACKEND_PEM, "SHIELD_ENTITLEMENT_GRACE_DAYS": "7d"},
    {"SHIELD_ENTITLEMENT_SIGNING_KEY": BACKEND_PEM, "SHIELD_ENTITLEMENT_PREVIOUS_KEYS": "bm90LWEta2V5"},
])
def test_an_invalid_key_configuration_issues_nothing(env):
    config, reason = load_issuer_config(env)
    assert config is None and reason


def test_the_key_loads_from_a_file_from_one_line_pem_and_keeps_previous_keys(tmp_path):
    path = tmp_path / "entitlement.pem"
    path.write_text(BACKEND_PEM)
    assert load_issuer_config({"SHIELD_ENTITLEMENT_SIGNING_KEY_FILE": str(path)})[0].public_key == BACKEND_KEY
    one_line = BACKEND_PEM.replace("\n", "\\n")
    old = base64.b64encode(Keypair.generate().public_bytes()).decode()
    config, _ = load_issuer_config({"SHIELD_ENTITLEMENT_SIGNING_KEY": one_line,
                                    "SHIELD_ENTITLEMENT_PREVIOUS_KEYS": f" {old} ,"})
    assert config.trusted_keys == (BACKEND_KEY, old)


def test_the_issuer_never_generates_a_key():
    source = (ROOT / "shield/backend/entitlement_issuer.py").read_text(encoding="utf-8")
    assert "generate(" not in source


# --------------------------------------------------------------------------- the route


def test_round_trip_paid_plan_enforces_and_free_runs_as_shadow(backend, tmp_path, monkeypatch):
    _configure(monkeypatch)
    enrollment = backend.store.enroll_device(tenant_id=TENANT, device_id=DEVICE, base_url=backend.url)
    # The device pins the backend key at enrollment.
    assert enrollment.device_config["gate_zone"] == {"entitlement_keys": [BACKEND_KEY]}

    # Free (no plan row): a valid document that does not include enforce.
    status, body = _get(_entitlement_url(backend.url), enrollment.device_token)
    assert status == 200 and body["zone_enforce_reason"] == REASON_PLAN
    now = datetime.now(timezone.utc)
    assert verify_entitlement(body["entitlement"], trusted_keys=[BACKEND_KEY], tenant_id=TENANT,
                              device_id=DEVICE, now=now) == STATUS_PLAN
    path = tmp_path / "entitlement.json"
    path.write_text(json.dumps(body["entitlement"]))
    assert _enforce_gate(tmp_path, path).effective_mode() == ("shadow", STATUS_PLAN)

    # Pro, active, in period: enforce.
    backend.store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="pro", status="active", period_end=_future())
    status, body = _get(_entitlement_url(backend.url), enrollment.device_token)
    assert status == 200 and body["entitlement"]["zone_enforce"] is True and body["entitlement"]["plan"] == "pro"
    assert verify_entitlement(body["entitlement"], trusted_keys=[BACKEND_KEY], tenant_id=TENANT,
                              device_id=DEVICE, now=now) == STATUS_OK
    path.write_text(json.dumps(body["entitlement"]))
    assert _enforce_gate(tmp_path, path).effective_mode() == ("enforce", STATUS_OK)


def test_no_signing_key_issues_nothing_and_the_device_stays_shadow(backend, tmp_path, monkeypatch):
    for name, value in PRO_ENV.items():
        monkeypatch.setenv(name, value)
    enrollment = backend.store.enroll_device(tenant_id=TENANT, device_id=DEVICE, base_url=backend.url)
    assert "gate_zone" not in enrollment.device_config
    backend.store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="pro", status="active", period_end=_future())
    status, body = _get(_entitlement_url(backend.url), enrollment.device_token)
    assert status == 503 and body == {"error": "entitlement issuing not configured"}
    assert _enforce_gate(tmp_path, tmp_path / "entitlement.json").effective_mode()[0] == "shadow"


def test_wrong_credentials_are_refused_and_a_document_is_bound_to_its_device(backend, monkeypatch):
    _configure(monkeypatch)
    a = backend.store.enroll_device(tenant_id=TENANT, device_id=DEVICE, base_url=backend.url)
    b = backend.store.enroll_device(tenant_id=TENANT, device_id=OTHER_DEVICE, base_url=backend.url)
    assert _get(_entitlement_url(backend.url), "wrong-token")[0] == 401
    # Device B's credential cannot fetch device A's entitlement.
    assert _get(_entitlement_url(backend.url, device=DEVICE), b.device_token)[0] == 401
    assert _get(_entitlement_url(backend.url, tenant="t-other"), a.device_token)[0] == 401
    backend.store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="pro", status="active", period_end=_future())
    status, body = _get(_entitlement_url(backend.url), a.device_token)
    assert status == 200
    assert verify_entitlement(body["entitlement"], trusted_keys=[BACKEND_KEY], tenant_id=TENANT,
                              device_id=OTHER_DEVICE, now=datetime.now(timezone.utc)) == STATUS_WRONG_DEVICE


def test_a_synthetic_device_never_gets_enforce(backend, monkeypatch):
    _configure(monkeypatch)
    enrollment = backend.store.enroll_device(tenant_id=TENANT, device_id=DEVICE, base_url=backend.url)
    backend.store.mark_device_synthetic(tenant_id=TENANT, device_id=DEVICE)
    backend.store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="pro", status="active", period_end=_future())
    status, body = _get(_entitlement_url(backend.url), enrollment.device_token)
    assert status == 200 and body["entitlement"]["zone_enforce"] is False
    assert body["zone_enforce_reason"] == REASON_SYNTHETIC


def test_an_unconfigured_paid_plan_is_issued_as_non_enforcing(backend, monkeypatch):
    monkeypatch.setenv("SHIELD_ENTITLEMENT_SIGNING_KEY", BACKEND_PEM)  # no pro prices set
    enrollment = backend.store.enroll_device(tenant_id=TENANT, device_id=DEVICE, base_url=backend.url)
    backend.store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="pro", status="active", period_end=_future())
    status, body = _get(_entitlement_url(backend.url), enrollment.device_token)
    assert status == 200 and body["entitlement"]["zone_enforce"] is False
    assert body["zone_enforce_reason"] == REASON_PLAN_NOT_CONFIGURED


def test_the_enrollment_config_loads_and_pins_the_key_for_the_gate(backend, tmp_path, monkeypatch):
    _configure(monkeypatch)
    enrollment = backend.store.enroll_device(tenant_id=TENANT, device_id=DEVICE, base_url=backend.url)
    config_path = tmp_path / "device.json"
    config_path.write_text(json.dumps(enrollment.device_config))
    device_config = load_device_config(config_path)
    assert device_config.gate_zone["entitlement_keys"] == [BACKEND_KEY]
    backend.store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="pro", status="active", period_end=_future())
    path = tmp_path / "entitlement.json"
    assert fetch_for_device_config(device_config, path=path).outcome == OUTCOME_WRITTEN
    mask = _gate_zone_mask(SimpleNamespace(zone_mode="enforce", zone="red", zone_entitlement_file=path), device_config)
    assert mask.effective_mode() == ("enforce", STATUS_OK)


# --------------------------------------------------------------------------- device fetch


def _signed(**overrides):
    now = datetime.now(timezone.utc)
    fields = dict(tenant_id=TENANT, device_id=DEVICE, plan="pro", zone_enforce=True,
                  issued_at=now - timedelta(minutes=1), not_after=now + timedelta(days=30), keypair=BACKEND)
    fields.update(overrides)
    from shield.entitlement import sign_entitlement

    return sign_entitlement(**fields)


def _fetch(path, transport, keys=(BACKEND_KEY,)):
    return fetch_entitlement(base_url="http://backend.invalid", tenant_id=TENANT, device_id=DEVICE,
                             trusted_keys=list(keys), path=path, transport=transport, auth_header=lambda: "Bearer t")


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _raise_oserror(_url, _headers):
    raise OSError("connection refused")


@pytest.mark.parametrize("transport, outcome", [
    (_raise_oserror, OUTCOME_RETRY),
    (lambda _u, _h: (503, '{"error": "entitlement issuing not configured"}'), OUTCOME_RETRY),
    (lambda _u, _h: (404, ""), OUTCOME_RETRY),
    (lambda _u, _h: (401, '{"error": "invalid device token"}'), OUTCOME_REFUSED),
    (lambda _u, _h: (200, "not json"), OUTCOME_REFUSED),
    (lambda _u, _h: (200, json.dumps({"entitlement": _signed(keypair=Keypair.generate())})), OUTCOME_REFUSED),
    (lambda _u, _h: (200, json.dumps({"entitlement": _signed(device_id=OTHER_DEVICE)})), OUTCOME_REFUSED),
    (lambda _u, _h: (200, json.dumps({"entitlement": _signed(
        issued_at=datetime.now(timezone.utc) - timedelta(days=9),
        not_after=datetime.now(timezone.utc) - timedelta(days=1))})), OUTCOME_REFUSED),
])
def test_a_failed_fetch_leaves_the_previous_file_intact(tmp_path, transport, outcome):
    path = tmp_path / "entitlement.json"
    previous = _signed()
    write_entitlement_atomic(path, previous)
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    result = _fetch(path, transport)
    assert result.outcome == outcome
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["entitlement.json"]


def test_a_verified_document_replaces_the_file_including_a_downgrade(tmp_path):
    path = tmp_path / "entitlement.json"
    write_entitlement_atomic(path, _signed())
    downgrade = _signed(plan="pro", zone_enforce=False)
    result = _fetch(path, lambda _u, _h: (200, json.dumps({"entitlement": downgrade})))
    assert result.outcome == OUTCOME_WRITTEN and result.status == STATUS_PLAN
    assert json.loads(path.read_text()) == downgrade


def test_no_pinned_keys_refuses_to_write(tmp_path):
    path = tmp_path / "entitlement.json"
    result = _fetch(path, lambda _u, _h: (200, json.dumps({"entitlement": _signed()})), keys=())
    assert result.outcome == OUTCOME_REFUSED and not path.exists()


def test_a_failed_replace_keeps_the_old_file_and_cleans_the_temp(tmp_path, monkeypatch):
    path = tmp_path / "entitlement.json"
    write_entitlement_atomic(path, _signed())
    before = path.read_bytes()

    def broken_replace(_src, _dst):
        raise OSError("disk full")

    monkeypatch.setattr("shield.entitlement_sync.os.replace", broken_replace)
    result = _fetch(path, lambda _u, _h: (200, json.dumps({"entitlement": _signed(plan="team")})))
    assert result.outcome == OUTCOME_RETRY
    assert path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["entitlement.json"]


# --------------------------------------------------------------------------- never in the decision path (§1)


def test_backend_unreachable_and_no_entitlement_the_gate_still_decides(tmp_path):
    path = tmp_path / "entitlement.json"
    device_config = SimpleNamespace(
        backend_url=f"http://127.0.0.1:{_closed_port()}", tenant_id=TENANT, device_id=DEVICE,
        device_token="tok", device_key_path="", gate_zone={"entitlement_keys": [BACKEND_KEY]},
        backend_ca_file="", backend_client_cert="", backend_client_key="")
    assert fetch_for_device_config(device_config, path=path).outcome == OUTCOME_RETRY
    assert not path.exists()

    writer = GateReceiptWriter(tmp_path / "r", signer=Keypair.generate(), hmac_key=os.urandom(32),
                               log_id="shield-gate:dev-a")
    response = evaluate_pre_tool_use(
        GateRequest(agent_id=AGENT, tool_name="Bash", tool_input_sha256=_DIGEST),
        evaluator=lambda _e, _c: _real_decision("allow"), basis_evaluator=_pack("allow"),
        ctx=EvaluationContext(tenant_id=TENANT, device_role="r", device_id=DEVICE), device_id=DEVICE,
        enforcement_mode="enforce", zone_mask=_enforce_gate(tmp_path, path), receipts=writer,
    )
    writer.close()
    # Enforce was requested against a red zone; with no entitlement it ran as shadow and allowed.
    assert response["decision"] == "allow"
    assert response["zone_mask"]["mode"] == "shadow" and response["zone_mask"]["requested_mode"] == "enforce"
    receipts = (tmp_path / "r" / RECEIPTS_FILENAME).read_text().splitlines()
    assert len(receipts) == 1 and "ais_zone_entitlement:missing" in json.loads(receipts[0])["controls"]


@pytest.mark.parametrize("module", ["shield/gate_daemon.py", "shield/gate_zone.py", "shield/entitlement.py",
                                    "shield/gate_receipts.py"])
def test_the_decision_path_never_imports_the_fetcher_or_the_backend(module):
    import ast

    tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(f"{node.module or ''}.{alias.name}" for alias in node.names)
    assert not [name for name in imported if "entitlement_sync" in name or "backend" in name.split(".")]


# --------------------------------------------------------------------------- CLI


def test_cli_entitlement_fetch_writes_the_file(backend, tmp_path, monkeypatch):
    _configure(monkeypatch)
    enrollment = backend.store.enroll_device(tenant_id=TENANT, device_id=DEVICE, base_url=backend.url)
    backend.store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="pro", status="active", period_end=_future())
    config_path = tmp_path / "device.json"
    config_path.write_text(json.dumps(enrollment.device_config))
    path = tmp_path / "out" / "entitlement.json"
    assert cli_main(["entitlement-fetch", "--device-config", str(config_path), "--entitlement-file", str(path),
                     "--once"]) == 0
    assert json.loads(path.read_text())["zone_enforce"] is True
    monkeypatch.delenv("SHIELD_ENTITLEMENT_SIGNING_KEY")
    before = path.read_bytes()
    assert cli_main(["entitlement-fetch", "--device-config", str(config_path), "--entitlement-file", str(path),
                     "--once"]) == 3
    assert path.read_bytes() == before
