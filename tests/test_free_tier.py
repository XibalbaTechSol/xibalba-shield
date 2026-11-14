"""Free-tier pressure (plans & metering design §4.3, phase 3e).

Over its included decisions, a free tenant keeps every decision and every enrolled device (§1). Only new
device enrollments are refused: at the free device cap, and after more than ``free_over_periods``
consecutive months over. The admins are emailed once per month over. All of it is off unless
``SHIELD_FREE_TIER_PRESSURE=1``.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from shield.backend import free_tier as ft
from shield.backend.api import make_handler
from shield.backend.free_tier import EnrollmentRefused
from shield.backend.store import ShieldStore

TENANT = "t-free"
INCLUDED = 5000  # free default per device


@pytest.fixture
def env(monkeypatch):
    monkeypatch.delenv("SHIELD_PLAN_CATALOG_JSON", raising=False)
    monkeypatch.setenv(ft.PRESSURE_ENV, "1")
    monkeypatch.delenv(ft.OVER_PERIODS_ENV, raising=False)
    monkeypatch.setenv("SHIELD_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("SHIELD_SMTP_FROM", "shield@test")
    return monkeypatch


@pytest.fixture
def store(tmp_path, env):
    s = ShieldStore(tmp_path / "shield.sqlite3")
    s.sent = []
    s.free_tier._send_email = lambda to, subject, body: s.sent.append((to, subject, body))
    s.free_tier._spawn = lambda fn: fn()  # synchronous, for determinism
    yield s
    s.close()


def _months_back(k: int) -> str:
    """The UTC month k months before the current one, as YYYY-MM."""
    month = ft.month_of(datetime.now(timezone.utc))
    for _ in range(k):
        month = ft.previous_month(month)
    return month


def _enroll(store, device_id, tenant=TENANT):
    return store.enroll_device(tenant_id=tenant, device_id=device_id, base_url="http://shield.test")


def _usage(store, device_id, billable, month, tenant=TENANT, day=10):
    at = f"{month}-{day:02d}T12:00:00Z"
    if month == _months_back(0):  # never in the future
        at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
    with store._conn:
        store._conn.execute(
            "INSERT INTO usage_reports (tenant_id, log_id, seq_from, seq_to, device_id, billable, excluded_mask, "
            "excluded_fault, checkpoint_root, received_at) VALUES (?,?,?,?,?,?,0,0,'root',?)",
            (tenant, f"log-{device_id}-{month}-{billable}", 0, billable - 1, device_id, billable, at))


def _over(store, *ks, device="dev-1"):
    for k in ks:
        _usage(store, device, INCLUDED + 1, _months_back(k))


def _admin(store, email="owner@tenant.test", tenant=TENANT):
    store.create_account(tenant_id=tenant, email=email, password="correct-horse-battery-9", display_name="Owner")


# -- the streak ------------------------------------------------------------------------------------


def test_n_months_over_still_enrolls_and_n_plus_one_is_refused(store):
    _enroll(store, "dev-1")
    _over(store, 1, 2)                      # two completed months over: not "more than 2"
    assert store.free_tier.status(TENANT)["over_streak"] == 2
    _enroll(store, "dev-2")                 # still allowed
    store.mark_device_synthetic(tenant_id=TENANT, device_id="dev-2")  # keep the cap out of this test
    _usage(store, "dev-1", 2 * INCLUDED, _months_back(3))
    state = store.free_tier.status(TENANT)
    assert state["over_streak"] == 3 and state["enrollment_blocked"] is True
    with pytest.raises(EnrollmentRefused) as refused:
        _enroll(store, "dev-3")
    assert refused.value.status == 402 and "consecutive months" in str(refused.value)


def test_a_month_under_the_allowance_breaks_the_streak(store):
    _enroll(store, "dev-1")
    _over(store, 1, 3, 4)
    _usage(store, "dev-1", 100, _months_back(2))
    assert store.free_tier.status(TENANT)["over_streak"] == 1


def test_the_current_month_counts_once_it_is_already_over(store):
    _enroll(store, "dev-1")
    _over(store, 0, 1, 2)
    assert store.free_tier.status(TENANT)["over_streak"] == 3


def test_the_free_device_cap_refuses_a_third_device(store):
    _enroll(store, "dev-1")
    _enroll(store, "dev-2")
    with pytest.raises(EnrollmentRefused, match="at most 2 devices"):
        _enroll(store, "dev-3")


def test_synthetic_devices_are_neither_seats_nor_usage(store):
    _enroll(store, "dev-1")
    _enroll(store, "demo")
    store.mark_device_synthetic(tenant_id=TENANT, device_id="demo")
    for k in (1, 2, 3):
        _usage(store, "demo", 50 * INCLUDED, _months_back(k))
    state = store.free_tier.status(TENANT)
    assert state["over_streak"] == 0 and state["device_cap_reached"] is False
    _enroll(store, "dev-2")


def test_an_enrolled_device_re_enrolls_while_the_tenant_is_blocked(store):
    _enroll(store, "dev-1")
    _over(store, 1, 2, 3)
    assert store.free_tier.status(TENANT)["enrollment_blocked"] is True
    assert _enroll(store, "dev-1").device_token  # §1: existing devices keep working


def test_paid_tenants_are_never_refused(store):
    _enroll(store, "dev-1")
    _over(store, 1, 2, 3)
    store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="pro", status="active", period_end="2099-01-01T00:00:00Z")
    assert store.free_tier.status(TENANT)["applies"] is False
    for n in range(2, 6):
        _enroll(store, f"dev-{n}")


def test_a_downgrade_from_paid_starts_a_clean_streak(store):
    """Months on a paid plan never count toward free-tier pressure, however far over they were."""
    _enroll(store, "dev-1")
    _over(store, 0, 1, 2, 3)
    store.plans.set_tenant_plan(tenant_id=TENANT, plan_id="free", status="active")  # the webhook on cancellation
    state = store.free_tier.status(TENANT)
    assert state["over_streak"] == 0 and state["over"] is False and state["enrollment_blocked"] is False
    _enroll(store, "dev-2")


def test_the_allowance_counts_devices_that_reported_in_the_month(store):
    """A month in which two devices reported has a two-device allowance, even if one was removed since."""
    _enroll(store, "dev-1")
    _enroll(store, "dev-2")
    _usage(store, "dev-1", INCLUDED + 100, _months_back(1))
    _usage(store, "dev-2", 100, _months_back(1))
    with store._conn:
        store._conn.execute("DELETE FROM devices WHERE device_id='dev-2'")
    assert store.free_tier.status(TENANT)["over_streak"] == 0


def test_pressure_is_off_unless_enabled(store, env):
    env.delenv(ft.PRESSURE_ENV)
    _admin(store)
    _enroll(store, "dev-1")
    _enroll(store, "dev-2")
    for k in (0, 1, 2, 3):  # over a two-device allowance
        _usage(store, "dev-1", 2 * INCLUDED + 1, _months_back(k))
    state = store.free_tier.status(TENANT)
    assert state["enforced"] is False and state["enrollment_blocked"] is True  # shown, not enforced
    _enroll(store, "dev-3")
    assert store.free_tier.notify_if_over(TENANT) is False and store.sent == []


def test_free_over_periods_is_configurable(store, env):
    env.setenv(ft.OVER_PERIODS_ENV, "1")
    _enroll(store, "dev-1")
    _over(store, 1, 2)
    with pytest.raises(EnrollmentRefused):
        _enroll(store, "dev-2")


# -- the email -------------------------------------------------------------------------------------


def test_the_admins_are_emailed_once_per_month_over(store):
    _admin(store)  # signup creates the tenant, so it comes first
    _enroll(store, "dev-1")
    _usage(store, "dev-1", INCLUDED - 1, _months_back(0))
    assert store.free_tier.notify_if_over(TENANT) is False  # under: nothing
    _usage(store, "dev-1", 2, _months_back(0))
    assert store.free_tier.notify_if_over(TENANT) is True
    assert store.free_tier.notify_if_over(TENANT) is False  # once per month
    [(to, subject, body)] = store.sent
    assert to == "owner@tenant.test" and "Free plan" in subject and "5,001" in body and "keep working" in body


def test_concurrent_uploads_claim_one_notice(store):
    _admin(store)  # signup creates the tenant, so it comes first
    _enroll(store, "dev-1")
    _over(store, 0)
    results = []
    threads = [threading.Thread(target=lambda: results.append(store.free_tier.notify_if_over(TENANT)))
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1 and len(store.sent) == 1


def test_a_failed_email_is_retried_at_most_hourly(store, monkeypatch):
    _admin(store)  # signup creates the tenant, so it comes first
    _enroll(store, "dev-1")
    _over(store, 0)
    calls = []

    def down(to, subject, body):
        calls.append(to)
        raise OSError("SMTP down")
    store.free_tier._send_email = down
    assert store.free_tier.notify_if_over(TENANT) is True
    assert store.free_tier.notify_if_over(TENANT) is False  # within the hour: no new attempt
    assert len(calls) == 1
    row = store._conn.execute("SELECT * FROM free_tier_notices").fetchone()
    assert row["sent_at"] is None and row["last_error"]
    with store._conn:  # an hour later
        store._conn.execute("UPDATE free_tier_notices SET claimed_at='2000-01-01T00:00:00Z'")
    store.free_tier._send_email = lambda to, subject, body: store.sent.append(to)
    assert store.free_tier.notify_if_over(TENANT) is True and store.sent == ["owner@tenant.test"]
    row = store._conn.execute("SELECT * FROM free_tier_notices").fetchone()
    assert row["sent_at"] and row["attempts"] == 2


def test_without_smtp_no_notice_is_claimed(store, env):
    env.delenv("SHIELD_SMTP_HOST")
    _admin(store)  # signup creates the tenant, so it comes first
    _enroll(store, "dev-1")
    _over(store, 0)
    assert store.free_tier.notify_if_over(TENANT) is False
    assert store._conn.execute("SELECT COUNT(*) FROM free_tier_notices").fetchone()[0] == 0


# -- over HTTP: the refusal, the page, and §1 ------------------------------------------------------


@pytest.fixture
def backend(store):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store=store, admin_token="admin-token"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield SimpleNamespace(store=store, url=f"http://127.0.0.1:{server.server_port}")
    server.shutdown()
    server.server_close()


def _call(url, body=None, token="admin-token"):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_a_refused_enrollment_answers_402_and_the_page_says_why(backend):
    for device in ("dev-1", "dev-2"):
        assert _call(f"{backend.url}/api/shield/enroll", {"tenant_id": TENANT, "device_id": device})[0] == 201
    status, body = _call(f"{backend.url}/api/shield/enroll", {"tenant_id": TENANT, "device_id": "dev-3"})
    assert status == 402 and "at most 2 devices" in body["error"]
    page = _call(f"{backend.url}/api/shield/billing/usage?tenant_id={TENANT}")[1]
    assert page["free_tier"]["device_cap_reached"] is True and page["free_tier"]["enforced"] is True


def test_the_page_and_enforcement_use_one_allowance(backend):
    """Parity: the usage page's allowance is the one enforcement judges the current month by."""
    store = backend.store
    _enroll(store, "dev-1")
    _enroll(store, "dev-2")
    _usage(store, "dev-2", 10, _months_back(0))
    store._conn.execute("DELETE FROM devices WHERE device_id='dev-2'")  # reported this month, since removed
    store._conn.commit()
    _usage(store, "dev-1", 2 * INCLUDED + 10, _months_back(0))
    page = _call(f"{backend.url}/api/shield/billing/usage?tenant_id={TENANT}")[1]
    month = store.free_tier.status(TENANT)["month"]
    assert (page["seats"], page["included"]) == (month["seats"], month["included"])
    assert (page["overage_decisions"] > 0) == store.free_tier.status(TENANT)["over"]


def test_a_blocked_tenants_enrolled_devices_keep_their_settings(backend):
    """§1: pressure never reaches an enrolled device's control plane."""
    enrollment = _enroll(backend.store, "dev-1")
    _over(backend.store, 1, 2, 3)
    assert backend.store.free_tier.status(TENANT)["enrollment_blocked"] is True
    status, _ = _call(f"{backend.url}/api/shield/device-settings?tenant_id={TENANT}&device_id=dev-1",
                      token=enrollment.device_token)
    assert status == 200
