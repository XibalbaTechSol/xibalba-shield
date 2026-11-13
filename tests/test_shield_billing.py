"""Stripe checkout, portal, webhook and seat sync for Shield (billing phase 3c).

Design: docs/superpowers/specs/2026-11-12-shield-plans-metering-design.md §4–§5, §8 test 8.

The real `StripeGateway` runs, including its HMAC webhook verification; only its one network function
(`_send`) is replaced by an in-memory Stripe so every request Shield makes is recorded and asserted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

import integrity_sdk.billing.stripe_gateway as stripe_gateway
from shield.backend.api import make_handler
from shield.backend.shield_billing import BillingConfig, ShieldBilling, _trial_days
from shield.backend.store import ShieldStore

TENANT = "t-billing"
SECRET, WHSEC, METER = "sk_test_51Qa7Shieldbilling", "whsec_7Fq2shieldwebhook", "mtr_shield_decisions"
PRICE_DEVICE, PRICE_OVERAGE = "price_pro_device", "price_pro_overage"
PERIOD_END = 1_798_761_600  # 2027-01-01T00:00:00Z
ENV = {
    "SHIELD_STRIPE_SECRET_KEY": SECRET, "SHIELD_STRIPE_WEBHOOK_SECRET": WHSEC, "SHIELD_STRIPE_METER_ID": METER,
    "SHIELD_STRIPE_PRICE_PRO_DEVICE": PRICE_DEVICE, "SHIELD_STRIPE_PRICE_PRO_OVERAGE": PRICE_OVERAGE,
    "SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS": "1200", "SHIELD_PLAN_PRO_INCLUDED_DECISIONS_PER_DEVICE": "25000",
    "SHIELD_PLAN_PRO_OVERAGE_CENTS_PER_1K": "40", "SHIELD_PLAN_PRO_MAX_DEVICES": "5",
}


def _device_price(**overrides):
    return {"id": PRICE_DEVICE, "active": True, "currency": "usd", "billing_scheme": "per_unit", "unit_amount": 1200,
            "recurring": {"usage_type": "licensed", "interval": "month", "interval_count": 1}, **overrides}


def _overage_price(**overrides):
    return {"id": PRICE_OVERAGE, "active": True, "currency": "usd", "billing_scheme": "per_unit", "unit_amount": 40,
            "recurring": {"usage_type": "metered", "meter": METER, "interval": "month", "interval_count": 1},
            **overrides}


class FakeStripe:
    """Just enough of the Stripe API for Shield's calls; records each one."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict, dict]] = []
        self.prices = {PRICE_DEVICE: _device_price(), PRICE_OVERAGE: _overage_price()}
        self.sessions: dict[str, dict] = {}
        self.subscriptions: dict[str, dict] = {}
        self.fail = False

    def send(self, method, url, **kwargs):
        if self.fail:
            raise stripe_gateway.BillingUnavailable("Stripe is temporarily unavailable; retry shortly")
        path = url[len(stripe_gateway.STRIPE_API_ORIGIN):]
        data, headers = kwargs.get("data") or {}, kwargs.get("headers") or {}
        self.calls.append((method, path, data, headers))
        if path.startswith("/prices/"):
            return self.prices[path.split("/")[-1]]
        if path == "/customers":
            return {"id": "cus_shield1"}
        if path == "/checkout/sessions":
            sid = f"cs_test_{len(self.sessions) + 1}"
            self.sessions[sid] = {"id": sid, "url": f"https://checkout.stripe.test/{sid}", "status": "open"}
            return self.sessions[sid]
        if path.startswith("/checkout/sessions/"):
            return self.sessions[path.split("/")[-1]]
        if path == "/billing_portal/sessions":
            return {"url": "https://billing.stripe.test/portal"}
        if path.startswith("/subscriptions/"):
            return self.subscriptions[path.split("/")[-1]]
        if path.startswith("/subscription_items/"):
            return {"id": path.split("/")[-1], "quantity": int(data["quantity"])}
        raise AssertionError(f"unexpected Stripe call {method} {path}")

    def subscription(self, sub_id="sub_1", *, status="trialing", customer="cus_shield1", quantity=1,
                     device=None, overage=None, trial_end=PERIOD_END - 86400):
        self.subscriptions[sub_id] = {
            "id": sub_id, "customer": customer, "status": status, "trial_end": trial_end,
            "items": {"data": [
                {"id": "si_device", "quantity": quantity, "current_period_end": PERIOD_END,
                 "price": device or _device_price()},
                {"id": "si_overage", "current_period_end": PERIOD_END, "price": overage or _overage_price()},
            ]},
        }

    def of(self, path):
        return [call for call in self.calls if call[1] == path]


@pytest.fixture
def stripe(monkeypatch):
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SHIELD_STRIPE_TRIAL_DAYS", raising=False)
    monkeypatch.delenv("SHIELD_STRIPE_LIVE", raising=False)
    fake = FakeStripe()
    monkeypatch.setattr(stripe_gateway, "_send", fake.send)
    return fake


@pytest.fixture
def backend(tmp_path, stripe):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    def sync_now(tenant_id):  # the production contract (never raises) without the thread, for determinism
        try:
            store.billing.sync_seats(tenant_id)
        except Exception:  # noqa: BLE001
            pass
    store.billing.sync_seats_soon = sync_now
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store=store, admin_token="admin-token"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield SimpleNamespace(store=store, url=f"http://127.0.0.1:{server.server_port}", stripe=stripe)
    server.shutdown()
    server.server_close()
    store.close()


def _call(url, *, body=None, token="admin-token", headers=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    request = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET",
                                     headers={"Content-Type": "application/json", **(headers or {}),
                                              **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _enroll(b, device_id, synthetic=False):
    status, _ = _call(f"{b.url}/api/shield/enroll", body={"tenant_id": TENANT, "device_id": device_id})
    assert status == 201
    if synthetic:
        b.store.mark_device_synthetic(tenant_id=TENANT, device_id=device_id)


def _checkout(b, plan_id="pro"):
    return _call(f"{b.url}/api/shield/billing/checkout", body={"tenant_id": TENANT, "plan_id": plan_id})


def _signed(event, secret=WHSEC, timestamp=None):
    body = json.dumps(event).encode()
    t = int(time.time() if timestamp is None else timestamp)
    sig = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return body, {"Stripe-Signature": f"t={t},v1={sig}"}


def _event(event_id, kind="customer.subscription.updated", sub_id="sub_1", customer="cus_shield1"):
    obj = {"id": "cs_test_1", "subscription": sub_id, "customer": customer} if kind == "checkout.session.completed" \
        else {"id": sub_id, "customer": customer}
    return {"id": event_id, "type": kind, "livemode": False, "data": {"object": obj}}


def _webhook(b, event, **sign):
    body, headers = _signed(event, **sign)
    return _call(f"{b.url}/api/shield/stripe/webhook", raw=body, headers=headers, token=None)


def _plan(b):
    return b.store.plans.get_tenant_plan(TENANT)


def _subscribe(b, status="trialing", event_id="evt_1"):
    """Checkout, then the webhook a completed payment produces."""
    assert _checkout(b)[0] == 200
    b.stripe.subscription(status=status)
    return _webhook(b, _event(event_id, "checkout.session.completed"))


# -- configuration and price validation (§8 test 8) ----------------------------------------------

def test_without_stripe_configuration_checkout_is_unavailable_and_nothing_changes(backend, monkeypatch):
    monkeypatch.delenv("SHIELD_STRIPE_SECRET_KEY")
    _enroll(backend, "dev-1")
    status, body = _checkout(backend)
    assert status == 503 and "not configured" in body["error"]
    assert backend.stripe.calls == [] and _plan(backend)["plan_id"] == "free"


@pytest.mark.parametrize("env", [
    {"SHIELD_STRIPE_METER_ID": "meter-without-prefix"},
    {"SHIELD_STRIPE_PRICE_PRO_DEVICE": "not-a-price"},
    {"SHIELD_STRIPE_SECRET_KEY": "sk_test_placeholder"},
])
def test_incomplete_configuration_is_not_ready(env):
    assert not BillingConfig.from_env({**ENV, **env}).ready


@pytest.mark.parametrize("which, override", [
    ("device", {"unit_amount": 1500}),
    ("device", {"currency": "eur"}),
    ("device", {"active": False}),
    ("device", {"billing_scheme": "tiered"}),
    ("device", {"recurring": {"usage_type": "metered", "interval": "month", "interval_count": 1}}),
    ("device", {"recurring": {"usage_type": "licensed", "interval": "year", "interval_count": 1}}),
    ("overage", {"unit_amount": 10}),
    ("overage", {"recurring": {"usage_type": "metered", "meter": "mtr_other", "interval": "month",
                               "interval_count": 1}}),
    ("overage", {"recurring": {"usage_type": "licensed", "meter": METER, "interval": "month", "interval_count": 1}}),
])
def test_a_stripe_price_that_differs_from_the_catalog_refuses_checkout(backend, which, override):
    price_id = PRICE_DEVICE if which == "device" else PRICE_OVERAGE
    backend.stripe.prices[price_id] = (_device_price if which == "device" else _overage_price)(**override)
    _enroll(backend, "dev-1")
    status, body = _checkout(backend)
    assert status == 503 and "does not match the approved Shield catalog" in body["error"]
    assert backend.stripe.of("/checkout/sessions") == []


@pytest.mark.parametrize("raw, days", [(None, 14), ("", 14), ("0", 0), ("30", 30), ("31", 14), ("-1", 14),
                                       ("7d", 14)])
def test_trial_days_fall_back_to_the_default_rather_than_granting_more(raw, days):
    assert _trial_days(raw) == days


# -- checkout ----------------------------------------------------------------------------------

def test_checkout_bills_non_synthetic_devices_with_a_card_on_file_trial(backend):
    _enroll(backend, "dev-1")
    _enroll(backend, "dev-2")
    _enroll(backend, "demo", synthetic=True)
    status, body = _checkout(backend)
    assert status == 200 and body["url"] == "https://checkout.stripe.test/cs_test_1"

    (_, _, customer, customer_headers), = backend.stripe.of("/customers")
    assert customer == {"metadata[tenant_id]": TENANT, "metadata[product]": "shield"}
    assert customer_headers["Idempotency-Key"] == f"shield-customer:{TENANT}"

    (_, _, params, headers), = backend.stripe.of("/checkout/sessions")
    assert params["line_items[0][price]"] == PRICE_DEVICE and params["line_items[0][quantity]"] == 2
    assert params["line_items[1][price]"] == PRICE_OVERAGE and "line_items[1][quantity]" not in params
    assert params["payment_method_collection"] == "always"
    assert params["subscription_data[trial_period_days]"] == 14
    assert params["subscription_data[metadata][tenant_id]"] == TENANT
    assert headers["Idempotency-Key"].startswith("shield-checkout:")
    assert _plan(backend)["plan_id"] == "free"  # checkout alone never grants a plan


def test_trial_days_zero_omits_the_trial(backend, monkeypatch):
    monkeypatch.setenv("SHIELD_STRIPE_TRIAL_DAYS", "0")
    _enroll(backend, "dev-1")
    assert _checkout(backend)[0] == 200
    (_, _, params, _), = backend.stripe.of("/checkout/sessions")
    assert "subscription_data[trial_period_days]" not in params


def test_an_open_checkout_is_reused_and_a_retry_after_expiry_gets_a_fresh_key(backend):
    _enroll(backend, "dev-1")
    assert _checkout(backend)[1]["url"].endswith("cs_test_1")
    assert _checkout(backend)[1]["url"].endswith("cs_test_1")
    assert len(backend.stripe.of("/checkout/sessions")) == 1
    backend.stripe.sessions["cs_test_1"]["status"] = "expired"
    assert _checkout(backend)[1]["url"].endswith("cs_test_2")
    first, second = (call[3]["Idempotency-Key"] for call in backend.stripe.of("/checkout/sessions"))
    assert first != second


def test_a_failed_session_create_retries_with_the_same_idempotency_key(backend):
    _enroll(backend, "dev-1")
    backend.stripe.fail = True
    assert _checkout(backend)[0] == 503
    backend.stripe.fail = False
    assert _checkout(backend)[0] == 200
    attempt = backend.store.billing._conn.execute("SELECT attempt FROM checkout_requests").fetchone()[0]
    assert backend.stripe.of("/checkout/sessions")[0][3]["Idempotency-Key"] == f"shield-checkout:{attempt}"


@pytest.mark.parametrize("plan_id", ["free", "enterprise", ""])
def test_only_paid_plans_can_be_bought(backend, plan_id):
    status, _ = _checkout(backend, plan_id)
    assert status == 400 and backend.stripe.calls == []


def test_a_tenant_already_on_a_paid_plan_is_sent_to_the_portal(backend):
    _enroll(backend, "dev-1")
    _subscribe(backend, status="active")
    status, body = _checkout(backend)
    assert status == 409 and "billing portal" in body["error"]


def test_a_tenant_over_the_plan_device_cap_cannot_check_out(backend):
    for n in range(6):
        _enroll(backend, f"dev-{n}")
    status, body = _checkout(backend)
    assert status == 409 and "at most 5 devices" in body["error"]


def test_billing_routes_require_the_tenant_admin(backend):
    for path in ("checkout", "portal", "sync"):
        status, _ = _call(f"{backend.url}/api/shield/billing/{path}", body={"tenant_id": TENANT}, token="wrong")
        assert status in (401, 403)
    assert _call(f"{backend.url}/api/shield/billing?tenant_id={TENANT}", token="wrong")[0] in (401, 403)
    assert backend.stripe.calls == []


# -- webhook: the only writer of tenant_plans ----------------------------------------------------

def test_a_completed_checkout_puts_the_tenant_on_a_trialing_plan_from_stripes_state(backend):
    _enroll(backend, "dev-1")
    status, body = _subscribe(backend)
    assert status == 200 and body == {"received": True, "plan_id": "pro", "status": "trialing"}
    plan = _plan(backend)
    assert (plan["plan_id"], plan["status"], plan["period_end"]) == ("pro", "trialing", "2027-01-01T00:00:00Z")
    status, info = _call(f"{backend.url}/api/shield/billing?tenant_id={TENANT}")
    assert status == 200 and info["trial_available"] is False and info["billed_seats"] == 1


def test_the_trial_is_offered_once_per_tenant(backend):
    _enroll(backend, "dev-1")
    _subscribe(backend)
    backend.stripe.subscription(status="canceled")
    assert _webhook(backend, _event("evt_2", "customer.subscription.deleted"))[1]["plan_id"] == "free"
    assert _checkout(backend)[0] == 200
    (_, _, params, _) = backend.stripe.of("/checkout/sessions")[-1]
    assert "subscription_data[trial_period_days]" not in params


@pytest.mark.parametrize("stripe_status, plan_id, status", [
    ("active", "pro", "active"), ("past_due", "pro", "past_due"), ("unpaid", "pro", "unpaid"),
    ("incomplete", "pro", "incomplete"), ("paused", "pro", "unpaid"),
    ("canceled", "free", "active"), ("incomplete_expired", "free", "active"),
])
def test_subscription_status_maps_onto_the_tenant_plan(backend, stripe_status, plan_id, status):
    _enroll(backend, "dev-1")
    _subscribe(backend)
    backend.stripe.subscription(status=stripe_status)
    _webhook(backend, _event("evt_2"))
    assert (_plan(backend)["plan_id"], _plan(backend)["status"]) == (plan_id, status)


def test_the_event_body_never_decides_the_plan(backend):
    """A delivered `active` event while Stripe says canceled: Stripe's current state wins."""
    _enroll(backend, "dev-1")
    _subscribe(backend)
    backend.stripe.subscription(status="canceled")
    event = _event("evt_2")
    event["data"]["object"]["status"] = "active"
    _webhook(backend, event)
    assert _plan(backend)["plan_id"] == "free"


@pytest.mark.parametrize("tamper", ["signature", "secret", "stale", "livemode"])
def test_an_unverified_webhook_is_refused(backend, tamper):
    _enroll(backend, "dev-1")
    _checkout(backend)
    backend.stripe.subscription(status="active")
    event = _event("evt_1", "checkout.session.completed")
    if tamper == "livemode":
        event["livemode"] = True
    body, headers = _signed(event, secret="whsec_attacker" if tamper == "secret" else WHSEC,
                            timestamp=time.time() - 3600 if tamper == "stale" else None)
    if tamper == "signature":
        body = body.replace(b"cus_shield1", b"cus_shield2")
    status, _ = _call(f"{backend.url}/api/shield/stripe/webhook", raw=body, headers=headers, token=None)
    assert status == 400 and _plan(backend)["plan_id"] == "free"


def test_events_for_other_customers_or_types_grant_nothing(backend):
    _enroll(backend, "dev-1")
    _checkout(backend)
    backend.stripe.subscription(status="active", customer="cus_cortex")
    assert _webhook(backend, _event("evt_1", customer="cus_cortex"))[1]["ignored"] is True
    assert _webhook(backend, {**_event("evt_2"), "type": "invoice.paid"})[1]["ignored"] is True
    assert _plan(backend)["plan_id"] == "free"


def test_a_subscription_customer_mismatch_is_refused(backend):
    _enroll(backend, "dev-1")
    _checkout(backend)
    backend.stripe.subscription(status="active", customer="cus_someone_else")
    assert _webhook(backend, _event("evt_1"))[0] == 400
    assert _plan(backend)["plan_id"] == "free"


@pytest.mark.parametrize("device, overage", [
    (_device_price(id="price_unknown"), None),
    (_device_price(unit_amount=1), None),
    (None, _overage_price(recurring={"usage_type": "metered", "meter": "mtr_other", "interval": "month",
                                     "interval_count": 1})),
])
def test_a_subscription_whose_prices_do_not_match_is_refused(backend, device, overage):
    _enroll(backend, "dev-1")
    _checkout(backend)
    backend.stripe.subscription(status="active", device=device, overage=overage)
    assert _webhook(backend, _event("evt_1"))[0] == 400
    assert _plan(backend)["plan_id"] == "free"


def test_a_duplicate_event_is_applied_once_without_calling_stripe(backend):
    _enroll(backend, "dev-1")
    _subscribe(backend, status="active")
    backend.stripe.subscription(status="canceled")
    before = len(backend.stripe.calls)
    status, body = _webhook(backend, _event("evt_1", "checkout.session.completed"))
    assert status == 200 and body["duplicate"] is True
    assert _plan(backend)["plan_id"] == "pro" and len(backend.stripe.calls) == before


def test_a_concurrent_delivery_of_the_same_event_is_applied_once(backend):
    """The race window is the Stripe re-read: another delivery records the event while we wait on it."""
    _enroll(backend, "dev-1")
    _subscribe(backend, status="active")
    backend.stripe.subscription(status="canceled")
    real_send = backend.stripe.send

    def concurrent_delivery(method, url, **kwargs):
        if "/subscriptions/" in url:
            with backend.store.billing._conn:
                backend.store.billing._conn.execute(
                    "INSERT INTO stripe_events (id, processed_at) VALUES ('evt_2', 0)")
        return real_send(method, url, **kwargs)
    stripe_gateway._send = concurrent_delivery
    try:
        status, body = _webhook(backend, _event("evt_2", "customer.subscription.deleted"))
    finally:
        stripe_gateway._send = real_send
    assert status == 200 and body["duplicate"] is True
    assert _plan(backend)["plan_id"] == "pro"


def test_an_old_subscription_ending_does_not_overwrite_the_current_one(backend):
    _enroll(backend, "dev-1")
    _subscribe(backend, status="active")
    backend.stripe.subscription("sub_old", status="canceled")
    assert _webhook(backend, _event("evt_2", "customer.subscription.deleted", sub_id="sub_old"))[1]["ignored"]
    assert _plan(backend)["plan_id"] == "pro"


def test_a_failed_plan_write_rolls_back_the_event_so_redelivery_applies_it(backend, monkeypatch):
    _enroll(backend, "dev-1")
    _checkout(backend)
    backend.stripe.subscription(status="active")
    real = backend.store.plans.set_tenant_plan

    def boom(**kwargs):
        raise ValueError("disk full")
    monkeypatch.setattr(backend.store.plans, "set_tenant_plan", boom)
    assert _webhook(backend, _event("evt_1"))[0] == 400
    assert backend.store.billing._conn.execute("SELECT COUNT(*) FROM stripe_events").fetchone()[0] == 0
    monkeypatch.setattr(backend.store.plans, "set_tenant_plan", real)
    assert _webhook(backend, _event("evt_1"))[1]["plan_id"] == "pro"


def test_a_plan_change_that_cannot_be_made_durable_asks_stripe_to_redeliver(backend):
    _enroll(backend, "dev-1")
    _checkout(backend)
    backend.stripe.subscription(status="active")
    backend.store.billing._durable = lambda: False
    assert _webhook(backend, _event("evt_1"))[0] == 503
    # The redelivery is a local duplicate, but it is still not durable: Stripe must keep retrying.
    assert _webhook(backend, _event("evt_1"))[0] == 503
    backend.store.billing._durable = lambda: True
    assert _webhook(backend, _event("evt_1"))[1]["duplicate"] is True
    assert _plan(backend)["plan_id"] == "pro"


def test_checkout_needs_at_least_one_billable_device(backend):
    _enroll(backend, "demo", synthetic=True)
    status, body = _checkout(backend)
    assert status == 409 and "Enroll a device" in body["error"]
    assert backend.stripe.of("/checkout/sessions") == []


def test_an_oversized_or_empty_webhook_body_is_refused_before_verification(backend):
    # Correctly signed, so only the size check can refuse it.
    oversized = _signed({**_event("evt_big"), "padding": "x" * (1 << 20)})
    for body, headers in ((b"", {"Stripe-Signature": "t=1,v1=0"}), oversized):
        status, reply = _call(f"{backend.url}/api/shield/stripe/webhook", raw=body, token=None, headers=headers)
        assert status == 400 and reply["error"] == "invalid webhook body"
    assert backend.stripe.calls == []


# -- portal and seats --------------------------------------------------------------------------

def test_the_portal_needs_a_billing_account(backend):
    assert _call(f"{backend.url}/api/shield/billing/portal", body={"tenant_id": TENANT})[0] == 409
    _enroll(backend, "dev-1")
    _checkout(backend)
    status, body = _call(f"{backend.url}/api/shield/billing/portal", body={"tenant_id": TENANT})
    assert status == 200 and body["url"] == "https://billing.stripe.test/portal"
    (_, _, params, _), = backend.stripe.of("/billing_portal/sessions")
    assert params["customer"] == "cus_shield1"


def test_enrolling_a_device_prorates_the_seat_count_and_each_change_has_its_own_key(backend):
    _enroll(backend, "dev-1")
    _subscribe(backend, status="active")
    _enroll(backend, "dev-2")
    _enroll(backend, "demo", synthetic=True)  # enrolled before being marked: the next sync drops it
    backend.store.billing.sync_seats(TENANT)
    updates = backend.stripe.of("/subscription_items/si_device")
    assert [u[2]["quantity"] for u in updates] == [2, 3, 2]
    assert all(u[2]["proration_behavior"] == "create_prorations" for u in updates)
    keys = [u[3]["Idempotency-Key"] for u in updates]
    assert len(set(keys)) == 3  # 2 -> 3 -> 2 is three changes, never a replay of the first


def test_an_unchanged_seat_count_does_not_call_stripe(backend):
    _enroll(backend, "dev-1")
    _subscribe(backend, status="active")
    before = len(backend.stripe.calls)
    assert backend.store.billing.sync_seats(TENANT) == {"synced": True, "quantity": 1, "changed": False}
    assert len(backend.stripe.calls) == before


def test_a_failed_seat_sync_retries_with_the_same_key(backend):
    _enroll(backend, "dev-1")
    _subscribe(backend, status="active")
    backend.stripe.fail = True
    _enroll(backend, "dev-2")  # the sync fails: enrollment still succeeds
    backend.stripe.fail = False
    status, body = _call(f"{backend.url}/api/shield/billing/sync", body={"tenant_id": TENANT})
    assert status == 200 and body["quantity"] == 2
    rows = backend.store.billing._conn.execute("SELECT id, acknowledged_at FROM seat_syncs").fetchall()
    assert len(rows) == 1 and rows[0]["acknowledged_at"]
    assert backend.stripe.of("/subscription_items/si_device")[-1][3]["Idempotency-Key"] == \
        f"shield-seats:{TENANT}:{rows[0]['id']}"


def test_without_a_subscription_seat_sync_is_a_no_op(tmp_path, stripe):
    store = ShieldStore(tmp_path / "s.sqlite3")
    try:
        assert ShieldBilling(store._conn, store.plans).sync_seats(TENANT)["synced"] is False
        assert stripe.calls == []
    finally:
        store.close()
