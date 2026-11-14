"""Full sandbox end-to-end run of Shield billing (phases 3a-3d) on the merged main tree.

Usage: SHIELD_STRIPE_WEBHOOK_SECRET=<whsec from `stripe listen`> SHIELD_STRIPE_PORTAL_CONFIGURATION=<bpc_...> \
    uv run --frozen python scripts/e2e_billing_sandbox.py <scratch-dir>
<scratch-dir> must hold stripe-catalog.json and stripe-meter.json (the sandbox price and meter ids). The report and a
whsec-redacted run.log go to <scratch-dir>/e2e. Sandbox only: never point it at a live Stripe account.

Real paths: Shield's HTTP handler (enroll, checkout, billing status, usage upload, webhook, portal), the shipped
device-side gate receipt log + UsageUploader, Stripe's hosted Checkout (completed by hand/browser), Stripe webhooks
forwarded by `stripe listen`, test-clock period closes, and Stripe's own invoice math.

Seeded (labelled in the report): the billing_customers row (so the customer lives on a test clock -- checkout()
creates clock-less customers), tenant A's trial_used_at (so its first period is paid), and each device's signing
identity binding. Stripe calls are routed through the logged-in `stripe` CLI so no API key is handled here.

Tenant A (no trial): 1 device at checkout, 2nd enrolled mid-period, 9,500 billable + 300 excluded decisions.
  Expect at close: seats 2, included 2x1,000, value 7,500 -> overage line qty 7,500, amount 7 x 40c = 280c.
Tenant B (trial): 1 device, 3,000 billable during the trial. Expect trial close: value 0, no meter event.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

SCRATCH = Path(sys.argv[1])
OUT = SCRATCH / "e2e"
OUT.mkdir(exist_ok=True)
PORT = 8799
CAT = json.loads((SCRATCH / "stripe-catalog.json").read_text())
METER = json.loads((SCRATCH / "stripe-meter.json").read_text())["id"]
PORTAL = os.environ.get("SHIELD_STRIPE_PORTAL_CONFIGURATION", "")  # a sandbox bpc_ id
INCLUDED = 1_000  # local only (production: 25,000); prices stay at production values because checkout validates them
A, B = "e2e-tenant-a", "e2e-tenant-b"
EXCLUDED = "AIS_ZONE_RESTRICTED"
LOG = open(OUT / "run.log", "a", buffering=1)


def say(*parts):
    line = time.strftime("%H:%M:%S ") + " ".join(str(p) for p in parts)
    print(line, flush=True)
    LOG.write(line + "\n")


os.environ.update({
    "SHIELD_STRIPE_SECRET_KEY": "sk_test_routed_through_stripe_cli",
    "SHIELD_STRIPE_METER_ID": METER,
    "SHIELD_STRIPE_PRICE_PRO_DEVICE": CAT["pro"]["device"], "SHIELD_STRIPE_PRICE_PRO_OVERAGE": CAT["pro"]["overage"],
    "SHIELD_STRIPE_PRICE_TEAM_DEVICE": CAT["team"]["device"], "SHIELD_STRIPE_PRICE_TEAM_OVERAGE": CAT["team"]["overage"],
    "SHIELD_STRIPE_PORTAL_CONFIGURATION": PORTAL,
    "SHIELD_PLAN_PRO_PER_DEVICE_MONTHLY_CENTS": "1200", "SHIELD_PLAN_PRO_OVERAGE_CENTS_PER_1K": "40",
    "SHIELD_PLAN_PRO_INCLUDED_DECISIONS_PER_DEVICE": str(INCLUDED), "SHIELD_PLAN_PRO_MAX_DEVICES": "5",
    "SHIELD_PLAN_TEAM_PER_DEVICE_MONTHLY_CENTS": "2000", "SHIELD_PLAN_TEAM_OVERAGE_CENTS_PER_1K": "25",
    "SHIELD_PLAN_TEAM_INCLUDED_DECISIONS_PER_DEVICE": "100000",
})
assert os.environ.get("SHIELD_STRIPE_WEBHOOK_SECRET", "").startswith("whsec_"), "launch with the listen secret in env"

import integrity_sdk.billing.stripe_gateway as gw_mod  # noqa: E402
from integrity_sdk.did import Keypair, fingerprint_for_pubkey, public_key_multibase  # noqa: E402
from shield.backend.api import make_handler  # noqa: E402
from shield.backend.shield_billing import _iso  # noqa: E402
from shield.backend.store import ShieldStore  # noqa: E402
from shield.gate_receipts import GateReceiptWriter  # noqa: E402
from shield.gate_usage import UsageUploader, build_reports  # noqa: E402

STRIPE_CALLS = open(OUT / "shield-stripe-calls.log", "a", buffering=1)


def cli(method, path, data=None, idem=None, version=None):
    cmd = ["stripe", method.lower(), path]
    for k, v in (data or {}).items():
        cmd += ["-d", f"{k}={v}"]
    if idem:
        cmd += ["-i", idem]
    if version:
        cmd += ["-v", version]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    obj = json.loads(out[out.index("{"):])
    if "error" in obj:
        raise gw_mod.BillingUnavailable(f"{method} {path}: {obj['error'].get('message')}")
    return obj


def cli_send(method, url, *, data=None, headers=None, **_kw):
    headers = headers or {}
    path = url[len(gw_mod.STRIPE_API_ORIGIN):]
    STRIPE_CALLS.write(json.dumps({"t": time.strftime("%H:%M:%S"), "method": method, "path": path,
                                   "params": data or {}, "idem": headers.get("Idempotency-Key")}) + "\n")
    return cli(method, path, data, headers.get("Idempotency-Key"), headers.get("Stripe-Version"))


gw_mod._send = cli_send

ADMIN = secrets.token_urlsafe(24)
store = ShieldStore(OUT / "shield.sqlite3")
server = ThreadingHTTPServer(("127.0.0.1", PORT), make_handler(store=store, admin_token=ADMIN))
threading.Thread(target=server.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"


def http(method, path, body=None, token=ADMIN):
    req = urllib.request.Request(BASE + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait(what, fn, timeout=600, every=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(every)
    raise SystemExit(f"FAIL: timed out waiting for {what}")


def advance(clock, to):
    cli("POST", f"/v1/test_helpers/test_clocks/{clock}/advance", {"frozen_time": to})
    wait("test clock ready", lambda: cli("GET", f"/v1/test_helpers/test_clocks/{clock}")["status"] == "ready",
         timeout=900, every=5)
    say("clock ->", _iso(to))


def listen():
    proc = subprocess.Popen(
        ["stripe", "listen", "--forward-to", f"{BASE}/api/shield/stripe/webhook", "--events",
         "checkout.session.completed,customer.subscription.created,customer.subscription.updated,"
         "customer.subscription.deleted,invoice.created"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    with open(OUT / "listen.log", "a", buffering=1) as f:
        for line in proc.stdout:
            f.write(re.sub(r"whsec_[A-Za-z0-9]+", "whsec_[redacted]", line))


threading.Thread(target=listen, daemon=True).start()
time.sleep(6)

checks: list[tuple[str, bool, str]] = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok), str(detail)))
    say("PASS" if ok else "FAIL", name, detail)


def enroll(tenant, device):
    status, body = http("POST", "/api/shield/enroll", {"tenant_id": tenant, "device_id": device})
    assert status == 201, (status, body)
    signer = Keypair.generate()
    store.bind_integrity_agent(tenant_id=tenant, device_id=device,  # seeded: signing identity
                               agent_id=f"did:integrity:{fingerprint_for_pubkey(signer.public_bytes())}",
                               registration_status="registered")
    return body["device_token"], signer


def upload(tenant, device, token, signer, billable, excluded=0):
    gate_dir = OUT / f"gate-{tenant}-{device}"
    writer = GateReceiptWriter(gate_dir, signer=signer, hmac_key=os.urandom(32), log_id=f"shield-gate:{device}",
                               checkpoint_every=500)
    for i in range(billable + excluded):
        deny = i >= billable
        writer.record(agent_did="did:key:agent", device_id=device, tool_name="Bash", tool_input_sha256=None,
                      event_class="tool_call", pack_hash="0x" + "ab" * 32, decision="deny" if deny else "permit",
                      reason_code=EXCLUDED if deny else "INTEGRITY_RULE_MATCH", mode="enforce")
    reports = build_reports(gate_dir, {}, trusted_signers=[public_key_multibase(signer.public_bytes())])
    outcome = UsageUploader(BASE, tenant, device, token, auth_header=lambda: f"Bearer {token}").upload(gate_dir, reports)
    return len(reports), outcome


def row(tenant):
    r = store._conn.execute("SELECT * FROM meter_submissions WHERE tenant_id=?", (tenant,)).fetchone()
    return dict(r) if r else None


def main():
    t0 = int(time.time())
    clock = cli("POST", "/v1/test_helpers/test_clocks", {"frozen_time": t0, "name": "shield-e2e-full"})["id"]
    say("clock", clock, "at", _iso(t0))
    (OUT / "clock").write_text(clock)

    tok_a1, sig_a1 = enroll(A, "a-dev-1")
    tok_b1, sig_b1 = enroll(B, "b-dev-1")
    customers = {}
    for tenant in (A, B):
        cus = cli("POST", "/v1/customers", {"test_clock": clock, "metadata[tenant_id]": tenant,
                                            "metadata[product]": "shield"})["id"]
        customers[tenant] = cus
        with store._conn:  # seeded: a clock-bound customer; A's trial marked used so its first period is paid
            store._conn.execute("INSERT INTO billing_customers (tenant_id, customer_id, updated_at, trial_used_at) "
                                "VALUES (?,?,?,?)", (tenant, cus, _iso(t0), _iso(t0) if tenant == A else None))
    say("customers", customers)

    urls = {}
    for tenant in (A, B):
        status, body = http("GET", f"/api/shield/billing?tenant_id={tenant}")
        check(f"{tenant}: billing status before checkout is free and configured",
              status == 200 and body["plan"]["plan_id"] == "free" and body["billing_configured"],
              (body["plan"]["plan_id"], body["trial_available"]))
        status, body = http("POST", "/api/shield/billing/checkout", {"tenant_id": tenant, "plan_id": "pro"})
        check(f"{tenant}: checkout returns a hosted URL", status == 200 and "checkout.stripe.com" in body.get("url", ""),
              status)
        urls[tenant] = body["url"]
    (OUT / "checkout-urls.json").write_text(json.dumps(urls, indent=1))
    say("CHECKOUT_READY", OUT / "checkout-urls.json")

    def active(tenant):
        _, body = http("GET", f"/api/shield/billing?tenant_id={tenant}")
        return body["plan"] if body["plan"].get("plan_id") == "pro" else None
    st_a = wait("tenant A checkout", lambda: active(A), timeout=1800, every=5)
    st_b = wait("tenant B checkout", lambda: active(B), timeout=1800, every=5)
    check("A: webhook set plan pro/active (no trial)", st_a.get("status") == "active", st_a.get("status"))
    check("B: webhook set plan pro/trialing", st_b.get("status") == "trialing", st_b.get("status"))
    sub_a = cli("GET", "/v1/subscriptions", {"customer": customers[A]})["data"][0]
    sub_b = cli("GET", "/v1/subscriptions", {"customer": customers[B]})["data"][0]
    check("A: no trial on the subscription", sub_a.get("trial_end") is None, sub_a.get("trial_end"))
    check("B: 14-day trial", sub_b.get("trial_end") and sub_b["trial_end"] - sub_b["start_date"] == 14 * 86400,
          sub_b.get("trial_end"))
    item_a = next(i for i in sub_a["items"]["data"] if i["price"]["id"] == CAT["pro"]["device"])
    start_a, end_a = item_a["current_period_start"], item_a["current_period_end"]
    say("A period", _iso(start_a), "->", _iso(end_a), "B trial_end", _iso(sub_b["trial_end"]))

    # Seat sync: enrolling a second device prorates A's subscription off-thread.
    tok_a2, sig_a2 = enroll(A, "a-dev-2")

    def qty():
        s = cli("GET", f"/v1/subscriptions/{sub_a['id']}")
        q = next(i["quantity"] for i in s["items"]["data"] if i["price"]["id"] == CAT["pro"]["device"])
        return q if q == 2 else None
    check("A: 2nd device enrolment syncs seat quantity to 2", wait("seat sync", qty, timeout=300) == 2)

    # Usage through the shipped device code: signed gate receipt log -> reports -> uploader -> ledger.
    n, outcome = upload(A, "a-dev-1", tok_a1, sig_a1, 9_500, excluded=300)
    check("A: usage reports acknowledged", outcome.acknowledged == n and outcome.rejected is None,
          (n, outcome.acknowledged, outcome.rejected))
    n, outcome = upload(B, "b-dev-1", tok_b1, sig_b1, 3_000)
    check("B: usage reports acknowledged", outcome.acknowledged == n and outcome.rejected is None,
          (n, outcome.acknowledged, outcome.rejected))
    _, usage = http("GET", f"/api/shield/usage?tenant_id={A}")
    check("A: ledger totals 9,500 billable / 300 excluded", usage.get("totals", {}).get("billable") == 9_500
          and usage["totals"].get("excluded_mask") == 300, usage.get("totals"))

    # Trial close (B): the trial-end cycle invoice bills no overage despite 3,000 > 1,000 included.
    advance(clock, sub_b["trial_end"] + 60)
    rb = wait("B close acknowledged", lambda: (r := row(B)) and r["acknowledged_at"] and r, timeout=300)
    check("B: trial period closed with value 0", rb["value"] == 0 and rb["billable"] == 3_000,
          {k: rb[k] for k in ("period_start", "period_end", "seats", "billable", "included", "value")})
    st_b = active(B)
    check("B: plan active after trial", st_b and st_b.get("status") == "active", st_b and st_b.get("status"))

    # Paid close (A).
    advance(clock, end_a + 60)
    inv = wait("A cycle invoice", lambda: next((i for i in cli("GET", "/v1/invoices", {"customer": customers[A],
                                                                                       "limit": 10})["data"]
                                                if i["billing_reason"] == "subscription_cycle"), None), timeout=120)
    ra = wait("A close acknowledged", lambda: (r := row(A)) and r["acknowledged_at"] and r, timeout=300)
    check("A: period closed seats 2, included 2,000, value 7,500",
          (ra["seats"], ra["included"], ra["billable"], ra["value"]) == (2, 2 * INCLUDED, 9_500, 7_500),
          {k: ra[k] for k in ("period_start", "period_end", "seats", "billable", "included", "value", "invoice_id")})
    check("A: close bound to the cycle invoice", ra["invoice_id"] == inv["id"], (ra["invoice_id"], inv["id"]))
    advance(clock, end_a + 2 * 3600)
    inv = cli("GET", f"/v1/invoices/{inv['id']}")
    lines = cli("GET", f"/v1/invoices/{inv['id']}/lines", {"limit": 20})["data"]
    for line in lines:
        say("  A line", line["pricing"]["price_details"]["price"], "qty", line["quantity"], "amount", line["amount"],
            line.get("description"))
    ovg = [ln for ln in lines if ln["pricing"]["price_details"]["price"] == CAT["pro"]["overage"]]
    seat = [ln for ln in lines if ln["pricing"]["price_details"]["price"] == CAT["pro"]["device"]
            and ln["period"]["start"] >= end_a - 60]
    check("A: overage line 7,500 decisions -> 280c", ovg and ovg[0]["quantity"] == 7_500 and ovg[0]["amount"] == 280,
          ovg and (ovg[0]["quantity"], ovg[0]["amount"]))
    check("A: next-period seat line 2 x 1200c", seat and seat[0]["quantity"] == 2 and seat[0]["amount"] == 2400,
          seat and (seat[0]["quantity"], seat[0]["amount"]))
    check("A: invoice paid", inv["status"] == "paid", (inv["status"], inv["total"]))

    # B sent nothing to the meter.
    summ = cli("GET", f"/v1/billing/meters/{METER}/event_summaries",
               {"customer": customers[B], "start_time": sub_b["start_date"] - (sub_b["start_date"] % 60),
                "end_time": end_a + 3600 - ((end_a + 3600) % 60)})
    check("B: no meter events", sum(s["aggregated_value"] for s in summ["data"]) == 0,
          [s["aggregated_value"] for s in summ["data"]])

    # Portal: pinned configuration.
    status, body = http("POST", "/api/shield/billing/portal", {"tenant_id": A})
    calls = [json.loads(ln) for ln in (OUT / "shield-stripe-calls.log").read_text().splitlines()]
    portal_calls = [c for c in calls if c["path"].startswith("/v1/billing_portal/sessions")]
    check("A: portal session uses the pinned configuration",
          status == 200 and "billing.stripe.com" in body.get("url", "")
          and portal_calls and portal_calls[-1]["params"].get("configuration") == PORTAL, status)

    say("SUMMARY", sum(ok for _, ok, _ in checks), "/", len(checks), "passed")
    (OUT / "checks.json").write_text(json.dumps(checks, indent=1))
    if all(ok for _, ok, _ in checks):
        cli("DELETE", f"/v1/test_helpers/test_clocks/{clock}")
        say("clock deleted", clock)
    else:
        say("clock kept for inspection", clock)


try:
    main()
finally:
    server.shutdown()
    store.close()
