# Shield plans and metering — design

- **Date:** 2026-11-12
- **Status:** accepted by the operator 2026-11-13 (prices and allowances in §9 still to be set). Phase 1 = integrity-core #212
- **Scope:** xibalba-shield (backend + gate), integrity-sdk (shared billing core). Cortex `managed/` is **not** changed by this design.
- **Review provenance:** advisor review plus self-review. The Devil's Advocate engine is not entitled on this account (`ENGINE_NOT_IN_PLAN`), so no DA run was possible.

## 0. Decisions already taken (operator, 2026-11-12)

| # | Decision | Source |
|---|----------|--------|
| D1 | Pricing unit: **flat fee per device, with an included number of gated decisions per device, plus overage** | operator answer |
| D2 | Shield **reuses Cortex's plan catalog pattern and Stripe gateway**: one billing system, not a second one | operator answer |
| D3 | `ais` zone **enforce** is a paid feature. The free tier gets **shadow** mode: it shows what would have been blocked, without blocking | operator answer |

Prices, included-decision counts, device caps and grace periods are **parameters** (§9). They are left for the operator to set and are not decided here.

## 1. Hard rule: billing is never in the decision path

The L0 gate answers tool calls offline from a signed pack. Nothing in this design may add a network call, a quota check or a billing state to that path. Concretely:

- A quota running out **never** denies, delays or downgrades a tool-call decision. Running out of quota only produces overage, or a warning on the free tier (§4).
- A missing, expired or unverifiable entitlement degrades `ais` zone **enforce** to **shadow** (§6). It never blocks everything, and it never turns the gate off.
- A usage report that fails to upload is retried later. The gate keeps writing receipts, and the receipts are the source of truth.

Each rule gets a test that fails if it is broken (§8).

## 2. What is billed: gated decisions, not sensor events

Shield produces two decision streams. Only one of them is billed.

| Stream | Where it goes today | Billed? |
|--------|--------------------|---------|
| **Sensor / policy decisions** (`/api/shield/decisions`) | Backend. High-volume `allow`/`log_only` + `_no_match` rows are rolled up into per-minute counts (`decision_observation_rollups`) | **No.** This could be every TCP connect; a customer cannot predict or control it |
| **Gate receipts:** one signed, hash-chained receipt per agent tool call (`shield.gate_receipts` → `integrity_sdk.core.receipt_writer`) | **Device only.** Nothing uploads them today | **Yes.** This is the unit the customer buys: one governed tool call |

**A billable gated decision** is a gate receipt whose `reason_code` is **not** in `integrity_sdk.core.ais_local.EXCLUDED_REASON_CODES`. That set contains:

- `AIS_ZONE_RESTRICTED`: the zone mask's own denial. Billing for these would charge the customer for the paid feature's own blocks.
- `INTEGRITY_EVALUATOR_ERROR`, `INTEGRITY_MALFORMED_DECISION`, `INTEGRITY_NO_PACK`: gate faults. Billing for these would charge the customer for our failures.

`permit`, `deny` and `log_only` all count, and so does `INTEGRITY_NO_MATCH`, because a real tool call was governed. The billing classification and the AIS scorer reuse the same exclusion set, so both read a receipt the same way. A test pins them together (§8).

## 3. The usage report: device → backend

### 3.1 Shape

The device sends `POST /api/shield/usage`, authenticated with the existing device token (the same `_require_device_token` path as `/api/shield/decisions`):

```json
{
  "schema": "xibalba.shield.usage-report.v1",
  "tenant_id": "...", "device_id": "...",
  "log_id": "shield-gate:…",
  "seq_from": 400, "seq_to": 499,
  "counts": {"billable": 97, "excluded_mask": 2, "excluded_fault": 1},
  "checkpoint": { /* the signed checkpoint line whose tree_size == seq_to + 1 */ }
}
```

### 3.2 Why ranges end on checkpoints

The SDK writer emits a signed checkpoint every `DEFAULT_CHECKPOINT_EVERY = 100` receipts, plus one on a clean close. Each checkpoint commits to the Merkle root over the first `tree_size` receipts. A report covers exactly `[previous tree_size, this tree_size)`, so **every reported range is covered by a signature the device already produced**. The report invents no new signed object. The backend checks three things:

1. The checkpoint signature verifies under the device's enrolled signing key (`verify_checkpoint`).
2. `checkpoint.log_id == log_id` and `checkpoint.tree_size == seq_to + 1`.
3. `billable + excluded_mask + excluded_fault == seq_to - seq_from + 1`.

Receipts in a range that has no checkpoint yet are reported once the next checkpoint (or the clean-close checkpoint) exists. This adds at most 100 receipts of latency, which is fine because billing works in arrears.

### 3.3 Ledger and idempotency

The new backend table `usage_reports` has primary key `(tenant_id, log_id, seq_from)`. It stores `device_id`, `seq_to`, the three counts, the checkpoint root and `received_at`.

- **Replays are no-ops.** The same `(log_id, seq_from)` with an identical body returns 200. A different body returns 409.
- **Overlaps are refused.** The backend rejects any range that intersects one already stored for that `log_id`.
- **Gaps are accepted and flagged.** A missing range is an under-count, which costs us and not the customer. It appears on the tenant's usage page and in an operator metric.
- **A reinstall is a new chain.** A new `log_id` starts at `seq 0`, and its ranges add to the device's total. Keying on `(log_id, seq range)` means a reinstall neither resets the count nor double-counts.

### 3.4 Trust model (stated plainly)

The per-class split is **self-reported by the device**. The checkpoint proves *how many* receipts exist (`tree_size`) and fixes their content (the Merkle root), but it does not prove the split. Here is why that is acceptable:

- The total cannot be inflated or deflated without a new checkpoint signed by the device's own key.
- Shifting receipts from `billable` into `excluded_*` is the only way to cheat. Any range is auditable: the backend can ask for the receipts behind a stored root and recount them, which Phase 4 implements as a spot check. Receipts carry `action_hmac`, never tool inputs, so an audit reveals no customer payloads.
- The device software runs on the customer's machine. No local check can be tamper-proof against its owner. What this protects is a commercial licence, not security, and the audit trail is what enforces it.

## 4. Plans: what "reuse Cortex" means concretely

### 4.1 What carries over, and what does not

Cortex has `managed/plans.py` (`Plan`, `PLANS`, `WRITE_STATUSES`), `managed/stripe_gateway.py` (`StripeGateway`, `BillingUnavailable`, signature-verified webhooks, a fail-closed `billing_ready`), and in `managed/control.py` a `usage(tenant, month, meter, amount)` table with an atomic `UPDATE … WHERE amount < limit` reservation, a `stripe_events` idempotency table and `validate_price`.

| Cortex piece | Reusable for Shield as-is? | Why |
|---|---|---|
| `StripeGateway` (fixed origin, bounded timeouts, no raw Stripe errors forwarded, `verify_event` with tolerance and livemode check) | **Yes**, unchanged | Product-neutral |
| `stripe_events` webhook idempotency | **Yes**, same pattern | Product-neutral |
| `Plan` dataclass | **No** | Its fields are memory limits only |
| `consume()` | **No** | It accepts only `writes`/`retrievals` and raises `LimitExceeded` at the cap. A hard quota contradicts D1 (overage) and §1 (never block) |
| `validate_price` | **No** | It assumes one flat monthly `unit_amount`. Shield needs a per-device licensed price and a meter-backed price |

### 4.2 Chosen structure

**Shared billing core in integrity-sdk.** `StripeGateway`, webhook verification and the `stripe_events` idempotency helper move into a product-neutral module, `integrity_sdk.billing`. Shield imports it.

Cortex keeps its own copy until a separate Cortex PR switches it over. That PR deploys the managed pilot, so it gets its own review and is not part of this work. "One billing system" therefore means one gateway implementation, one Stripe account and one catalog convention.

**Customer record: one Stripe account, separate customers per product for now.** Cortex tenants (`t-<hex>`, Supabase-auth accounts) and Shield tenants (Shield's own `accounts`/`tenants` store) are **different identity stores**. Sharing one Stripe customer between them before those identities are unified would let a login on one product act on billing for the other.

So in Phase 1 each Shield tenant gets its own Stripe customer, with metadata `product=shield`, `tenant_id=…`, in the same Stripe account. A later identity-unification step merges the two customers into one organisation-level customer, and a linked-accounts flow is its prerequisite. This is a deliberate deferral, and the reason is the one above.

**Alternative rejected: the Shield backend calls Cortex's managed API for entitlement and usage.** It would make Shield's control plane depend on Cortex's uptime and deploy cadence. Every Shield billing change would also become a Cortex pilot deploy.

### 4.3 Shield plan shape

```python
@dataclass(frozen=True)
class ShieldPlan:
    id: str                               # "free" | "pro" | "team"
    name: str
    per_device_monthly_cents: int         # 0 on free
    included_decisions_per_device: int    # per billing period
    overage_cents_per_1k: int | None      # None on free: no overage billing
    max_devices: int | None               # cap on enrolled, non-synthetic devices
    zone_enforce: bool                    # D3: False on free
```

**Free tier when it goes over its included decisions.** Decisions keep flowing (§1). The tenant's usage page shows how far over it is, and the backend emails the owner once per period. If the tenant is over for more than `free_over_periods` (§9) consecutive periods, **new device enrollments** are refused, while existing devices keep working. This pressure is aimed only at enrollment, never at decisions.

**Synthetic/demo devices** (`devices.synthetic = 1`) are never counted, either as seats or as usage.

## 5. Stripe mapping (API version `2025-06-30.basil`)

Basil **removed legacy usage-based billing**: a `usage_type=metered` price must be backed by a **Billing Meter**, and `UsageRecord` is gone (confirmed from the Stripe changelog, `stripe docs`, 2026-11-12). The design therefore uses meters.

Each paid plan has two prices on one subscription:

| Item | Price type | Quantity / value |
|---|---|---|
| Devices | licensed, `per_unit`, monthly, `unit_amount = per_device_monthly_cents` | quantity = count of enrolled non-synthetic devices. Synced on enroll and unenroll with `proration_behavior=create_prorations` |
| Overage | metered, backed by meter `shield_gated_decisions_overage` (aggregation `sum`), priced per 1,000 | **only the units beyond the included amount**, computed by us |

**Why we compute overage ourselves instead of using graduated "first N free" tiers.** The included amount is *per device*, so it changes with the seat quantity during a period. A graduated tier's `up_to` is fixed on the price. So the backend computes `included = included_decisions_per_device × max(device quantity during period)` and sends only `max(0, billable − included)` to the meter.

Using the **maximum** device count in the period is the customer-favourable choice: removing a device mid-month does not shrink that month's allowance.

**Meter events.**

- The backend sends meter events **daily** while overage accrues, plus a final one at period close before the invoice finalizes. The final event lands inside the draft-invoice window, which is to be confirmed with a Stripe test clock in Phase 3.
- Each event carries the delta since the last submission.
- Stripe enforces `identifier` uniqueness for only about 24 hours, so **our own ledger is the dedupe authority**. Table `meter_submissions(tenant_id, period, n, value, identifier, sent_at, stripe_ack)`, with identifier `shield-ovg:{tenant}:{period}:{n}`. A row is written *before* the call and acknowledged after it, the same persist-before-call pattern as Cortex's `checkout_requests`.

**Late reports.** A device that was offline reports old ranges when it reconnects. Stripe accepts meter-event timestamps only within the past 35 days, and a closed period's invoice is already final. Usage is therefore attributed to the period in which the backend **received** it, never back-dated. This is stated on the pricing page.

**Price validation** (the Shield counterpart of `validate_price`): before the first checkout, check the device price (`recurring.usage_type=licensed`, `per_unit`, USD, monthly, amount matches the catalog) and the overage price (`usage_type=metered`, `recurring.meter` is the configured meter id, amount matches). If either check fails, billing stays unavailable (fail closed), exactly as `billing_ready` does in Cortex.

## 6. Entitlement on the device: paid enforce, free shadow, offline-safe

The gate cannot ask the backend at decision time (§1), so the entitlement travels **to** the device as a signed, expiring document. It is fetched together with tenant settings and policy:

```json
{
  "schema": "xibalba.shield.entitlement.v1",
  "tenant_id": "...", "device_id": "...",
  "plan": "pro", "zone_enforce": true,
  "issued_at": "...", "not_after": "<period_end + grace>",
  "signer_key": "...", "signature": "..."
}
```

- It is signed with the backend's Ed25519 entitlement key. The device pins that public key at enrollment, the same trust step as the policy signing keys in `shield/config/signing.py`.
- **Resolution at gate start-up and on every refresh:** the operator asks for `--zone-mode enforce`, and the gate enforces only if a valid entitlement for this tenant and device, with `zone_enforce = true`, is unexpired. Otherwise it runs in **shadow** and logs why.
- Every receipt records the effective mode and the reason in its controls. `ais_zone_mode:` (shadow/enforce) is the mode actually applied, and the new `ais_zone_entitlement:` is one of `ok`, `missing`, `expired`, `bad_signature`, `plan`. Audits can then tell apart "the customer chose shadow" from "the gate downgraded to shadow".
- **Offline:** an entitlement stays valid until `not_after` (period end + `entitlement_grace_days`, §9). A device offline longer than that drops to shadow and never to blocking.
- `--zone-mode off` and `shadow` need no entitlement. Unenrolled local runs have no entitlement and therefore get shadow at most. The open-source gate stays fully usable for observation.

## 7. Changes by repository, in PR order

| Phase | Repo | Change | Deploys? |
|---|---|---|---|
| 1 | integrity-core | `integrity_sdk.billing`: the gateway, webhook verify and event idempotency, lifted from Cortex with tests. A `classify_for_billing(receipt)` that reuses `EXCLUDED_REASON_CODES` | No (library) |
| 2 | xibalba-shield | Gate side: a usage-report builder that reads receipts and checkpoints, stores the last reported `tree_size` in a local cursor file and uploads with backoff. Entitlement verification plus the enforce→shadow downgrade, with the receipt control. CI pin bumped to phase 1 | Shield auto-deploys on merge, but the backend ignores the new route until phase 3 |
| 3 | xibalba-shield | Backend side: `/api/shield/usage` with the `usage_reports` ledger, `ShieldPlan` catalog, entitlement issuing, Stripe checkout/portal/webhook through `integrity_sdk.billing`, `meter_submissions`, daily meter job, usage page | Yes. Billing stays **off** until real Stripe keys, prices and the meter are configured (fail closed, as in Cortex) |
| 4 | xibalba-shield | Audit spot-check: re-derive the class counts for a sampled range from uploaded receipts | Yes |
| later | xibalba-cortex | Switch Cortex to `integrity_sdk.billing`. A separate PR, because merging it deploys the managed pilot | Yes (pilot) |

Creating Stripe products, prices and the meter is an **operator action** after Phase 3, done in test mode first.

## 8. Tests that must exist, each shown to fail when its rule is removed

1. **Never in the decision path:** with the backend unreachable, the entitlement expired and the quota exceeded, a tool call still gets its normal pack decision and receipt. Removing the downgrade-to-shadow, or adding a quota check, makes this test fail.
2. **Downgrade, not block:** `--zone-mode enforce` without an entitlement, with an expired entitlement, or with a bad signature → `ais_zone_mode:shadow` plus the matching `ais_zone_entitlement:` reason. A red-zone agent is **not** blocked.
3. **Billing exclusions match AIS exclusions:** a test pins `classify_for_billing` and `classify_receipt` to the same exclusion set.
4. **Ledger idempotency:** a replayed report is a no-op, a changed body returns 409, an overlapping range is refused, a reinstall (new `log_id`) adds to the total, and a gap is flagged and not invented.
5. **Count arithmetic:** a report whose counts do not sum to the range, or whose checkpoint `tree_size` ≠ `seq_to + 1`, or whose checkpoint does not verify under the enrolled key → 400.
6. **Overage maths:** the included amount uses the maximum device quantity in the period. Removing a device mid-period does not shrink the allowance. Units at or below the allowance produce no meter event.
7. **Meter dedupe:** a crash after the row is written but before the Stripe call → the retry reuses the same identifier and value. Two runs on the same day never double-send.
8. **Price validation:** a wrong amount, currency or interval, a licensed price where metered is expected, or a wrong meter id → billing unavailable.

## 9. Parameters for the operator to set

| Parameter | Meaning | Suggestion (not a decision) |
|---|---|---|
| `free.max_devices` | Devices allowed on free | 2 |
| `free.included_decisions_per_device` | Monthly allowance on free | 5,000 |
| `free_over_periods` | Periods over allowance before new enrollments are refused | 2 |
| `pro.per_device_monthly_cents` | Pro seat price | 1200 ($12; $10 if annual) |
| `pro.included_decisions_per_device` | Pro allowance | 25,000 |
| `pro.overage_cents_per_1k` | Pro overage | 40 |
| `team.per_device_monthly_cents` | Team seat price | 2000 |
| `team.included_decisions_per_device` | Team allowance | 100,000 |
| `team.overage_cents_per_1k` | Team overage | 25 |
| `team.max_devices` | Team cap | operator's call |
| `entitlement_grace_days` | Offline validity after period end | 7 |
| `SHIELD_STRIPE_TRIAL_DAYS` | Trial on a tenant's first paid checkout, card collected up front, once per tenant | 14 (**decided**, operator 2026-11-13) |

Price suggestions (research 2026-11-13): below a full EDR seat (CrowdStrike Falcon Pro ≈ $8–15,
SentinelOne Complete ≈ $15 per endpoint per month) and inside the AI-guardrail/agent-security band
(≈ $15–25 per seat). A heavy coding agent was estimated at 4.4k–22k gated decisions a month, so the Pro
allowance covers one without overage. Advertising was considered and rejected: an ad SDK would sit
inside the gate's trust boundary and conflicts with the provenance/privacy positioning.

Real numbers should come from shadow data: switch one real gate to `--zone-mode shadow --zone-provider ais` and measure gated decisions per device per month before setting allowances.

## 10. Risks and limits

- **Self-reported split** (§3.4). Mitigated by checkpoint-bound totals and audit; not eliminated.
- **Free-tier farming by re-enrolling devices.** Seats and allowance are per tenant, so new devices count against `free.max_devices`. Creating new tenants is the residual risk, and it is bounded by email verification on signup.
- **Clock skew** affects only which period a report lands in. Received-time attribution (§5) makes the backend's clock the authority.
- **Agent ids are caller-supplied at L0.** This affects AIS zone evasion (a new id means a cold start), not billing, because billing counts receipts per device and log.
- **Stripe API drift:** the design relies on Basil meter semantics, checked against Stripe's docs on 2026-11-12. Phase 3 should confirm the period-close and invoice-finalization timing on a test clock before going live.
