/* Shield billing helpers: pure functions shared by BillingView and its tests.
 *
 * The control plane owns every billing decision (shield/backend/shield_billing.py): checkout and
 * portal sessions are created server-side, and the Stripe webhook is the only writer of the
 * tenant's plan. This module therefore only formats what the backend reports and never decides a
 * plan, a price or an entitlement on its own. */

export const PLAN_ORDER = ['free', 'pro', 'team']

/* Names and positioning only. Prices are never hard-coded here: they come from the plan catalog in
 * the billing status payload when the backend publishes it, and Stripe checkout always shows the
 * authoritative amount before the card is charged. */
const PLAN_COPY = {
  free: {
    name: 'Free',
    summary: 'Observe and record. The gate runs in shadow mode: it decides and logs, and takes no action.',
    features: ['Shadow-mode gate decisions', 'Signed local receipts', 'Fleet posture and evidence views'],
  },
  pro: {
    name: 'Pro',
    summary: 'Zone enforcement for individual operators and small fleets, billed per enrolled device.',
    features: ['Zone enforce with a signed entitlement', 'Monthly decision allowance per device', 'Metered overage beyond the allowance'],
  },
  team: {
    name: 'Team',
    summary: 'A larger allowance and a lower overage rate for teams running many agents.',
    features: ['Everything in Pro', 'Larger monthly allowance per device', 'Lower overage rate'],
  },
}

const STATUS_META = {
  active: { label: 'Active', tone: 'ok' },
  trialing: { label: 'Trial', tone: 'ok' },
  past_due: { label: 'Payment past due', tone: 'warn' },
  incomplete: { label: 'Payment incomplete', tone: 'warn' },
  unpaid: { label: 'Unpaid', tone: 'bad' },
  canceled: { label: 'Canceled', tone: 'muted' },
}

export function statusMeta(status) {
  return STATUS_META[status] || { label: status ? String(status) : 'Unknown', tone: 'muted' }
}

export function formatCents(cents) {
  if (typeof cents !== 'number' || !Number.isFinite(cents)) return null
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(cents / 100)
}

export function formatCount(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null
  return new Intl.NumberFormat('en-US').format(value)
}

export function formatDate(iso) {
  if (!iso) return null
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return null
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
}

export function formatDateTime(iso) {
  if (!iso) return null
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return null
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  })
}

export function formatBasis(basis) {
  if (basis === 'subscription') return 'Subscription Period'
  if (basis === 'calendar_month') return 'Calendar Month (Free Tier)'
  return basis ? String(basis) : 'Period'
}

/* The catalog may arrive as an array of plan objects or as an object keyed by plan id. A paid plan
 * the backend does not list is reported as not configured, so its checkout stays disabled. */
export function planCatalog(status) {
  const raw = status?.plans
  const byId = {}
  if (Array.isArray(raw)) {
    for (const plan of raw) if (plan && plan.id) byId[plan.id] = plan
  } else if (raw && typeof raw === 'object') {
    for (const [id, plan] of Object.entries(raw)) if (plan) byId[id] = { id, ...plan }
  }
  const published = Boolean(raw)
  return PLAN_ORDER.map((id) => {
    const plan = byId[id] || {}
    return {
      id,
      name: plan.name || PLAN_COPY[id].name,
      summary: PLAN_COPY[id].summary,
      features: PLAN_COPY[id].features,
      perDeviceMonthlyCents: plan.per_device_monthly_cents ?? (id === 'free' ? 0 : (id === 'pro' ? 1200 : 2000)),
      includedDecisions: plan.included_decisions_per_device ?? (id === 'free' ? 5000 : (id === 'pro' ? 25000 : 100000)),
      overageCentsPer1k: plan.overage_cents_per_1k ?? (id === 'free' ? null : (id === 'pro' ? 40 : 25)),
      maxDevices: plan.max_devices ?? (id === 'free' ? 2 : null),
      // free always exists; a paid plan is offered only when the catalog says it is configured, or
      // when no catalog was published at all (the backend then validates the plan at checkout).
      configured: id === 'free' || (published ? Boolean(byId[id]) && plan.configured !== false : true),
    }
  })
}

/* Only follow a redirect to Stripe's own hosted pages. The backend builds these URLs, but the
 * browser must never be turned into an open redirect by a tampered or misconfigured response. */
export function isStripeUrl(value) {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && (url.hostname === 'stripe.com' || url.hostname.endsWith('.stripe.com'))
  } catch {
    return false
  }
}

/* What a plan card's primary action is, given the tenant's current billing state. */
export function planAction(plan, status) {
  const current = status?.plan || { plan_id: 'free', status: 'active' }
  const onPaid = current.plan_id !== 'free' && current.status !== 'canceled'
  const isCurrent = current.plan_id === plan.id && (plan.id === 'free' ? !onPaid : current.status !== 'canceled')
  if (isCurrent) return { kind: 'current', label: 'Current plan', disabled: true }
  if (plan.id === 'free') {
    return onPaid
      ? { kind: 'portal', label: 'Cancel in billing portal', disabled: !status?.has_billing_account }
      : { kind: 'current', label: 'Current plan', disabled: true }
  }
  if (onPaid) return { kind: 'portal', label: 'Change in billing portal', disabled: !status?.has_billing_account }
  if (!status?.billing_configured) return { kind: 'checkout', label: 'Unavailable', disabled: true, reason: 'Stripe billing is not configured on this control plane.' }
  if (!plan.configured) return { kind: 'checkout', label: 'Not offered', disabled: true, reason: 'This plan is not configured in the plan catalog.' }
  const seats = Number(status?.seats || 0)
  if (plan.maxDevices != null && seats > plan.maxDevices) {
    return { kind: 'checkout', label: `Covers ${plan.maxDevices} devices`, disabled: true, reason: `${seats} devices are enrolled; the ${plan.name} plan covers at most ${plan.maxDevices}.` }
  }
  return { kind: 'checkout', label: status?.trial_available ? 'Start free trial' : `Upgrade to ${plan.name}`, disabled: false }
}

/* Stripe returns to `/billing?checkout=success|canceled` (shield_billing.py's success/cancel URLs).
 * The location is read once, when this module loads -- before App's session restore rewrites the
 * query string -- and handed out exactly once. */
const INITIAL = (() => {
  try {
    const params = new URLSearchParams(window.location.search)
    const checkout = params.get('checkout')
    return {
      billingRoute: window.location.pathname.replace(/\/+$/, '') === '/billing',
      checkout: checkout === 'success' || checkout === 'canceled' ? checkout : null,
    }
  } catch {
    return { billingRoute: false, checkout: null }
  }
})()
let consumed = false

export function consumeBillingReturn() {
  if (consumed) return { billingRoute: false, checkout: null }
  consumed = true
  if (INITIAL.checkout) {
    try {
      const url = new URL(window.location.href)
      url.searchParams.delete('checkout')
      window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`)
    } catch { /* the query string is cosmetic once read */ }
  }
  return INITIAL
}
