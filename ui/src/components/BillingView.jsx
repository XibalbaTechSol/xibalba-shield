import { useCallback, useEffect, useState } from 'react'
import {
  CreditCard,
  Check,
  ShieldCheck,
  RefreshCw,
  ExternalLink,
  TriangleAlert,
  Info,
  Layers,
  HardDrive,
  Calendar,
  Lock,
  Clock,
  Activity,
} from 'lucide-react'
import {
  planCatalog,
  planAction,
  statusMeta,
  formatCents,
  formatCount,
  formatDate,
  formatDateTime,
  formatBasis,
  isStripeUrl,
  consumeBillingReturn,
} from '../billing'

export function BillingView({ api, connection, refresh: refreshParent, billingReturn, data: parentData }) {
  const [status, setStatus] = useState(() => parentData?.billing || null)
  const [usage, setUsage] = useState(() => parentData?.billingUsage || null)
  const [loading, setLoading] = useState(() => !parentData?.billing)
  const [usageLoading, setUsageLoading] = useState(() => !parentData?.billingUsage)
  const [actionLoading, setActionLoading] = useState('')
  const [actionError, setActionError] = useState('')
  const [actionNotice, setActionNotice] = useState('')
  const [retInfo] = useState(() => billingReturn || consumeBillingReturn())

  const loadStatus = useCallback(async () => {
    try {
      const res = await api.billingStatus()
      setStatus(res)
      setActionError('')
    } catch (err) {
      setActionError(err.message || 'Failed to fetch billing status from control plane.')
    } finally {
      setLoading(false)
    }
  }, [api])

  const loadUsage = useCallback(async () => {
    try {
      const res = await api.billingUsage()
      setUsage(res)
    } catch {
      // Usage endpoint may be unavailable on older mock fixtures
    } finally {
      setUsageLoading(false)
    }
  }, [api])

  useEffect(() => {
    if (parentData?.billing) {
      setStatus(parentData.billing)
      setLoading(false)
    }
  }, [parentData?.billing])

  useEffect(() => {
    if (parentData?.billingUsage) {
      setUsage(parentData.billingUsage)
      setUsageLoading(false)
    }
  }, [parentData?.billingUsage])

  useEffect(() => {
    if (!parentData?.billing) {
      loadStatus()
    }
    if (!parentData?.billingUsage) {
      loadUsage()
    }
  }, [loadStatus, loadUsage, parentData?.billing, parentData?.billingUsage])

  const plans = planCatalog(status)
  const currentPlanId = status?.plan?.plan_id || 'free'
  const currentStatus = status?.plan?.status || 'active'
  const currentMeta = statusMeta(currentStatus)
  const currentPlan = plans.find((p) => p.id === currentPlanId) || plans[0]

  const handleCheckout = async (planId) => {
    setActionLoading(`checkout-${planId}`)
    setActionError('')
    setActionNotice('')
    try {
      const result = await api.billingCheckout(planId)
      if (result?.url) {
        if (isStripeUrl(result.url)) {
          window.location.assign(result.url)
          return
        }
        setActionNotice(`Stripe Checkout Session created: ${result.url}`)
      } else {
        setActionNotice('Checkout session initialized successfully.')
        await Promise.all([loadStatus(), loadUsage()])
        if (refreshParent) refreshParent()
      }
    } catch (err) {
      setActionError(err.message || 'Stripe checkout could not be created.')
    } finally {
      setActionLoading('')
    }
  }

  const handlePortal = async () => {
    setActionLoading('portal')
    setActionError('')
    setActionNotice('')
    try {
      const result = await api.billingPortal()
      if (result?.url) {
        if (isStripeUrl(result.url)) {
          window.location.assign(result.url)
          return
        }
        setActionNotice(`Stripe Billing Portal created: ${result.url}`)
      } else {
        setActionNotice('Portal session opened.')
      }
    } catch (err) {
      setActionError(err.message || 'Stripe customer portal could not be reached.')
    } finally {
      setActionLoading('')
    }
  }

  const handleSyncSeats = async () => {
    setActionLoading('sync')
    setActionError('')
    setActionNotice('')
    try {
      const result = await api.billingSync()
      setActionNotice(`Seats synchronized: ${result.quantity ?? 'ok'} device(s) registered.`)
      await Promise.all([loadStatus(), loadUsage()])
      if (refreshParent) refreshParent()
    } catch (err) {
      setActionError(err.message || 'Seat synchronization failed.')
    } finally {
      setActionLoading('')
    }
  }

  return (
    <div className="billing-view" aria-label="Shield Billing and Subscriptions">
      <header className="workspace-header">
        <p className="eyebrow">SYSTEM / SUBSCRIPTIONS</p>
        <h2>Shield Subscription & Entitlements</h2>
        <p className="copy">
          Manage plan tiers, per-device seat licenses, and verifiable gate enforcement entitlements.
          Billing is never in the decision path: offline and unconfigured gates downgrade to shadow mode
          and never block.
        </p>
      </header>

      {/* Checkout Return Banners */}
      {retInfo?.checkout === 'success' && (
        <div className="billing-alert success" role="status">
          <Check aria-hidden="true" />
          <div>
            <strong>Checkout completed successfully.</strong>
            <p>Your workspace plan has been upgraded. Gate enforcement entitlements will activate automatically across enrolled devices.</p>
          </div>
        </div>
      )}

      {retInfo?.checkout === 'canceled' && (
        <div className="billing-alert info" role="status">
          <Info aria-hidden="true" />
          <div>
            <strong>Checkout canceled.</strong>
            <p>The Stripe checkout session was canceled. No changes were made to your tenant plan or billing account.</p>
          </div>
        </div>
      )}

      {actionNotice && (
        <div className="billing-alert info" role="status">
          <Info aria-hidden="true" />
          <div>
            <strong>Notice</strong>
            <p>{actionNotice}</p>
          </div>
          <button type="button" className="alert-dismiss-btn" onClick={() => setActionNotice('')}>Dismiss</button>
        </div>
      )}

      {actionError && (
        <div className="billing-alert error" role="alert">
          <TriangleAlert aria-hidden="true" />
          <div>
            <strong>Billing Error</strong>
            <p>{actionError}</p>
          </div>
          <button type="button" className="alert-dismiss-btn" onClick={() => setActionError('')}>Dismiss</button>
        </div>
      )}

      {status && !status.billing_configured && (
        <div className="billing-alert muted" role="status">
          <Lock aria-hidden="true" />
          <div>
            <strong>Stripe billing is not configured on this control plane.</strong>
            <p>The control plane is operating in local/evaluation mode. Gate decisions run in shadow mode unless a custom entitlement key is provisioned.</p>
          </div>
        </div>
      )}

      {/* Current Subscription Metric Overview */}
      <section className="billing-metrics-panel" aria-label="Current subscription overview">
        <div className="billing-metric-card">
          <div className="metric-header">
            <span className="metric-eyebrow">CURRENT TIER</span>
            <span className={`status-pill tone-${currentMeta.tone}`}>{currentMeta.label}</span>
          </div>
          <div className="metric-value">{currentPlan.name}</div>
          <div className="metric-meta">
            {currentPlan.id === 'free'
              ? 'Shadow-mode observation only'
              : `${formatCents(currentPlan.perDeviceMonthlyCents)} / device / mo`}
          </div>
        </div>

        <div className="billing-metric-card">
          <div className="metric-header">
            <span className="metric-eyebrow">ENROLLED SEATS</span>
            <HardDrive className="metric-icon" aria-hidden="true" />
          </div>
          <div className="metric-value">{formatCount(status?.seats || 0)}</div>
          <div className="metric-meta">
            {status?.billed_seats != null
              ? `${formatCount(status.billed_seats)} seats billed via Stripe`
              : 'Unmetered local seats'}
          </div>
        </div>

        <div className="billing-metric-card">
          <div className="metric-header">
            <span className="metric-eyebrow">DECISION ALLOWANCE</span>
            <Layers className="metric-icon" aria-hidden="true" />
          </div>
          <div className="metric-value">
            {formatCount(currentPlan.includedDecisions) || '5,000'}
          </div>
          <div className="metric-meta">per enrolled device / month</div>
        </div>

        <div className="billing-metric-card">
          <div className="metric-header">
            <span className="metric-eyebrow">PERIOD END / RENEWAL</span>
            <Calendar className="metric-icon" aria-hidden="true" />
          </div>
          <div className="metric-value date-val">
            {formatDate(status?.plan?.period_end) || 'Monthly UTC'}
          </div>
          <div className="metric-meta">
            {status?.plan?.trial_end
              ? `Trial ends ${formatDate(status.plan.trial_end)}`
              : (status?.plan?.period_start
                ? `${formatDate(status.plan.period_start)} → ${formatDate(status.plan.period_end)}`
                : (status?.plan?.period_end
                  ? `Renews ${formatDate(status.plan.period_end)}`
                  : (currentPlanId === 'free' ? 'Calendar month' : 'No expiration')))}
          </div>
        </div>
      </section>

      {/* Current Period Usage & Decision Allowance */}
      <section className="billing-usage-section" aria-label="Current period usage">
        <div className="section-title-wrap">
          <div className="usage-title-row">
            <div>
              <span className="eyebrow">METERING & LEDGER</span>
              <h3>Current Period Usage & Allowance</h3>
            </div>
            {usage?.as_of && (
              <div className="usage-as-of" aria-label="Usage timestamp">
                <Clock aria-hidden="true" />
                <span>As of {formatDateTime(usage.as_of)}</span>
              </div>
            )}
          </div>
        </div>

        {/* Case 1: Period is null -> show reason instead of numbers */}
        {usage && usage.period === null && (
          <div className="billing-alert info usage-null-period" role="status">
            <Info aria-hidden="true" />
            <div>
              <strong>Billing Period Not Active</strong>
              <p>{usage.reason || 'Billing period not yet known for this subscription.'}</p>
            </div>
          </div>
        )}

        {/* Case 2: Period is active -> show full breakdown */}
        {usage && usage.period && (
          <div className="usage-panel-body">
            {/* Period Details & Allowance Formula Card */}
            <div className="usage-period-card">
              <div className="period-card-left">
                <div className="period-dates">
                  <Calendar className="period-icon" aria-hidden="true" />
                  <span className="period-range">
                    {formatDate(usage.period.start)} &rarr; {formatDate(usage.period.end)}
                  </span>
                  <span className="status-pill tone-ok">{formatBasis(usage.period.basis)}</span>
                  {usage.in_trial && (
                    <span className="status-pill tone-warn">14-Day Free Trial</span>
                  )}
                </div>
                <div className="period-formula">
                  <span className="formula-part">
                    <strong>{usage.seats}</strong> {usage.seats === 1 ? 'seat' : 'seats'}
                  </span>
                  <span className="formula-op">&times;</span>
                  <span className="formula-part">
                    <strong>{formatCount(usage.included_per_device)}</strong> / dev
                  </span>
                  <span className="formula-op">=</span>
                  <span className="formula-part highlight">
                    <strong>{formatCount(usage.included)}</strong> included
                  </span>
                </div>
              </div>
              <div className="period-card-right">
                <div className="accrued-stat">
                  <span className="stat-label">Accrued so far</span>
                  <span className="stat-val">{formatCents(usage.overage_accrued_cents) || '$0.00'}</span>
                  <span className="stat-sub">
                    {usage.overage_cents_per_1k != null
                      ? `${formatCents(usage.overage_cents_per_1k)} / 1,000 decisions`
                      : 'Included in plan (Free)'}
                  </span>
                </div>
              </div>
            </div>

            {/* Usage Metrics Quad */}
            <div className="usage-metrics-grid">
              <div className="usage-metric-card">
                <div className="metric-eyebrow">BILLABLE DECISIONS</div>
                <div className="metric-value">{formatCount(usage.totals?.billable || 0)}</div>
                <div className="metric-meta">
                  Excludes {formatCount(usage.totals?.excluded_mask || 0)} zone masks, {formatCount(usage.totals?.excluded_fault || 0)} faults
                </div>
              </div>

              <div className="usage-metric-card">
                <div className="metric-eyebrow">REMAINING ALLOWANCE</div>
                <div className="metric-value highlight">{formatCount(usage.remaining || 0)}</div>
                <div className="metric-meta">
                  From {formatCount(usage.included || 0)} total included
                </div>
              </div>

              <div className="usage-metric-card">
                <div className="metric-eyebrow">OVERAGE DECISIONS</div>
                <div className={`metric-value ${(usage.overage_decisions || 0) > 0 ? 'overage-warn' : ''}`}>
                  {formatCount(usage.overage_decisions || 0)}
                </div>
                <div className="metric-meta">
                  {(usage.overage_decisions || 0) > 0
                    ? `${formatCents(usage.overage_accrued_cents)} accrued towards cycle invoice`
                    : 'Within included allowance'}
                </div>
              </div>

              <div className="usage-metric-card">
                <div className="metric-eyebrow">ACCRUED OVERAGE</div>
                <div className="metric-value">{formatCents(usage.overage_accrued_cents) || '$0.00'}</div>
                <div className="metric-meta">
                  {usage.in_trial ? 'Trial period ($0 overage)' : 'Accrued so far this period'}
                </div>
              </div>
            </div>

            {/* Allowance Progress Bar */}
            <div className="usage-progress-wrap" aria-label="Allowance consumption">
              <div className="progress-labels">
                <span>Allowance consumed</span>
                <span>
                  {usage.included > 0
                    ? `${Math.min(100, Math.round(((usage.totals?.billable || 0) / usage.included) * 100))}%`
                    : '0%'}
                </span>
              </div>
              <div className="progress-track">
                <div
                  className={`progress-fill ${(usage.overage_decisions || 0) > 0 ? 'fill-overage' : ''}`}
                  style={{
                    width: `${Math.min(100, usage.included > 0 ? Math.round(((usage.totals?.billable || 0) / usage.included) * 100) : 0)}%`,
                  }}
                />
              </div>
            </div>
          </div>
        )}

        {/* Missing Receipt Gaps Banner */}
        {usage?.gaps && usage.gaps.length > 0 && (
          <div className="billing-alert error usage-gaps-alert" role="alert">
            <TriangleAlert aria-hidden="true" />
            <div>
              <strong>Receipt Ledger Gaps Detected ({usage.gaps.length})</strong>
              <p>
                Missing receipt sequences were detected in the cryptographic audit log. These are treated as unbilled under-counts:
              </p>
              <ul className="gaps-list">
                {usage.gaps.map((gap, i) => (
                  <li key={i}>
                    {typeof gap === 'string' ? (
                      <code>{gap}</code>
                    ) : (
                      <>
                        Device <code>{gap.device_id}</code> &middot; Log <code>{gap.log_id}</code> &middot; Missing Seqs <strong>{gap.seq_from} &rarr; {gap.seq_to}</strong>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* Per-Device Table */}
        {usage?.devices && usage.devices.length > 0 && (
          <div className="usage-devices-section">
            <div className="table-header-row">
              <h4>Device Ledger Attribution</h4>
              <span className="devices-count">
                {usage.devices.length} reporting {usage.devices.length === 1 ? 'device' : 'devices'}
              </span>
            </div>
            <div className="usage-table-wrap">
              <table className="usage-table">
                <thead>
                  <tr>
                    <th>DEVICE ID</th>
                    <th>BILLABLE</th>
                    <th>ZONE DENIALS (MASK)</th>
                    <th>GATE FAULTS</th>
                    <th>REPORTS</th>
                    <th>AUDIT INTEGRITY</th>
                  </tr>
                </thead>
                <tbody>
                  {usage.devices.map((d) => {
                    const hasGap = usage.gaps?.some((g) => (typeof g === 'string' ? g.includes(d.device_id) : g.device_id === d.device_id))
                    return (
                      <tr key={d.device_id} className={hasGap ? 'row-has-gap' : ''}>
                        <td>
                          <div className="device-id-cell">
                            <HardDrive className="device-icon" aria-hidden="true" />
                            <code>{d.device_id}</code>
                            {hasGap && (
                              <span className="gap-flag" title="Telemetry receipt gaps detected">
                                <TriangleAlert aria-hidden="true" />
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="billable-col"><strong>{formatCount(d.billable)}</strong></td>
                        <td>{formatCount(d.excluded_mask)}</td>
                        <td>{formatCount(d.excluded_fault)}</td>
                        <td>{formatCount(d.reports)}</td>
                        <td>
                          {hasGap ? (
                            <span className="status-pill tone-bad">GAP FLAGGED</span>
                          ) : (
                            <span className="status-pill tone-ok">VERIFIED</span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      {/* Plan Comparison Grid */}
      <section className="billing-plans-section" aria-label="Available subscription plans">
        <div className="section-title-wrap">
          <span className="eyebrow">FLEET TIERS</span>
          <h3>Select Plan Tier</h3>
          <p>Each paid plan includes signed zone enforcement entitlements for enrolled devices and metered decision overage.</p>
        </div>

        <div className="billing-plans-grid">
          {plans.map((plan) => {
            const isCurrent = plan.id === currentPlanId
            const action = planAction(plan, status)
            const isLoading = actionLoading === `checkout-${plan.id}` || (action.kind === 'portal' && actionLoading === 'portal')

            return (
              <article
                key={plan.id}
                className={`billing-plan-card ${isCurrent ? 'active-plan' : ''}`}
                aria-label={`${plan.name} Plan`}
              >
                {isCurrent && (
                  <div className="plan-badge-top">CURRENT PLAN</div>
                )}

                <div className="plan-card-header">
                  <h4 className="plan-title">{plan.name}</h4>
                  <div className="plan-price">
                    {plan.id === 'free' ? (
                      <>
                        <span className="currency">$0</span>
                        <span className="period">forever</span>
                      </>
                    ) : (
                      <>
                        <span className="currency">{formatCents(plan.perDeviceMonthlyCents)}</span>
                        <span className="period">/ device / mo</span>
                      </>
                    )}
                  </div>
                  <p className="plan-summary">{plan.summary}</p>
                </div>

                <div className="plan-specs-table">
                  <div className="spec-row">
                    <span className="spec-label">Monthly allowance</span>
                    <span className="spec-val">{formatCount(plan.includedDecisions)} / dev</span>
                  </div>
                  <div className="spec-row">
                    <span className="spec-label">Overage rate</span>
                    <span className="spec-val">
                      {plan.overageCentsPer1k ? `${formatCents(plan.overageCentsPer1k)} / 1k` : 'None'}
                    </span>
                  </div>
                  <div className="spec-row">
                    <span className="spec-label">Device cap</span>
                    <span className="spec-val">{plan.maxDevices ? `${plan.maxDevices} max` : 'Unlimited'}</span>
                  </div>
                  <div className="spec-row">
                    <span className="spec-label">Zone enforcement</span>
                    <span className="spec-val highlight">
                      {plan.id === 'free' ? 'Shadow mode' : 'Signed entitlement'}
                    </span>
                  </div>
                </div>

                <ul className="plan-features-list" aria-label={`${plan.name} features`}>
                  {plan.features.map((feature, i) => (
                    <li key={i}>
                      <Check className="check-icon" aria-hidden="true" />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>

                <div className="plan-action-box">
                  <button
                    type="button"
                    className={`plan-btn ${isCurrent ? 'btn-secondary' : 'btn-primary'}`}
                    disabled={action.disabled || Boolean(actionLoading) || loading}
                    title={action.reason || action.label}
                    onClick={() => {
                      if (action.kind === 'checkout') handleCheckout(plan.id)
                      else if (action.kind === 'portal') handlePortal()
                    }}
                  >
                    {isLoading ? (
                      <>
                        <RefreshCw className="spinning" aria-hidden="true" />
                        <span>Connecting...</span>
                      </>
                    ) : (
                      action.label
                    )}
                  </button>
                  {action.reason && !action.disabled && (
                    <p className="action-hint">{action.reason}</p>
                  )}
                  {action.disabled && action.reason && (
                    <p className="action-hint disabled-hint">{action.reason}</p>
                  )}
                </div>
              </article>
            )
          })}
        </div>
      </section>

      {/* Seat Management & Customer Portal Actions */}
      <section className="billing-management-grid" aria-label="Subscription management">
        <div className="management-card">
          <div className="management-card-head">
            <CreditCard aria-hidden="true" />
            <div>
              <h4>Stripe Customer Portal</h4>
              <p>Update payment methods, view invoices, download receipts, and configure billing contacts.</p>
            </div>
          </div>
          <div className="management-card-action">
            <button
              type="button"
              className="btn-secondary"
              disabled={!status?.has_billing_account || actionLoading === 'portal'}
              onClick={handlePortal}
            >
              {actionLoading === 'portal' ? (
                <>
                  <RefreshCw className="spinning" aria-hidden="true" />
                  <span>Opening Portal...</span>
                </>
              ) : (
                <>
                  <span>Open Stripe Portal</span>
                  <ExternalLink aria-hidden="true" />
                </>
              )}
            </button>
            {!status?.has_billing_account && (
              <small className="hint-text">Available once an active checkout session is completed.</small>
            )}
          </div>
        </div>

        <div className="management-card">
          <div className="management-card-head">
            <RefreshCw aria-hidden="true" />
            <div>
              <h4>Device Seat Synchronization</h4>
              <p>Reconcile enrolled hardware endpoints with Stripe subscription quantity and apply prorations.</p>
            </div>
          </div>
          <div className="management-card-action">
            <button
              type="button"
              className="btn-secondary"
              disabled={actionLoading === 'sync'}
              onClick={handleSyncSeats}
            >
              {actionLoading === 'sync' ? (
                <>
                  <RefreshCw className="spinning" aria-hidden="true" />
                  <span>Syncing Seats...</span>
                </>
              ) : (
                <>
                  <span>Sync Seats Now</span>
                  <RefreshCw aria-hidden="true" />
                </>
              )}
            </button>
            <small className="hint-text">Currently {status?.seats || 0} enrolled device(s) on tenant {connection?.tenant}.</small>
          </div>
        </div>
      </section>

      {/* Assurance and Architecture Notes */}
      <section className="billing-invariants-box" aria-label="Billing invariants">
        <div className="invariants-header">
          <ShieldCheck aria-hidden="true" />
          <h4>Enterprise Zero-Trust Billing Guarantees</h4>
        </div>
        <div className="invariants-grid">
          <div className="invariant-item">
            <strong>1. Never in the Decision Path</strong>
            <p>
              Gating decisions on endpoints never wait for network calls or third-party APIs. Enforce authority is granted via locally cached Ed25519-signed entitlements.
            </p>
          </div>
          <div className="invariant-item">
            <strong>2. Offline Grace Periods & Downgrades</strong>
            <p>
              If a device loses connectivity or an entitlement lapses, Shield safely downgrades to shadow observation mode. Legitimate customer operations are never blocked.
            </p>
          </div>
          <div className="invariant-item">
            <strong>3. Cryptographic Receipt Ledger</strong>
            <p>
              Decision allowances and overage are verified using signed Merkle tree checkpoint receipts from the gate daemon, ensuring mathematical auditability.
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}
