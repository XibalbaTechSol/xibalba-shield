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
} from 'lucide-react'
import {
  planCatalog,
  planAction,
  statusMeta,
  formatCents,
  formatCount,
  formatDate,
  isStripeUrl,
  consumeBillingReturn,
} from '../billing'

export function BillingView({ api, connection, refresh: refreshParent, billingReturn, data: parentData }) {
  const [status, setStatus] = useState(() => parentData?.billing || null)
  const [loading, setLoading] = useState(() => !parentData?.billing)
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

  useEffect(() => {
    if (parentData?.billing) {
      setStatus(parentData.billing)
      setLoading(false)
    }
  }, [parentData?.billing])

  useEffect(() => {
    if (!parentData?.billing) {
      loadStatus()
    }
  }, [loadStatus, parentData?.billing])

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
        await loadStatus()
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
      await loadStatus()
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
          <ShieldCheck aria-hidden="true" />
          <div>
            <strong>Checkout completed successfully.</strong>
            <p>Your subscription is active. Enrolled devices will receive cryptographically signed zone enforcement entitlements upon their next refresh.</p>
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
            {formatDate(status?.plan?.period_end) || 'Continuous'}
          </div>
          <div className="metric-meta">
            {status?.trial_available ? '14-day trial eligible' : 'Standard billing cycle'}
          </div>
        </div>
      </section>

      {/* Plan Catalog Cards */}
      <section className="billing-plans-section" aria-label="Subscription plans">
        <div className="section-title-wrap">
          <p className="eyebrow">TIERS & PRICING</p>
          <h3>Select a plan for your agent fleet</h3>
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
