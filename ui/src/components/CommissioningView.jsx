import { useEffect, useState } from 'react'
import { Gauge, ShieldCheck } from 'lucide-react'
import { NOT_MEASURED, formatCount, formatMs, formatRate } from '../commissioningFormat'

/* Commissioning ladder
 *
 * A control engineer does not switch a plant to automatic on day one, and an operator should
 * not hand a fleet to enforcement on day one either. This view shows, per rung, the evidence
 * the control plane actually holds. https://en.wikipedia.org/wiki/Control_theory
 *
 * Honesty rules (the repo's "no silent mocks" rule, applied to a UI):
 *   - Every figure is read from GET /api/shield/commissioning-metrics. Nothing is computed from
 *     a constant, and nothing is invented to fill a gap.
 *   - A missing value (null/undefined) renders as "Not measured", NEVER as 0 or 0 ms. A zero
 *     would read as "fast" or "perfect"; absence of data is neither.
 *   - What the backend says it cannot yet measure (`not_instrumented`) is shown verbatim.
 *   - Rung status labels name what is VERIFIED, not what is hoped for. A setting that exists
 *     is not the same as device behaviour that has been verified.
 */

function Stat({ label, value, detail }) {
  const measured = value !== NOT_MEASURED
  return (
    <div className={`commissioning-stat${measured ? '' : ' unmeasured'}`}>
      <small>{label}</small>
      <b>{value}</b>
      {detail && <span>{detail}</span>}
    </div>
  )
}

function Rung({ number, title, state, stateTone, children }) {
  return (
    <article className="commissioning-rung" aria-label={`Rung ${number}: ${title}`}>
      <header>
        <span className="commissioning-rung-number" aria-hidden="true">{number}</span>
        <h3>{title}</h3>
      </header>
      <span className={`commissioning-state ${stateTone}`}>{state}</span>
      {children}
    </article>
  )
}

export function CommissioningView({ data, api }) {
  const devices = (data?.devices || []).map((d) => d.device_id).filter(Boolean)
  const [deviceId, setDeviceId] = useState('')
  // One state object keyed by the scope it answers. `loading` is DERIVED (the stored answer is
  // for a different scope than the one selected), so the effect never calls setState
  // synchronously and a slow response for a previous scope can never be shown for this one.
  const [answer, setAnswer] = useState({ scope: null, metrics: null, error: '' })
  const [containmentMode, setContainmentMode] = useState('')

  useEffect(() => {
    let cancelled = false
    api.commissioningMetrics(deviceId)
      .then((result) => { if (!cancelled) setAnswer({ scope: deviceId, metrics: result, error: '' }) })
      .catch((e) => { if (!cancelled) setAnswer({ scope: deviceId, metrics: null, error: e instanceof Error ? e.message : String(e) }) })
    return () => { cancelled = true }
  }, [api, deviceId])

  useEffect(() => {
    let cancelled = false
    api.settings()
      .then(({ settings = {} }) => { if (!cancelled) setContainmentMode(settings.containmentMode || '') })
      .catch(() => {})
    return () => { cancelled = true }
  }, [api])

  const loading = answer.scope !== deviceId
  const metrics = loading ? null : answer.metrics
  const error = loading ? '' : answer.error

  const containment = metrics?.containment
  const latency = metrics?.handle_to_contain_ms
  const falseFreeze = metrics?.false_freeze
  const observe = metrics?.observe
  const wouldTotal = observe?.would_actions_total
  const completed = containment?.completed

  return (
    <div className="commissioning-view">
      <section className="resource">
        <header>
          <p className="eyebrow">GOVERNANCE / COMMISSIONING</p>
          <h2>Commissioning ladder</h2>
          <span>Four rungs from observation to autonomous control. Each shows only the evidence this control plane holds.</span>
          <small className="evidence-label">A missing measurement reads “Not measured”, never zero.</small>
        </header>
      </section>

      <div className="commissioning-toolbar">
        <label htmlFor="commissioning-device">Scope</label>
        <select id="commissioning-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          <option value="">All devices in tenant</option>
          {devices.map((id) => <option key={id} value={id}>{id}</option>)}
        </select>
        {loading && <span className="small muted" role="status">Loading evidence…</span>}
      </div>

      {error && (
        <p className="form-message error" role="alert">
          Commissioning metrics unavailable: {error}. Nothing below is shown as measured.
        </p>
      )}

      <div className="commissioning-ladder">
        <Rung
          number={1}
          title="Observe"
          stateTone={wouldTotal > 0 ? 'ready' : 'idle'}
          state={wouldTotal > 0 ? 'Evidence recorded' : 'No would-actions recorded'}
        >
          <p>Open loop. Shield decides and records what it would have done, and takes no action.</p>
          <Stat label="Would-actions recorded" value={formatCount(wouldTotal)} detail={observe
            ? `contain ${observe.by_action?.contain ?? 0} · deny ${observe.by_action?.deny ?? 0} · escalate ${observe.by_action?.escalate ?? 0}`
            : undefined} />
        </Rung>

        <Rung
          number={2}
          title="Recommend"
          stateTone="caution"
          state="Setting exists; device behaviour unverified"
        >
          <p>The controller proposes and a human approves.</p>
          <Stat
            label="Configured response mode"
            value={containmentMode ? containmentMode : NOT_MEASURED}
            detail="Not verified that the device holds an action for approval. Confirm before relying on it."
          />
        </Rung>

        <Rung
          number={3}
          title="Enforce narrow classes"
          stateTone={completed > 0 ? 'ready' : 'idle'}
          state={completed > 0 ? 'Freezes recorded' : 'No completed freezes'}
        >
          <p>The loop is closed for a few high-confidence, low-regret actions.</p>
          <div className="commissioning-stats">
            <Stat label="Completed freezes" value={formatCount(completed)}
              detail={containment ? `${containment.attempts ?? 0} attempted · ${containment.failed ?? 0} failed` : undefined} />
            <Stat label="Decision-to-freeze p50" value={formatMs(latency?.p50)} detail={latency ? `n = ${latency.n ?? 0}` : undefined} />
            <Stat label="p95" value={formatMs(latency?.p95)} />
            <Stat label="p99" value={formatMs(latency?.p99)} />
            <Stat label="False-freeze rate" value={formatRate(falseFreeze?.rate)}
              detail={falseFreeze ? `${falseFreeze.linked_resumes ?? 0} reversed of ${falseFreeze.completed_contains ?? 0} · ${falseFreeze.unlinked_resumes ?? 0} unlinked resumes` : undefined} />
          </div>
        </Rung>

        <Rung number={4} title="Autonomous cascade" stateTone="planned" state="Partly planned">
          <p>The rule tier, the local model, and fleet policy act together, with receipts anchored.</p>
          <ul className="commissioning-planned">
            <li><b>Tier 1 rules</b> Shipping</li>
            <li><b>Tier 2 local model</b> Demo-grade</li>
            <li><b>Tier 3 cloud escalation</b> [PLANNED]</li>
            <li><b>Receipt anchoring</b> [PLANNED]</li>
          </ul>
        </Rung>
      </div>

      <section className="settings-card" aria-labelledby="commissioning-method-title">
        <div className="settings-card-header">
          <div className="settings-card-title"><Gauge size={18} /><h3 id="commissioning-method-title">How these are measured</h3></div>
          <span className="live-status-pill"><ShieldCheck size={13} /> Read-only</span>
        </div>
        <ul className="commissioning-notes">
          <li><b>Decision-to-freeze</b> is monotonic time from the router receiving an event to the freeze returning. It is not sensor-event-to-freeze.</li>
          <li><b>False-freeze rate</b> is operator resumes that name a freeze, over completed freezes. A resume that names nothing is shown separately and not counted.</li>
          <li>Window: latest {metrics?.window?.max_rows ?? '—'} outcome rows ({metrics?.window?.outcome_rows_read ?? '—'} read).</li>
        </ul>
        {(metrics?.not_instrumented || []).length > 0 && (
          <>
            <p className="eyebrow">NOT INSTRUMENTED</p>
            <ul className="commissioning-notes" aria-label="Not instrumented">
              {metrics.not_instrumented.map((line) => <li key={line}>{line}</li>)}
            </ul>
          </>
        )}
      </section>
    </div>
  )
}
