import { AlertTriangle, CheckCircle2, GitBranch, LockKeyhole } from 'lucide-react'

const short = (value) => value ? `${String(value).slice(0, 14)}…` : 'none'

export function DecisionTracePanel({ trace }) {
  if (!trace) return <section className="settings-card decision-trace-card" aria-labelledby="shield-decision-trace-title"><div className="settings-card-title"><GitBranch size={18} /><h3 id="shield-decision-trace-title">DecisionTrace</h3></div><p className="settings-card-desc">The local Jev correlation projection is not available from this control plane. This is an evidence gap, not a zero-risk result.</p><span className="live-status-pill"><AlertTriangle size={13} /> Unavailable</span></section>
  const events = trace.events || []
  const selected = events[0]
  const advisory = selected?.advisory
  return <section className="settings-card decision-trace-card" aria-labelledby="shield-decision-trace-title">
    <div className="settings-card-header"><div className="settings-card-title"><GitBranch size={18} /><div><p className="eyebrow">CORRELATION / OBSERVATION</p><h3 id="shield-decision-trace-title">DecisionTrace</h3></div></div><span className={`live-status-pill ${trace.valid ? 'verified' : ''}`}>{trace.valid ? <CheckCircle2 size={13} /> : <AlertTriangle size={13} />} {trace.valid ? 'Locally verified' : 'Review required'}</span></div>
    <p className="settings-card-desc">Jev estimates observed transitions around Shield policy events. It never authorizes, overrides, or proves causality for an enforcement action.</p>
    <div className="decision-trace-shield-summary"><span><small>Events</small><b>{events.length}</b></span><span><small>Trace root</small><code>{short(trace.root)}</code></span><span><small>Policy authority</small><b>Shield / OPA</b></span></div>
    {events.length === 0 ? <div className="decision-trace-empty"><GitBranch size={20} /><b>No trace events</b><span>Authenticated DecisionTrace records will appear here when the local projection is populated.</span></div> : <div className="decision-trace-shield-body"><div className="decision-trace-shield-events">{events.slice(0, 5).map((event, index) => <div className="decision-trace-shield-event" key={event.event_id}><b>{index + 1}. {event.envelope?.event_type || 'observed event'}</b><span>{event.envelope?.policy_decision || 'observed'} · {event.advisory?.risk_category || 'unclassified'}</span><code>{short(event.event_hash)}</code></div>)}</div><div className="decision-trace-shield-advisory"><b>Jev advisory</b><span>{advisory?.provider_id || 'not reported'} · {advisory?.status || 'unavailable'}</span>{Object.entries(advisory?.transition_probabilities || {}).map(([label, value]) => <div className="decision-probability" key={label}><span>{label}</span><b>{Math.round(Number(value) * 100)}%</b><i><em style={{ width: `${Math.round(Number(value) * 100)}%` }} /></i></div>)}<p className="decision-trace-boundary"><LockKeyhole size={13} /> Causal claim: false · enforcement remains policy-owned.</p></div></div>}
    <small className="decision-trace-disclaimer">{trace.disclaimer || 'Observational correlation only; probabilities do not prove causality or execution.'}</small>
  </section>
}
