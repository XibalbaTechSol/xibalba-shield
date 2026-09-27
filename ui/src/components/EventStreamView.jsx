import { useState, useMemo } from 'react'
import {
  Activity,
  Brain,
  Shield,
  Search,
  Filter,
  Cpu,
  X,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'

const ACTION_ALIASES = {
  contained: 'contain',
  blocked: 'deny',
  denied: 'deny',
  allowed: 'allow',
  escalated: 'escalate',
  observed: 'log_only',
  logged: 'log_only',
}

function normalizeAction(action) {
  const value = String(action || 'allow').toLowerCase()
  return ACTION_ALIASES[value] || value
}

export function EventStreamView({ data }) {
  const [search, setSearch] = useState('')
  const [actionFilter, setActionFilter] = useState('all')
  const [classFilter, setClassFilter] = useState('all')
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [expandedRowIndex, setExpandedRowIndex] = useState(null)

  // Render durable decisions alongside the live, loss-bounded observation rollups.
  // Routine no-match activity is intentionally aggregated by Shield instead of
  // being written as one database row per process event.
  const rawEvents = useMemo(() => {
    const decisions = (data.summary?.latest_decisions || []).map((item) => ({ ...item, source: 'decision' }))
    const testEvents = (data.events || []).map((item) => ({ ...item, source: 'test' }))
    const rollups = (data.summary?.decision_observation_rollups || []).map((item) => ({
      ...item,
      source: 'observation_rollup',
      event_id: `rollup-${item.device_id || 'unattributed'}-${item.bucket_start}-${item.action}-${item.event_class}`,
      reason: `${Number(item.count || item.observation_count || 0).toLocaleString()} observed ${item.event_class || 'system'} activities in this minute.`,
    }))

    return [...decisions, ...testEvents, ...rollups]
      .map((item, idx) => {
      const dec = item.decision || {}
      const dInfo = dec.decision || {}
      const action = normalizeAction(dInfo.action || item.action || dec.class || 'allow')
      const sample = item.sample_decision || {}
      const severity = (dInfo.severity || item.severity || sample.decision?.severity || 'low').toLowerCase()
      const deviceId = item.device_id || dec.device_id || sample.device_id || 'unattributed device'
      const eventClass = dec.event_ref?.class || item.event_ref?.class || item.event_class || sample.event_ref?.class || dec.class || 'system_event'
      const agentId = item.agent_id || dec.agent_id || dec.event_ref?.agent_id || sample.agent_id || sample.event_ref?.agent_id || null
      const ruleName = dec.rule?.name || item.rule?.name || sample.rule?.name || 'Policy Guardrail'
      const ruleId = dec.rule?.rule_id || item.rule?.rule_id || item.rule_id || sample.rule?.rule_id || 'default_rule'
      const ruleVersion = dec.rule?.version || item.rule?.version || sample.rule?.version || '1.0.0'
      const reason = dInfo.reason || item.reason || dec.reason || (eventClass === 'agent_event' ? 'Agent event observed without a policy decision.' : 'No policy rule matched.')
      const time = item.received_at || item.created_at || dec.time || item.time || new Date().toISOString()
      const eventId = dec.event_ref?.event_id || item.event_id || `evt-${idx + 1}`
      const target = item.source === 'observation_rollup'
        ? `${deviceId} · ${item.bucket_start || 'minute bucket'}`
        : item.target || dec.target || dec.event_ref?.target || dec.invocation_id || item.sample_decision?.event_ref?.event_id || 'Workstation activity'

      return {
        raw: item,
        id: eventId,
        action,
        severity,
        deviceId,
        eventClass,
        agentId,
        ruleName,
        ruleId,
        ruleVersion,
        reason,
        time,
        target,
        tier: dInfo.tier || 'tier1',
        exported: dec.export?.decision_exported ?? true,
        source: item.source || 'decision',
        observationCount: Number(item.count || item.observation_count || 1),
      }
      })
      .sort((left, right) => new Date(right.time).getTime() - new Date(left.time).getTime())
  }, [data.summary, data.events])

  // Filter events
  const filteredEvents = useMemo(() => {
    return rawEvents.filter((evt) => {
      if (actionFilter !== 'all' && evt.action !== actionFilter) return false
      if (classFilter !== 'all' && evt.eventClass !== classFilter) return false
      if (search.trim()) {
        const q = search.toLowerCase()
        const match =
          evt.id.toLowerCase().includes(q) ||
          evt.deviceId.toLowerCase().includes(q) ||
          evt.ruleName.toLowerCase().includes(q) ||
          evt.reason.toLowerCase().includes(q) ||
          evt.action.toLowerCase().includes(q) ||
          evt.target.toLowerCase().includes(q)
        if (!match) return false
      }
      return true
    })
  }, [rawEvents, actionFilter, classFilter, search])

  const counts = useMemo(() => {
    const countAction = (action) => rawEvents
      .filter((event) => event.action === action)
      .reduce((sum, event) => sum + event.observationCount, 0)

    return {
      total: rawEvents.reduce((sum, event) => sum + event.observationCount, 0),
      contained: countAction('contain'),
      containFallbacks: rawEvents.filter((event) => event.action === 'contain' && /A2A_UNRESOLVED_ESCALATION/i.test(event.reason)).reduce((sum, event) => sum + event.observationCount, 0),
      denied: countAction('deny'),
      escalated: countAction('escalate'),
      allowed: countAction('allow'),
      logged: countAction('log_only'),
      agent: rawEvents.filter((event) => event.eventClass === 'agent_event' && event.agentId).reduce((sum, event) => sum + event.observationCount, 0),
    }
  }, [rawEvents])

  return (
    <div className="event-stream-container">
      {/* Agent Reasoning Hero */}
      <div className="reasoning-hero">
        <div className="reasoning-hero-header">
          <div className="reasoning-hero-badge">
            <Brain size={16} />
            <span>SHIELD DECISION ENGINE</span>
          </div>
          <h2>Policy evaluation & decision stream</h2>
          <p>
            Shield displays authenticated kernel observations and policy decisions. Agent-level reasoning appears only
            when an authenticated agent hook attributes an event to a canonical agent identity.
          </p>
        </div>

        <div className="reasoning-stats-row">
          <div className="reasoning-stat-card">
            <span className="stat-label">Intercepted Events</span>
            <b className="stat-val">{counts.total}</b>
            <small>{rawEvents.some((event) => event.source === 'observation_rollup') ? 'Live Shield observations; rollups are loss-bounded' : 'Waiting for Shield observations'}</small>
          </div>
          <div className="reasoning-stat-card">
            <span className="stat-label">Containments</span>
            <b className="stat-val text-amber">{counts.contained}</b>
            <small>{counts.containFallbacks ? `${counts.contained - counts.containFallbacks} direct · ${counts.containFallbacks} fail-closed fallback` : 'Policy-approved workload freezes'}</small>
          </div>
          <div className="reasoning-stat-card">
            <span className="stat-label">Policy Denials</span>
            <b className="stat-val text-red">{counts.denied}</b>
            <small>Unauthorized attempts blocked</small>
          </div>
          <div className="reasoning-stat-card">
            <span className="stat-label">Verified Benign</span>
            <b className="stat-val text-green">{counts.allowed}</b>
            <small>Authenticated execution</small>
          </div>
          <div className="reasoning-stat-card">
            <span className="stat-label">Agent Events</span>
            <b className="stat-val">{counts.agent}</b>
            <small>{counts.agent ? 'Authenticated agent hooks' : 'No agent-attributed events'}</small>
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="event-stream-toolbar">
        <div className="stream-search-wrap">
          <Search size={15} />
          <input
            type="search"
            placeholder="Search by rule, process, reason, device, or event ID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button type="button" className="clear-search-btn" onClick={() => setSearch('')}>
              ✕
            </button>
          )}
        </div>

        <div className="stream-filters-group">
          <div className="action-filters">
            <button
              type="button"
              className={`filter-chip ${actionFilter === 'all' ? 'active' : ''}`}
              onClick={() => setActionFilter('all')}
            >
              All Actions ({counts.total})
            </button>
            <button
              type="button"
              className={`filter-chip chip-contain ${actionFilter === 'contain' ? 'active' : ''}`}
              onClick={() => setActionFilter(actionFilter === 'contain' ? 'all' : 'contain')}
            >
              Contained ({counts.contained})
            </button>
            <button
              type="button"
              className={`filter-chip chip-deny ${actionFilter === 'deny' ? 'active' : ''}`}
              onClick={() => setActionFilter(actionFilter === 'deny' ? 'all' : 'deny')}
            >
              Denied ({counts.denied})
            </button>
            <button
              type="button"
              className={`filter-chip chip-escalate ${actionFilter === 'escalate' ? 'active' : ''}`}
              onClick={() => setActionFilter(actionFilter === 'escalate' ? 'all' : 'escalate')}
            >
              Escalated ({counts.escalated})
            </button>
            <button
              type="button"
              className={`filter-chip chip-allow ${actionFilter === 'allow' ? 'active' : ''}`}
              onClick={() => setActionFilter(actionFilter === 'allow' ? 'all' : 'allow')}
            >
              Allowed ({counts.allowed})
            </button>
            <button
              type="button"
              className={`filter-chip ${actionFilter === 'log_only' ? 'active' : ''}`}
              onClick={() => setActionFilter(actionFilter === 'log_only' ? 'all' : 'log_only')}
            >
              Logged ({counts.logged})
            </button>
          </div>

          <div className="class-filter-wrap">
            <Filter size={13} />
            <select
              value={classFilter}
              onChange={(e) => setClassFilter(e.target.value)}
              className="class-select"
            >
              <option value="all">All Event Types</option>
              <option value="process_activity">Process Activity</option>
              <option value="network_flow">Network Flow</option>
              <option value="agent_event">Agent Event</option>
              <option value="system_event">System Event</option>
            </select>
          </div>
        </div>
      </div>

      {/* Stream Cards */}
      <div className="event-cards-stream">
        {filteredEvents.length === 0 ? (
          <div className="empty-stream-state">
            <Activity size={32} />
            <h4>No matching system events found</h4>
            <p>Try clearing your search query or adjusting the action filters.</p>
            <button
              type="button"
              className="reset-filters-btn"
              onClick={() => {
                setSearch('')
                setActionFilter('all')
                setClassFilter('all')
              }}
            >
              Reset Filters
            </button>
          </div>
        ) : (
          filteredEvents.map((evt, idx) => {
            const isExpanded = expandedRowIndex === idx
            return (
              <article key={`${evt.id}-${idx}`} className={`event-stream-card action-${evt.action}`}>
                {/* Event Card Header */}
                <div className="event-card-top">
                  <div className="event-badges-row">
                    <span className={`event-action-pill ${evt.action}`}>
                      <span className="dot" />
                      {evt.source === 'observation_rollup' ? 'OBSERVED' : evt.action.toUpperCase()}
                    </span>

                    {evt.source === 'observation_rollup' && (
                      <span className="event-class-tag">{evt.observationCount.toLocaleString()} observations</span>
                    )}

                    <span className={`severity-tag sev-${evt.severity}`}>
                      {evt.severity.toUpperCase()}
                    </span>

                    <span className="event-class-tag">
                      <Cpu size={11} /> {evt.eventClass}
                    </span>

                    <span className="event-device-tag">{evt.deviceId}</span>
                  </div>

                  <div className="event-time-meta">
                    <time dateTime={evt.time}>{evt.time}</time>
                  </div>
                </div>

                {/* Primary Subject / Process Target */}
                <div className="event-subject-row">
                  <span className="subject-label">Event Target:</span>
                  <code className="subject-target">{evt.target}</code>
                  <span className="event-id-ref">ID: <code>{evt.id}</code></span>
                </div>

                {/* Prominent Agent Reasoning Callout */}
                <div className="agent-reasoning-callout">
                  <div className="reasoning-header">
                    <Brain size={14} className="reasoning-icon" />
                    <b>{evt.eventClass === 'agent_event' ? (evt.agentId ? 'Authenticated agent attribution' : 'Agent event · identity unbound') : 'Shield policy evaluation'}</b>
                    <span className="matched-rule-tag">
                      <Shield size={11} /> Rule: <code>{evt.ruleName}</code> ({evt.ruleId} v{evt.ruleVersion})
                    </span>
                  </div>
                  <p className="reasoning-rationale">
                    {evt.reason}{evt.eventClass === 'agent_event' && !evt.agentId ? ' This event is device-scoped until a canonical agent identity is attached.' : ''}
                  </p>
                  <div className="reasoning-footer-meta">
                    <span className="guardrail-tier">Governance Tier: {evt.tier}</span>
                    <span className="export-status">
                      {evt.source === 'observation_rollup'
                        ? '○ Local Shield observation · aggregated'
                        : evt.exported ? '✓ Receipt Exported & Verified' : '○ Local Execution'}
                    </span>
                  </div>
                </div>

                {/* Card Actions */}
                <div className="event-card-actions">
                  <button
                    type="button"
                    className="toggle-raw-btn"
                    onClick={() => setExpandedRowIndex(isExpanded ? null : idx)}
                  >
                    {isExpanded ? (
                      <>
                        <ChevronUp size={13} /> Hide Details
                      </>
                    ) : (
                      <>
                        <ChevronDown size={13} /> Inspect JSON Payload
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    className="open-drawer-btn"
                    onClick={() => setSelectedEvent(evt.raw)}
                  >
                    <ExternalLink size={13} /> Open in Evidence Drawer
                  </button>
                </div>

                {/* Inline JSON payload when expanded */}
                {isExpanded && (
                  <div className="event-inline-json">
                    <pre>{JSON.stringify(evt.raw, null, 2)}</pre>
                  </div>
                )}
              </article>
            )
          })
        )}
      </div>

      {/* Detailed Side Drawer */}
      {selectedEvent && (
        <aside
          className="event-drawer"
          role="dialog"
          aria-modal="true"
          aria-label="Event details"
        >
          <header>
            <div>
              <p className="eyebrow">
                <Brain size={12} /> AGENT DECISION EVIDENCE
              </p>
              <h3>Event Record Details</h3>
            </div>
            <button
              type="button"
              aria-label="Close details"
              className="drawer-close"
              onClick={() => setSelectedEvent(null)}
            >
              <X aria-hidden="true" />
            </button>
          </header>
          <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
        </aside>
      )}
    </div>
  )
}
