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

export function EventStreamView({ data }) {
  const [search, setSearch] = useState('')
  const [actionFilter, setActionFilter] = useState('all')
  const [classFilter, setClassFilter] = useState('all')
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [expandedRowIndex, setExpandedRowIndex] = useState(null)

  // Merge latest decisions and test events
  const rawEvents = useMemo(() => {
    const list = [...(data.summary?.latest_decisions || []), ...(data.events || [])]
    return list.map((item, idx) => {
      const dec = item.decision || {}
      const dInfo = dec.decision || {}
      const action = (dInfo.action || item.action || dec.class || 'allow').toLowerCase()
      const severity = (dInfo.severity || item.severity || 'low').toLowerCase()
      const deviceId = item.device_id || dec.device_id || 'xibalba-desktop'
      const eventClass = dec.event_ref?.class || item.event_ref?.class || dec.class || 'system_event'
      const ruleName = dec.rule?.name || item.rule?.name || 'Policy Guardrail'
      const ruleId = dec.rule?.rule_id || item.rule?.rule_id || 'default_rule'
      const ruleVersion = dec.rule?.version || item.rule?.version || '1.0.0'
      const reason = dInfo.reason || item.reason || dec.reason || 'Agent verified benign system execution.'
      const time = item.received_at || item.created_at || dec.time || item.time || new Date().toISOString()
      const eventId = dec.event_ref?.event_id || item.event_id || `evt-${idx + 1}`
      const target = item.target || dec.target || dec.event_ref?.target || dec.invocation_id || 'Workstation Process'

      return {
        raw: item,
        id: eventId,
        action,
        severity,
        deviceId,
        eventClass,
        ruleName,
        ruleId,
        ruleVersion,
        reason,
        time,
        target,
        tier: dInfo.tier || 'tier1',
        exported: dec.export?.decision_exported ?? true,
      }
    })
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
    return {
      total: rawEvents.length,
      contained: rawEvents.filter((e) => e.action === 'contain' || e.action === 'contained').length,
      denied: rawEvents.filter((e) => e.action === 'deny' || e.action === 'blocked').length,
      allowed: rawEvents.filter((e) => e.action === 'allow' || e.action === 'allowed').length,
      escalated: rawEvents.filter((e) => e.action === 'escalate').length,
    }
  }, [rawEvents])

  return (
    <div className="event-stream-container">
      {/* Agent Reasoning Hero */}
      <div className="reasoning-hero">
        <div className="reasoning-hero-header">
          <div className="reasoning-hero-badge">
            <Brain size={16} />
            <span>AGENT REASONING ENGINE</span>
          </div>
          <h2>Autonomous Event Reasoner & Decision Stream</h2>
          <p>
            Shield inspects real-time low-level eBPF kernel probes, process execution chains, and agent network traffic.
            Every observed activity is evaluated against active cryptographic policies with human-auditable reasoning.
          </p>
        </div>

        <div className="reasoning-stats-row">
          <div className="reasoning-stat-card">
            <span className="stat-label">Intercepted Events</span>
            <b className="stat-val">{counts.total}</b>
            <small>Live event stream</small>
          </div>
          <div className="reasoning-stat-card">
            <span className="stat-label">Contained Workloads</span>
            <b className="stat-val text-amber">{counts.contained}</b>
            <small>Shadow workloads quarantined</small>
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
                      {evt.action.toUpperCase()}
                    </span>

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
                    <b>Agent Security Reasoning</b>
                    <span className="matched-rule-tag">
                      <Shield size={11} /> Rule: <code>{evt.ruleName}</code> ({evt.ruleId} v{evt.ruleVersion})
                    </span>
                  </div>
                  <p className="reasoning-rationale">
                    {evt.reason}
                  </p>
                  <div className="reasoning-footer-meta">
                    <span className="guardrail-tier">Governance Tier: {evt.tier}</span>
                    <span className="export-status">
                      {evt.exported ? '✓ Receipt Exported & Verified' : '○ Local Execution'}
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
