import { useEffect, useState, useMemo } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  ExternalLink,
  RefreshCw,
  Sliders,
  Check,
  X,
  Radio,
  FileCheck2,
  AlertTriangle,
} from 'lucide-react'

function WorkspaceHeader({ eyebrow, title, copy }) {
  return (
    <div className="workspace-header">
      <p className="eyebrow">{eyebrow}</p>
      <h2>{title}</h2>
      <p>{copy}</p>
    </div>
  )
}

function WorkspaceTabs({ tabs, active, onChange }) {
  return (
    <div className="workspace-tabs" role="tablist" aria-label="Response workspace tabs">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={active === tab.id}
          className={active === tab.id ? 'active' : ''}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
          {tab.count !== undefined && <span className="tab-count">{tab.count}</span>}
        </button>
      ))}
    </div>
  )
}

function shortHash(h) {
  if (!h) return '—'
  const clean = h.replace('sha256:', '')
  return clean.slice(0, 10) + '…' + clean.slice(-6)
}

function vendorConsoleUrl(vendor, hostId, detectionId) {
  if (vendor === 'crowdstrike') {
    if (detectionId) return `https://falcon.crowdstrike.com/activity-v2/detections/${detectionId}`
    if (hostId) return `https://falcon.crowdstrike.com/host-management/hosts/${hostId}`
    return 'https://falcon.crowdstrike.com'
  }
  return null
}

export function ResponseWorkspace({ api, refresh, timeRange, connection }) {
  const [activeTab, setActiveTab] = useState('queue')
  const [intents, setIntents] = useState([])
  const [ledger, setLedger] = useState([])
  const [chainVerify, setChainVerify] = useState(null)
  const [connectors, setConnectors] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [selectedItem, setSelectedItem] = useState(null)
  const [chainDetail, setChainDetail] = useState(null)
  const [decideReason, setDecideReason] = useState('')
  const [actionMessage, setActionMessage] = useState('')
  const [actionError, setActionError] = useState(false)
  const [executingHash, setExecutingHash] = useState(null)
  const [ledgerFilter, setLedgerFilter] = useState('all')

  const loadData = async () => {
    setLoading(true)
    setError('')
    try {
      const [pendingRes, ledgerRes, connRes] = await Promise.all([
        api.responseIntents('pending').catch(() => ({ intents: [] })),
        api.responseLedger().catch(() => ({ intents: [], verify: null })),
        api.edrConnectors().catch(() => ({ connectors: [] })),
      ])
      setIntents(pendingRes.intents || [])
      setLedger(ledgerRes.intents || [])
      setChainVerify(ledgerRes.verify || null)
      setConnectors(connRes.connectors || [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [api])

  const openChainDrawer = async (item) => {
    setSelectedItem(item)
    setChainDetail(null)
    try {
      const full = await api.responseChain(item.intent_hash)
      setChainDetail(full)
    } catch (err) {
      setChainDetail({ error: err instanceof Error ? err.message : String(err) })
    }
  }

  const handleDecision = async (intentHash, verdict) => {
    if (!decideReason.trim()) {
      setActionMessage('A justification reason is required.')
      setActionError(true)
      return
    }
    setActionMessage('Recording decision…')
    setActionError(false)
    try {
      const approverId = connection?.email || 'tenant-admin'
      await api.approveResponse(intentHash, approverId, verdict, decideReason.trim())
      setDecideReason('')
      setActionMessage(`Intent ${verdict === 'approve' ? 'approved' : 'denied'} successfully.`)
      await loadData()
      if (selectedItem?.intent_hash === intentHash) {
        const full = await api.responseChain(intentHash)
        setChainDetail(full)
        setSelectedItem(full)
      }
    } catch (err) {
      setActionMessage(err instanceof Error ? err.message : String(err))
      setActionError(true)
    }
  }

  const handleConsume = async (intentHash) => {
    setExecutingHash(intentHash)
    setActionMessage('Executing action on EDR endpoint…')
    setActionError(false)
    try {
      const res = await api.consumeResponseApproval(intentHash, true)
      const status = res.result?.status || 'executed'
      setActionMessage(`Action consumed & executed (${status}). Receipt spooled for Integrity anchoring.`)
      await loadData()
      if (selectedItem?.intent_hash === intentHash) {
        const full = await api.responseChain(intentHash)
        setChainDetail(full)
        setSelectedItem(full)
      }
    } catch (err) {
      setActionMessage(err instanceof Error ? err.message : String(err))
      setActionError(true)
    } finally {
      setExecutingHash(null)
    }
  }

  const filteredLedger = useMemo(() => {
    if (ledgerFilter === 'all') return ledger
    return ledger.filter((item) => item.status === ledgerFilter)
  }, [ledger, ledgerFilter])

  const pendingCount = intents.length

  const tabs = [
    { id: 'queue', label: 'Approval Queue', count: pendingCount },
    { id: 'ledger', label: 'Action Ledger', count: ledger.length },
    { id: 'connectors', label: 'EDR Connectors', count: connectors.length },
  ]

  return (
    <div className="response-workspace-container" role="region" aria-label="EDR Response Governance Workspace">
      <WorkspaceHeader
        eyebrow="EDR RESPONSE GOVERNANCE"
        title="Response Control & Ledger"
        copy="Attested human and agent response governance across connected EDRs. Hash-bound authorization with tamper-evident chain verification anchored to the Integrity Protocol."
      />

      <WorkspaceTabs tabs={tabs} active={activeTab} onChange={setActiveTab} />

      {error && (
        <div className="form-feedback-alert error" role="alert">
          {error}
        </div>
      )}

      {activeTab === 'queue' && (
        <section className="response-panel" aria-labelledby="approval-queue-heading">
          <div className="panel-header-row">
            <div>
              <h3 id="approval-queue-heading">Approval Queue</h3>
              <p>Escalated response intents awaiting operator sign-off before endpoint execution.</p>
            </div>
            <button type="button" className="secondary-btn" onClick={loadData} disabled={loading}>
              <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
            </button>
          </div>

          {intents.length === 0 ? (
            <div className="empty-row" role="status">
              <CheckCircle2 size={24} className="text-muted" aria-hidden="true" />
              <p>No response actions are waiting for approval.</p>
            </div>
          ) : (
            <div className="event-table response-intent-table" tabIndex={0}>
              <header>
                <span>REQUESTED</span>
                <span>ACTOR</span>
                <span>ACTION &amp; HOST</span>
                <span>TRIGGER / VENDOR</span>
                <span>STATUS / EXPIRES</span>
                <span>DECISION</span>
              </header>
              {intents.map((item) => {
                const intent = item.intent || {}
                const decision = item.decision || {}
                const vendorLink = vendorConsoleUrl(intent.vendor, intent.host_id, intent.detection_id)
                return (
                  <div key={item.intent_hash} className="event-row response-row">
                    <span>
                      <b>{item.created_at ? new Date(item.created_at).toLocaleTimeString() : '—'}</b>
                      <small>{item.created_at ? new Date(item.created_at).toLocaleDateString() : ''}</small>
                    </span>
                    <span>
                      <span className={`status-badge actor-${intent.actor_type}`}>
                        {intent.actor_type || 'human'}
                      </span>
                      <small title={intent.actor_did || intent.actor_id}>
                        {intent.actor_did ? shortHash(intent.actor_did) : intent.actor_id || '—'}
                      </small>
                    </span>
                    <span>
                      <b>{intent.action?.replace('_', ' ')}</b>
                      <small title={intent.host_id}>Host: {intent.host_id}</small>
                    </span>
                    <span>
                      <b>{intent.vendor}</b>
                      {vendorLink ? (
                        <a
                          href={vendorLink}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="vendor-console-link"
                          title="View detection in vendor console"
                        >
                          View in Falcon <ExternalLink size={12} />
                        </a>
                      ) : (
                        <small>{intent.detection_id || 'manual'}</small>
                      )}
                    </span>
                    <span>
                      <span className="status-badge pending">pending</span>
                      <small className="ttl-countdown">
                        <Clock size={11} /> {item.expires_at ? new Date(item.expires_at).toLocaleTimeString() : '—'}
                      </small>
                    </span>
                    <span>
                      <button
                        type="button"
                        className="primary-btn sm"
                        onClick={() => openChainDrawer(item)}
                      >
                        Review
                      </button>
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </section>
      )}

      {activeTab === 'ledger' && (
        <section className="response-panel" aria-labelledby="action-ledger-heading">
          <div className="panel-header-row">
            <div>
              <h3 id="action-ledger-heading">Action Ledger</h3>
              <p>Tamper-evident log of all response actions, decisions, authorizations, and Integrity receipts.</p>
            </div>
            <div className="ledger-actions-bar">
              {chainVerify && (
                <span
                  className={`status-pill ${chainVerify.valid ? 'success' : 'failed'}`}
                  title={`Head: ${chainVerify.head || 'none'}`}
                >
                  {chainVerify.valid ? (
                    <>
                      <ShieldCheck size={14} /> Chain Valid ({chainVerify.events} events)
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={14} /> Chain Broken (seq #{chainVerify.broken_at})
                    </>
                  )}
                </span>
              )}
              <select
                aria-label="Filter ledger by status"
                value={ledgerFilter}
                onChange={(e) => setLedgerFilter(e.target.value)}
                className="filter-select"
              >
                <option value="all">All statuses</option>
                <option value="executed">Executed</option>
                <option value="pending">Pending</option>
                <option value="approved">Approved</option>
                <option value="denied">Denied</option>
                <option value="expired">Expired</option>
                <option value="failed">Failed</option>
              </select>
              <button type="button" className="secondary-btn" onClick={loadData} disabled={loading}>
                <RefreshCw size={14} className={loading ? 'spin' : ''} />
              </button>
            </div>
          </div>

          {filteredLedger.length === 0 ? (
            <div className="empty-row" role="status">
              <p>No response ledger entries match the selected filter.</p>
            </div>
          ) : (
            <div className="event-table response-ledger-table" tabIndex={0}>
              <header>
                <span>TIME</span>
                <span>ACTOR</span>
                <span>ACTION &amp; HOST</span>
                <span>DECISION</span>
                <span>EDR OUTCOME</span>
                <span>INTEGRITY RECEIPT</span>
                <span>TRACE</span>
              </header>
              {filteredLedger.map((item) => {
                const intent = item.intent || {}
                const decision = item.decision || {}
                const result = item.result || {}
                const vendorLink = vendorConsoleUrl(intent.vendor, intent.host_id, intent.detection_id)
                return (
                  <div key={item.intent_hash} className="event-row response-row">
                    <span>
                      <b>{item.created_at ? new Date(item.created_at).toLocaleTimeString() : '—'}</b>
                      <small>{item.created_at ? new Date(item.created_at).toLocaleDateString() : ''}</small>
                    </span>
                    <span>
                      <span className={`status-badge actor-${intent.actor_type}`}>
                        {intent.actor_type || 'human'}
                      </span>
                      <small title={intent.actor_did || intent.actor_id}>
                        {intent.actor_did ? shortHash(intent.actor_did) : intent.actor_id || '—'}
                      </small>
                    </span>
                    <span>
                      <b>{intent.action?.replace('_', ' ')}</b>
                      <small>Host: {intent.host_id}</small>
                      {vendorLink && (
                        <a
                          href={vendorLink}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="vendor-console-link"
                          title="View host in Falcon"
                        >
                          Falcon <ExternalLink size={10} />
                        </a>
                      )}
                    </span>
                    <span>
                      <span className={`status-badge decision-${decision.action || 'unknown'}`}>
                        {decision.action || '—'}
                      </span>
                      <small title={decision.reason}>{decision.rule_id || 'policy-rule'}</small>
                    </span>
                    <span>
                      <span className={`status-badge status-${item.status}`}>
                        {item.status}
                      </span>
                      {result.vendor_reference && (
                        <small title={result.vendor_reference}>{result.vendor_reference}</small>
                      )}
                    </span>
                    <span>
                      <span className="status-badge receipt-anchored">
                        <ShieldCheck size={12} /> {shortHash(item.intent_hash)}
                      </span>
                      <small>Exported to oracle</small>
                    </span>
                    <span>
                      <button
                        type="button"
                        className="secondary-btn sm"
                        onClick={() => openChainDrawer(item)}
                      >
                        Inspect
                      </button>
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </section>
      )}

      {activeTab === 'connectors' && (
        <section className="response-panel" aria-labelledby="edr-connectors-heading">
          <div className="panel-header-row">
            <div>
              <h3 id="edr-connectors-heading">Connected EDR Providers</h3>
              <p>Configure and probe API connectors to CrowdStrike Falcon and automated response backends.</p>
            </div>
            <button type="button" className="secondary-btn" onClick={loadData} disabled={loading}>
              <RefreshCw size={14} className={loading ? 'spin' : ''} />
            </button>
          </div>

          <div className="connectors-grid">
            <ConnectorCard
              vendor="crowdstrike"
              title="CrowdStrike Falcon"
              copy="Direct API integration via OAuth2. Collects detections, provides host telemetry, and securely executes containment with cryptographic sign-off."
              api={api}
              onSaved={loadData}
            />

            <ConnectorCard
              vendor="simulated"
              title="Simulated EDR"
              copy="In-memory simulated provider for zero-risk test automation, live gate validation, and boundary verification without a live Falcon tenant."
              api={api}
              onSaved={loadData}
            />
          </div>
        </section>
      )}

      {selectedItem && (
        <aside className="device-detail-backdrop" role="presentation" onClick={() => setSelectedItem(null)}>
          <section
            className="device-detail-drawer"
            role="dialog"
            aria-modal="true"
            aria-label="Response intent chain details"
            onClick={(e) => e.stopPropagation()}
          >
            <header className="device-detail-header">
              <div>
                <p className="eyebrow">RESPONSE INTENT</p>
                <h2>{selectedItem.intent?.action?.replace('_', ' ') || 'Action'}</h2>
                <span>
                  Host: {selectedItem.intent?.host_id} · Vendor: {selectedItem.intent?.vendor}
                </span>
              </div>
              <button
                type="button"
                className="drawer-close"
                aria-label="Close details"
                onClick={() => setSelectedItem(null)}
              >
                <X aria-hidden="true" />
              </button>
            </header>

            <div className="device-detail-content">
              {actionMessage && (
                <div className={`form-feedback-alert ${actionError ? 'error' : 'success'}`} role="alert">
                  {actionMessage}
                </div>
              )}

              <div className="drawer-section">
                <h4>Authorization Status</h4>
                <div className="status-banner">
                  <span className={`status-badge status-${selectedItem.status}`}>
                    {selectedItem.status}
                  </span>
                  <code>{selectedItem.intent_hash}</code>
                </div>
              </div>

              {selectedItem.intent?.justification && (
                <div className="drawer-section">
                  <h4>Justification</h4>
                  <p className="justification-text">{selectedItem.intent.justification}</p>
                </div>
              )}

              {selectedItem.status === 'pending' && (
                <div className="drawer-section decision-controls">
                  <h4>Operator Decision</h4>
                  <label htmlFor="decide-reason">
                    Mandatory Approval / Denial Reason:
                    <textarea
                      id="decide-reason"
                      rows={2}
                      value={decideReason}
                      onChange={(e) => setDecideReason(e.target.value)}
                      placeholder="e.g. Confirmed malicious execution per SOC runbook #402"
                      required
                    />
                  </label>
                  <div className="btn-group">
                    <button
                      type="button"
                      className="primary-btn"
                      onClick={() => handleDecision(selectedItem.intent_hash, 'approve')}
                    >
                      <Check size={14} /> Approve Intent
                    </button>
                    <button
                      type="button"
                      className="secondary-btn danger"
                      onClick={() => handleDecision(selectedItem.intent_hash, 'deny')}
                    >
                      <X size={14} /> Deny Intent
                    </button>
                  </div>
                </div>
              )}

              {selectedItem.status === 'approved' && (
                <div className="drawer-section execution-controls">
                  <h4>Ready for Execution</h4>
                  <p>All required approvals are recorded. Ready to dispatch action to {selectedItem.intent?.vendor}.</p>
                  <button
                    type="button"
                    className="primary-btn"
                    disabled={executingHash === selectedItem.intent_hash}
                    onClick={() => handleConsume(selectedItem.intent_hash)}
                  >
                    <Radio size={14} /> Dispatch &amp; Execute Action
                  </button>
                </div>
              )}

              {chainDetail?.events && chainDetail.events.length > 0 && (
                <div className="drawer-section">
                  <h4>Cryptographic Chain of Custody ({chainDetail.events.length} events)</h4>
                  <div className="chain-timeline">
                    {chainDetail.events.map((ev) => (
                      <div key={ev.seq} className="timeline-node">
                        <div className="timeline-seq">#{ev.seq}</div>
                        <div className="timeline-body">
                          <b>{ev.event_type}</b>
                          <small>{new Date(ev.created_at).toLocaleTimeString()}</small>
                          <code title={ev.event_hash}>{shortHash(ev.event_hash)}</code>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="drawer-section">
                <h4>Canonical Intent Payload</h4>
                <pre className="code-block json-view">
                  {JSON.stringify(selectedItem.intent, null, 2)}
                </pre>
              </div>
            </div>
          </section>
        </aside>
      )}
    </div>
  )
}

function ConnectorCard({ vendor, title, copy, api, onSaved }) {
  const isCrowdStrike = vendor === 'crowdstrike'
  const [cloud, setCloud] = useState('us-1')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const config = isCrowdStrike ? { client_id: clientId, client_secret: clientSecret, cloud } : {}
      const res = await api.testEdrConnector(vendor, config)
      setTestResult({ ok: res.ok, message: res.ok ? 'Connection verified successfully.' : res.error || 'Failed' })
    } catch (err) {
      setTestResult({ ok: false, message: err instanceof Error ? err.message : String(err) })
    } finally {
      setTesting(false)
    }
  }

  const handleSave = async (e) => {
    e.preventDefault()
    try {
      await api.createIntegration(`edr-${vendor}`, vendor, {
        cloud,
        client_id: clientId,
        client_secret: clientSecret,
        enabled: true,
      })
      setTestResult({ ok: true, message: 'Connector saved successfully.' })
      onSaved?.()
    } catch (err) {
      setTestResult({ ok: false, message: err instanceof Error ? err.message : String(err) })
    }
  }

  return (
    <article className="settings-card connector-card">
      <div className="settings-card-header">
        <div className="settings-card-title">
          <ShieldAlert size={18} />
          <h3>{title}</h3>
        </div>
        <span className={`live-status-pill ${vendor === 'simulated' ? 'simulated' : 'ready'}`}>
          {vendor === 'simulated' ? 'Mock Provider' : 'Configurable'}
        </span>
      </div>
      <p className="settings-card-desc">{copy}</p>

      {isCrowdStrike ? (
        <form onSubmit={handleSave} className="connector-form">
          <div className="settings-fields-grid">
            <div className="field-group">
              <label htmlFor="cs-cloud">Cloud Region</label>
              <select id="cs-cloud" value={cloud} onChange={(e) => setCloud(e.target.value)}>
                <option value="us-1">US-1 (Commercial)</option>
                <option value="us-2">US-2 (Commercial)</option>
                <option value="eu-1">EU-1 (Frankfurt)</option>
                <option value="us-gov-1">US-GOV-1 (GovCloud)</option>
              </select>
            </div>
            <div className="field-group">
              <label htmlFor="cs-client-id">Client ID</label>
              <input
                id="cs-client-id"
                type="text"
                placeholder="e.g. 0123456789abcdef"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
              />
            </div>
            <div className="field-group">
              <label htmlFor="cs-client-secret">Client Secret</label>
              <input
                id="cs-client-secret"
                type="password"
                placeholder="••••••••••••••••"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
              />
            </div>
          </div>

          <div className="btn-group">
            <button type="button" className="secondary-btn" onClick={handleTest} disabled={testing}>
              <RefreshCw size={13} className={testing ? 'spin' : ''} /> Test Connection
            </button>
            <button type="submit" className="primary-btn">
              Save Connector
            </button>
          </div>
        </form>
      ) : (
        <div className="connector-sim-actions">
          <button type="button" className="secondary-btn" onClick={handleTest} disabled={testing}>
            <Radio size={14} /> Probe Test Mock Provider
          </button>
        </div>
      )}

      {testResult && (
        <p className={`form-message ${testResult.ok ? 'success' : 'error'}`} role="status">
          {testResult.message}
        </p>
      )}
    </article>
  )
}
