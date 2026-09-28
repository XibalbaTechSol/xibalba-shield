import { useState } from 'react'
import { HardDrive, X, ShieldCheck, Activity, Database, Save, CheckCircle2, FileCheck2 } from 'lucide-react'
import { ActionForm, JsonRows, Resource } from './Common'
import { ContainmentView } from './ContainmentView'
import { OpaPoliciesView } from './OpaPoliciesView';



import { EventStreamView } from './EventStreamView'
import { PoliciesView } from './PoliciesView'
import { IntegrationsView } from './IntegrationsView'
import { DeveloperView } from './DeveloperView'
import { SettingsChangeQueue, SettingsView } from './SettingsView'
import { TransactionWorkbench } from './TransactionWorkbench'
import { AgentView } from './AgentView'
import { NetworkView } from './NetworkView'
import { HermesAgentView } from './HermesAgentView'

export function RollbackForm({ api }) {
  const [message, setMessage] = useState('')
  const [isError, setIsError] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    const values = Object.fromEntries(new FormData(event.currentTarget))
    setMessage('Loading policy history…')
    setIsError(false)
    try {
      const result = await api.policyHistory(values.deviceId)
      const latest = result.history?.[0]
      if (!latest) throw new Error('No previous policy is available for this device.')
      if (!window.confirm(`Rollback ${values.deviceId} to ${latest.policy_version}?`)) {
        setMessage('')
        return
      }
      await api.rollbackPolicy(values.deviceId, latest.id)
      setMessage(`Successfully rolled back to ${latest.policy_version}.`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error))
      setIsError(true)
    }
  }

  return (
    <Resource
      title="Rollback a policy"
      copy="Restores the most recent prior policy version and records the replacement in history."
    >
      <form className="action-form" onSubmit={submit}>
        <label>
          Device ID
          <input name="deviceId" required placeholder="prod-worker-02" />
        </label>
        <button type="submit" className="primary">Load and rollback latest</button>
        {message && (
          <p className={`form-message ${isError ? 'error' : 'success'}`} aria-live="polite">
            {message}
          </p>
        )}
      </form>
    </Resource>
  )
}

export function RemediationForm({ api }) {
  const [message, setMessage] = useState('')
  const [isError, setIsError] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    const values = Object.fromEntries(new FormData(event.currentTarget))
    setMessage('Queueing remediation…')
    setIsError(false)
    try {
      const result = await api.exporterRemediation(values.deviceId, values.action, values.reason)
      setMessage(`Request ${result.id} queued for the exporter worker.`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error))
      setIsError(true)
    }
  }

  return (
    <Resource
      title="Exporter remediation"
      copy="Queue a retry, reconnect, or flush request for the authenticated tenant. Execution is explicitly worker-backed and auditable."
    >
      <form className="action-form" onSubmit={submit}>
        <label>
          Device ID
          <input name="deviceId" required placeholder="prod-api-01" />
        </label>
        <label>
          Action
          <select name="action" defaultValue="retry" className="form-select">
            <option value="retry">Retry failed exports</option>
            <option value="reconnect">Reconnect exporter</option>
            <option value="flush">Flush pending queue</option>
          </select>
        </label>
        <label>
          Reason
          <input name="reason" placeholder="Why is remediation needed?" />
        </label>
        <button type="submit" className="primary">Queue remediation</button>
        {message && (
          <p className={`form-message ${isError ? 'error' : 'success'}`} aria-live="polite">
            {message}
          </p>
        )}
      </form>
    </Resource>
  )
}

function EvidenceControls({ api, rows }) {
  const [destination, setDestination] = useState('integrity')
  const [retention, setRetention] = useState('90')
  const [autoRetry, setAutoRetry] = useState(true)
  const [message, setMessage] = useState('')
  const live = rows.find((row) => row.status?.exporter)?.status?.exporter || {}
  const save = async (event) => {
    event.preventDefault()
    setMessage('Saving evidence controls…')
    try {
      const current = await api.settings()
      await api.saveSettings({ ...(current.settings || {}), evidenceDestination: destination, evidenceRetention: Number(retention), evidenceAutoRetry: autoRetry })
      setMessage('Evidence controls saved to the tenant control plane. Endpoint adoption requires configuration distribution.')
    } catch (error) { setMessage(error instanceof Error ? error.message : String(error)) }
  }
  const verified = live.backend_evidence?.verified === true
  return <form className="settings-card evidence-controls" onSubmit={save}><div className="settings-card-header"><div className="settings-card-title"><Database size={18} /><h3>Export, queue, and verification</h3></div><span className="live-status-pill"><span className={`status-dot ${verified ? 'green' : 'yellow'}`} /> {verified ? 'Receipt verified' : 'Verification unverified'}</span></div><p className="settings-card-desc">Configure where decisions are sent and how the endpoint recovers from transient delivery failures. Queue depth, spool state, and receipt verification are separate signals.</p><div className="settings-fields-grid"><div className="field-group"><label htmlFor="evidence-destination">Evidence destination</label><select id="evidence-destination" value={destination} onChange={(event) => setDestination(event.target.value)}><option value="integrity">Integrity Protocol</option><option value="siem">SIEM webhook</option><option value="both">Integrity + SIEM</option></select></div><div className="field-group"><label htmlFor="evidence-retention">Local retention</label><select id="evidence-retention" value={retention} onChange={(event) => setRetention(event.target.value)}><option value="30">30 days</option><option value="90">90 days</option><option value="365">365 days</option></select></div></div><label className="toggle-item"><input type="checkbox" checked={autoRetry} onChange={(event) => setAutoRetry(event.target.checked)} /><div><b>Retry transient delivery failures</b><p>Use the bounded worker queue; never bypass authentication or TLS verification.</p></div></label><div className="evidence-runtime-strip"><span><b>Queue depth</b>{live.queue_depth ?? '—'}</span><span><b>Spool pending</b>{live.spool_pending ?? '—'}</span><span><b>Failures</b>{live.export_failures ?? '—'}</span><span><b>Verification</b>{verified ? (live.backend_evidence.receipt_id || 'verified') : 'unverified'}</span></div><div className="settings-actions-footer"><button type="submit" className="primary-btn"><Save size={14} /> Save evidence controls</button>{message && <span className="form-message" aria-live="polite"><CheckCircle2 size={14} /> {message}</span>}</div></form>
}

function WorkspaceTabs({ tabs, active, onChange }) {
  return (
    <div className="workspace-tabs" role="tablist" aria-label="Workspace sections">
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
          {tab.count !== undefined && <span>{tab.count}</span>}
        </button>
      ))}
    </div>
  )
}

function WorkspaceHeader({ eyebrow, title, copy }) {
  return <div className="workspace-header"><p className="eyebrow">{eyebrow}</p><h2>{title}</h2><p>{copy}</p></div>
}

function DeviceInventory({ data, api, refresh }) {
  const [deviceDetail, setDeviceDetail] = useState(null)
  const openDevice = async (device) => {
    const deviceId = device.device_id || device.id
    setDeviceDetail({ loading: true, device_id: deviceId })
    try {
      const detail = await api.device(deviceId)
      setDeviceDetail({ loading: false, ...detail })
    } catch (error) {
      setDeviceDetail({ loading: false, device_id: deviceId, error: error instanceof Error ? error.message : String(error) })
    }
  }
  return <>
    <Resource title="Fleet inventory" copy="Tenant-scoped enrolled endpoints and their current attestation state">
      {data.devices.length === 0 ? <div className="empty resource-empty-state" role="status"><HardDrive aria-hidden="true" /><h3>No enrolled endpoints returned</h3><p>The control plane did not return a device inventory for this tenant. Aggregate event counts are shown separately and do not prove that an endpoint record is available here.</p><button type="button" className="secondary-btn" onClick={refresh}>Refresh inventory</button></div> : <div className="cards">
        {data.devices.map((d, i) => (
          <button type="button" className="resource-card device-card-button" key={d.device_id || d.id || i} onClick={() => openDevice(d)}>
            <HardDrive aria-hidden="true" />
            <div><h3>{d.device_id || d.name || 'Unnamed device'}</h3><p>{d.device_role || d.os || 'Endpoint'} · {d.policy_version ? `Policy: ${d.policy_version} · ` : ''}{d.last_seen_at || d.enrolled_at || d.last_seen || 'active'}</p></div>
            <span className={`status-pill ${d.status || 'enrolled'}`}>{d.status || 'enrolled'}</span>
          </button>
        ))}
      </div>}
    </Resource>
    <ActionForm title="Enroll a device" copy="Issue a tenant-scoped device credential and configuration bundle." fields={[['deviceId', 'Device ID'], ['deviceRole', 'Device role']]} buttonText="Enroll device" successText="Device enrolled successfully." submit={async (values) => { await api.enrollDevice(values.deviceId, values.deviceRole || 'workstation'); await refresh() }} />
    {deviceDetail && <aside className="device-detail-backdrop" role="presentation" onClick={() => setDeviceDetail(null)}><section className="device-detail-drawer" role="dialog" aria-modal="true" aria-label="Device details" onClick={(event) => event.stopPropagation()}>
      <header className="device-detail-header"><div><p className="eyebrow">DEVICE DETAIL</p><h2>{deviceDetail.device_id}</h2><span>{deviceDetail.device_role || 'Endpoint'} · {deviceDetail.status || 'enrolled'}</span></div><button type="button" className="drawer-close" aria-label="Close device details" onClick={() => setDeviceDetail(null)}><X aria-hidden="true" /></button></header>
      {deviceDetail.loading ? <p className="device-detail-loading">Loading authenticated device state…</p> : deviceDetail.error ? <p className="form-message error" role="alert">Unable to load device details: {deviceDetail.error}</p> : <div className="device-detail-content"><div className="device-detail-summary"><ShieldCheck size={20} /><span><b>Policy</b><small>{deviceDetail.policy_version || 'No policy deployed'}</small></span></div><div className="device-detail-summary"><Activity size={20} /><span><b>Last seen</b><small>{deviceDetail.last_seen_at || 'Not reported'}</small></span></div><dl className="device-detail-grid">{['device_role', 'agent_label', 'ip_address', 'kernel_version', 'ebpf_sensor', 'did'].map((key) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{deviceDetail[key] || '—'}</dd></div>)}</dl></div>}
    </section></aside>}
  </>
}

function AgentWorkspace({ data, api, refresh }) {
  return <>
    <WorkspaceHeader eyebrow="OPERATIONS / AGENT" title="Agent" copy="Bind devices, local Shield enforcement, and the redacted Hermes reasoning boundary in one operator workspace." />
    <div className="agent-unified-workspace">
      <section className="agent-unified-section" aria-labelledby="agent-inventory-title">
        <div className="agent-unified-heading">
          <p className="eyebrow">FLEET INVENTORY</p>
          <h3 id="agent-inventory-title">Enrolled endpoints</h3>
          <p>Inspect device enrollment and open an authenticated endpoint detail view.</p>
        </div>
        <DeviceInventory data={data} api={api} refresh={refresh} />
      </section>
      <section className="agent-unified-section" aria-labelledby="agent-shield-title">
        <div className="agent-unified-heading">
          <p className="eyebrow">LOCAL ENFORCEMENT</p>
          <h3 id="agent-shield-title">Shield agent</h3>
          <p>Review the device-to-agent binding, responder readiness, and guardrail contract.</p>
        </div>
        <AgentView data={data} refresh={refresh} api={api} />
      </section>
      <section className="agent-unified-section" aria-labelledby="agent-hermes-title">
        <div className="agent-unified-heading">
          <p className="eyebrow">REDACTED ANALYSIS</p>
          <h3 id="agent-hermes-title">Hermes agent</h3>
          <p>Configure the analysis-only cloud boundary and its authenticated local spool.</p>
        </div>
        <HermesAgentView api={api} data={data} />
      </section>
    </div>
  </>
}

function NetworkWorkspace({ api }) {
  return <><WorkspaceHeader eyebrow="NETWORK SHIELD · PREVIEW" title="What can the network control plane touch?" copy="Protected zones and blast-radius limits for network containment. Hermes remains analysis-only here too; production adapters are not enabled from this console." /><NetworkView api={api} /></>
}

function EvidenceMetricStrip({ data }) {
  const summary = data.summary || {}
  const metrics = summary.latest_metrics || {}
  const rows = data.exporter || []
  const exporter = rows.map((row) => row.status?.exporter || {}).filter(Boolean)
  const queue = exporter.reduce((total, item) => total + Number(item.queue_depth || item.spool_pending || 0), 0)
  const failures = exporter.reduce((total, item) => total + Number(item.export_failures || 0), 0)
  const signed = metrics.signed_decisions ?? summary.signed_decisions ?? summary.total_decisions ?? '—'
  const success = metrics.export_success_rate ?? metrics.evidence_export_success_rate ?? summary.export_success_rate
  const chain = metrics.local_log_chain || summary.local_log_chain || '—'
  const cards = [
    ['Signed decisions', signed, 'accepted by bcc_middleware'],
    ['Export success', success == null ? '—' : `${Number(success).toFixed(1)}%`, 'selected telemetry window'],
    ['Spool pending', queue || '—', rows.length ? 'authenticated exporter state' : 'not reported'],
    ['Export failures', failures, 'worker-reported failures'],
    ['Local log chain', chain, 'receipt integrity state'],
  ]
  return <div className="evidence-reference-metrics" aria-label="Evidence summary metrics">{cards.map(([label, value, detail]) => <article key={label}><span>{label}</span><b>{value}</b><small>{detail}</small></article>)}</div>
}

function AuditPacketBuilder({ data }) {
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [message, setMessage] = useState('')
  const [include, setInclude] = useState({ decisions: true, outcomes: true, policies: true, settings: true })
  const generate = (event) => {
    event.preventDefault()
    const packet = {
      generated_at: new Date().toISOString(),
      window: { from: from || null, to: to || null },
      includes: include,
      decisions: include.decisions ? data.summary?.latest_decisions || [] : [],
      enforcement_outcomes: include.outcomes ? data.outcomes || [] : [],
      exporter_status: data.exporter || [],
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(packet, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'shield-audit-packet.json'
    anchor.click()
    URL.revokeObjectURL(url)
    setMessage('Audit packet generated from the authenticated records currently loaded in Shield.')
  }
  return <form className="settings-card audit-packet-builder" onSubmit={generate}><div className="settings-card-header"><div className="settings-card-title"><FileCheck2 size={18} /><h3>Build an audit packet</h3></div><span className="live-status-pill">Local export</span></div><p className="settings-card-desc">Bundle decisions, outcomes, policy history, and settings audit records for the selected telemetry window.</p><div className="settings-fields-grid"><div className="field-group"><label htmlFor="audit-from">From</label><input id="audit-from" type="date" value={from} onChange={(event) => setFrom(event.target.value)} /></div><div className="field-group"><label htmlFor="audit-to">To</label><input id="audit-to" type="date" value={to} onChange={(event) => setTo(event.target.value)} /></div></div><div className="audit-packet-options">{[['decisions', 'Policy decisions'], ['outcomes', 'Enforcement outcomes'], ['policies', 'Policy version history'], ['settings', 'Settings audit trail']].map(([key, label]) => <label key={key}><input type="checkbox" checked={include[key]} onChange={(event) => setInclude((current) => ({ ...current, [key]: event.target.checked }))} />{label}</label>)}</div><button type="submit" className="primary-btn">Generate packet</button>{message && <p className="form-message success" aria-live="polite">{message}</p>}</form>
}

function DecisionsWorkspace({ data, api, refresh, timeRange }) {
  const [tab, setTab] = useState('events')
  return <><WorkspaceHeader eyebrow="GOVERNANCE / DECISIONS" title="Decisions" copy="Review observed activity, policy evaluation, approvals, and enforcement outcomes as one auditable decision record." /><WorkspaceTabs active={tab} onChange={setTab} tabs={[{ id: 'policy-enforcement', label: 'Policy & enforcement', count: data.outcomes.length }, { id: 'events', label: 'Event stream' }, { id: 'approvals', label: 'Approvals & guardrails' }]} />{tab === 'policy-enforcement' ? <div className="decisions-policy-workspace"><section className="decisions-policy-section" aria-labelledby="decisions-policy-title"><div className="decisions-policy-heading"><p className="eyebrow">POLICY AUTHORITY</p><h3 id="decisions-policy-title">Policy catalog</h3><p>Review tenant-scoped enforcement profiles and select the policy source used by Shield.</p></div><PoliciesView data={data} api={api} refresh={refresh} /></section><section className="decisions-policy-section" aria-labelledby="decisions-enforcement-title"><div className="decisions-policy-heading"><p className="eyebrow">ENFORCEMENT OUTCOMES</p><h3 id="decisions-enforcement-title">Containment &amp; enforcement</h3><p>Configure approval boundaries and inspect every recorded enforcement outcome.</p></div><ContainmentView outcomes={data.outcomes} api={api} data={data} /></section></div> : tab === 'events' ? <EventStreamView data={data} timeRange={timeRange} /> : <div className="decisions-approvals-workspace"><section className="decisions-approvals-section" aria-labelledby="decisions-guardrails-title"><div className="decisions-approvals-heading"><p className="eyebrow">CHANGE GOVERNANCE</p><h3 id="decisions-guardrails-title">Containment &amp; guardrail approvals</h3><p>Review high-impact settings changes and their explicit approval state.</p></div><SettingsChangeQueue api={api} /></section><section className="decisions-approvals-section" aria-labelledby="decisions-transactions-title"><div className="decisions-approvals-heading"><p className="eyebrow">TRANSACTION CONTROL</p><h3 id="decisions-transactions-title">Approvals &amp; transactions</h3><p>Inspect transaction intents and operator approval requirements in the same governance view.</p></div><TransactionWorkbench api={api} /></section></div>}</>
}

function EvidenceWorkspace({ data, api }) {
  return <>
    <WorkspaceHeader eyebrow="ASSURANCE / EVIDENCE" title="Evidence" copy="Confirm what Shield observed, what was exported, and what the evidence supports. Synthetic fallback data stays hidden." />
    <div className="evidence-unified-workspace">
      <section className="evidence-unified-section" aria-labelledby="evidence-exporter-title">
        <div className="evidence-unified-heading">
          <p className="eyebrow">EXPORT ASSURANCE</p>
          <h3 id="evidence-exporter-title">Evidence &amp; exporter</h3>
          <p>Review signed decisions, exporter state, receipt verification, and remediation controls.</p>
        </div>
        <EvidenceMetricStrip data={data} />
        <div className="evidence-reference-grid"><Resource title="Exporter status by device" copy="DID preflight, queue, and receipt publication"><JsonRows rows={data.exporter} /></Resource><AuditPacketBuilder data={data} /></div>
        <EvidenceControls api={api} rows={data.exporter || []} />
        <RemediationForm api={api} />
      </section>
      <section className="evidence-unified-section" aria-labelledby="evidence-quality-title">
        <div className="evidence-unified-heading">
          <p className="eyebrow">DETECTION ASSURANCE</p>
          <h3 id="evidence-quality-title">Detection quality</h3>
          <p>Inspect labeled runtime coverage and generate a verification report.</p>
        </div>
        <DetectionQualityView data={data.quality} summary={data.summary} api={api} />
      </section>
    </div>
  </>
}

function ConfigurationWorkspace({ connection, logout, theme, onThemeChange, data, api, refresh }) {
  return <>
    <WorkspaceHeader eyebrow="CONFIGURATION" title="What is the fleet configured to do?" copy="Signed policy bundles, response boundaries, guardrails, and destinations. Containment and guardrail changes go through two-step approval and can be rolled back." />
    <div className="configuration-unified">
      <section className="configuration-section" aria-labelledby="configuration-policies-title">
        <div className="configuration-section-heading">
          <p className="eyebrow">PRESELECTED POLICY BUNDLES</p>
          <h3 id="configuration-policies-title">Policy bundle</h3>
          <p>Select from three pre-engineered zero-trust policy profiles, deploy to enrolled devices, or inspect rollback history.</p>
        </div>
        <PoliciesView data={data} api={api} refresh={refresh} />
      </section>
      <section className="configuration-section" aria-labelledby="configuration-integrations-title">
        <div className="configuration-section-heading">
          <p className="eyebrow">DELIVERY & CONNECTORS</p>
          <h3 id="configuration-integrations-title">Integrations</h3>
          <p>Configure SIEM, SOAR, and event delivery boundaries.</p>
        </div>
        <IntegrationsView data={data} api={api} refresh={refresh} />
      </section>
      <section className="configuration-section" aria-labelledby="configuration-opa-title">
        <div className="configuration-section-heading">
          <p className="eyebrow">LOCAL POLICY ENGINE</p>
          <h3 id="configuration-opa-title">OPA policies</h3>
          <p>Inspect the policy sources and evaluation contract used by Shield.</p>
        </div>
        <OpaPoliciesView api={api} />
      </section>
      <section className="configuration-section" aria-labelledby="configuration-developer-title">
        <div className="configuration-section-heading">
          <p className="eyebrow">ADVANCED ACCESS</p>
          <h3 id="configuration-developer-title">Developer contract & API explorer</h3>
          <p>Test authenticated control-plane contracts and inspect developer diagnostics.</p>
        </div>
        <DeveloperView connection={connection} />
      </section>
    </div>
  </>
}

export function ResourceView({ view, data, api, refresh, connection, logout, theme, onThemeChange, timeRange }) {
  if (view === 'agent') return <AgentWorkspace data={data} api={api} refresh={refresh} />
  if (view === 'network') return <NetworkWorkspace api={api} />
  if (view === 'decisions') return <DecisionsWorkspace data={data} api={api} refresh={refresh} timeRange={timeRange} />
  if (view === 'evidence') return <EvidenceWorkspace data={data} api={api} />
  if (view === 'settings') return <SettingsView connection={connection} logout={logout} data={data} theme={theme} onThemeChange={onThemeChange} />
  if (view === 'configuration') return <ConfigurationWorkspace connection={connection} logout={logout} theme={theme} onThemeChange={onThemeChange} data={data} api={api} refresh={refresh} />
  return <Resource title="Evidence" copy="Authenticated evidence records"><JsonRows rows={data.exporter} /></Resource>
}

function DetectionQualityView({ data, summary, api }) {
  const [bccUrl, setBccUrl] = useState('http://127.0.0.1:8080')
  const [oracleUrl, setOracleUrl] = useState('')
  const [report, setReport] = useState(null)
  const [message, setMessage] = useState('')
  const eventClassTotal = Object.values(summary?.event_class_counts || {}).reduce((total, count) => total + Number(count || 0), 0)
  const actionTotal = Object.values(summary?.decisions_by_action || {}).reduce((total, count) => total + Number(count || 0), 0)
  const observedEvents = eventClassTotal || actionTotal
  const securityDecisions = ['deny', 'contain', 'escalate'].reduce((total, action) => total + Number(summary?.decisions_by_action?.[action] || 0), 0)
  const agentEvents = Number(summary?.event_class_counts?.agent_event || 0)
  const generate = async (event) => { event.preventDefault(); setMessage('Generating report…'); try { setReport(await api.detectionQualityReport(bccUrl, oracleUrl)); setMessage('Report generated from authenticated detection-quality records.') } catch (error) { setMessage(error instanceof Error ? error.message : String(error)) } }
  return <><Resource title="Detection quality" copy="Measured adversarial detection and export quality">{data.length === 0 ? <div className="empty"><Activity size={28} /><h3>No labeled quality records persisted</h3><p>Runtime decisions are live, but detection quality requires authenticated samples with an operator or benchmark label and verifiable receipts.</p><small>Current evidence state: uncounted, not zero. Runtime activity is shown below without being promoted to a detection metric.</small></div> : <JsonRows rows={data} />}</Resource><Resource title="Observed runtime coverage" copy="Authenticated control-plane observations; not a precision, recall, or adversarial benchmark."><div className="quality-coverage-grid"><div><b>{observedEvents || '—'}</b><span>observed events</span></div><div><b>{securityDecisions || '—'}</b><span>security decisions</span></div><div><b>{agentEvents || '—'}</b><span>authenticated agent events</span></div></div><p className="field-hint">These counts confirm that the control plane is receiving runtime activity. They do not establish malicious ground truth or detection quality.</p></Resource><Resource title="Generate quality report" copy="Verify labeled detection-quality records against BCC middleware and optional Oracle audit data."><form className="action-form" onSubmit={generate}><label>BCC middleware URL<input value={bccUrl} onChange={(event) => setBccUrl(event.target.value)} required /></label><label>Oracle URL (optional)<input value={oracleUrl} onChange={(event) => setOracleUrl(event.target.value)} /></label><button type="submit" className="primary">Generate report</button><p className="form-message" aria-live="polite">{message}</p></form>{report && <pre className="report-preview">{JSON.stringify(report, null, 2)}</pre>}</Resource></>
}
