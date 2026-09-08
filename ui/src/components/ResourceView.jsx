import { useState } from 'react'
import { HardDrive, X, ShieldCheck, Activity, Database, Save, CheckCircle2 } from 'lucide-react'
import { ActionForm, JsonRows, Resource } from './Common'
import { ContainmentView } from './ContainmentView'
import { OpaPoliciesView } from './OpaPoliciesView';



import { EventStreamView } from './EventStreamView'
import { PoliciesView } from './PoliciesView'
import { IntegrationsView } from './IntegrationsView'
import { DeveloperView } from './DeveloperView'
import { SettingsView } from './SettingsView'
import { TransactionWorkbench } from './TransactionWorkbench'
import { AgentView } from './AgentView'

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
  return <form className="settings-card evidence-controls" onSubmit={save}><div className="settings-card-header"><div className="settings-card-title"><Database size={18} /><h3>Export, queue, and verification</h3></div><span className="live-status-pill"><span className="status-dot green" /> Evidence path</span></div><p className="settings-card-desc">Configure where decisions are sent and how the endpoint recovers from transient delivery failures. Queue state is read from authenticated runtime status.</p><div className="settings-fields-grid"><div className="field-group"><label htmlFor="evidence-destination">Evidence destination</label><select id="evidence-destination" value={destination} onChange={(event) => setDestination(event.target.value)}><option value="integrity">Integrity Protocol</option><option value="siem">SIEM webhook</option><option value="both">Integrity + SIEM</option></select></div><div className="field-group"><label htmlFor="evidence-retention">Local retention</label><select id="evidence-retention" value={retention} onChange={(event) => setRetention(event.target.value)}><option value="30">30 days</option><option value="90">90 days</option><option value="365">365 days</option></select></div></div><label className="toggle-item"><input type="checkbox" checked={autoRetry} onChange={(event) => setAutoRetry(event.target.checked)} /><div><b>Retry transient delivery failures</b><p>Use the bounded worker queue; never bypass authentication or TLS verification.</p></div></label><div className="evidence-runtime-strip"><span><b>Queue depth</b>{live.queue_depth ?? '—'}</span><span><b>Spool pending</b>{live.spool_pending ?? '—'}</span><span><b>Failures</b>{live.export_failures ?? '—'}</span><span><b>Verification</b>{live.backend_evidence?.publish_failures === 0 ? 'Publishing' : 'Unverified'}</span></div><div className="settings-actions-footer"><button type="submit" className="primary-btn"><Save size={14} /> Save evidence controls</button>{message && <span className="form-message" aria-live="polite"><CheckCircle2 size={14} /> {message}</span>}</div></form>
}

export function ResourceView({ view, data, api, refresh, connection, logout }) {
  const [deviceDetail, setDeviceDetail] = useState(null)

  if (view === 'devices') {
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
    return (
      <>
        <Resource title="Devices" copy="Tenant-scoped enrolled endpoints">
          <div className="cards">
            {data.devices.map((d, i) => (
              <button type="button" className="resource-card device-card-button" key={d.device_id || d.id || i} onClick={() => openDevice(d)}>
                <HardDrive aria-hidden="true" />
                <div>
                  <h3>{d.device_id || d.name || 'Unnamed device'}</h3>
                  <p>
                    {d.device_role || d.os || 'Endpoint'} · {d.policy_version ? `Policy: ${d.policy_version} · ` : ''}{d.last_seen_at || d.enrolled_at || d.last_seen || 'active'}
                  </p>
                </div>
                <span className={`status-pill ${d.status || 'enrolled'}`}>{d.status || 'enrolled'}</span>
              </button>
            ))}
          </div>
        </Resource>
        <ActionForm
          title="Enroll a device"
          copy="Issue a tenant-scoped device credential and configuration bundle."
          fields={[
            ['deviceId', 'Device ID'],
            ['deviceRole', 'Device role'],
          ]}
          buttonText="Enroll device"
          successText="Device enrolled successfully."
          submit={async (values) => {
            await api.enrollDevice(values.deviceId, values.deviceRole || 'workstation')
            await refresh()
          }}
        />
        {deviceDetail && (
          <aside className="device-detail-backdrop" role="presentation" onClick={() => setDeviceDetail(null)}>
            <section className="device-detail-drawer" role="dialog" aria-modal="true" aria-label="Device details" onClick={(event) => event.stopPropagation()}>
              <header className="device-detail-header">
                <div>
                  <p className="eyebrow">DEVICE DETAIL</p>
                  <h2>{deviceDetail.device_id}</h2>
                  <span>{deviceDetail.device_role || 'Endpoint'} · {deviceDetail.status || 'enrolled'}</span>
                </div>
                <button type="button" className="drawer-close" aria-label="Close device details" onClick={() => setDeviceDetail(null)}><X aria-hidden="true" /></button>
              </header>
              {deviceDetail.loading ? <p className="device-detail-loading">Loading authenticated device state…</p> : deviceDetail.error ? <p className="form-message error" role="alert">Unable to load device details: {deviceDetail.error}</p> : (
                <div className="device-detail-content">
                  <div className="device-detail-summary"><ShieldCheck size={20} /><span><b>Policy</b><small>{deviceDetail.policy_version || 'No policy deployed'}</small></span></div>
                  <div className="device-detail-summary"><Activity size={20} /><span><b>Last seen</b><small>{deviceDetail.last_seen_at || 'Not reported'}</small></span></div>
                  <dl className="device-detail-grid">
                    {['device_role', 'agent_label', 'ip_address', 'kernel_version', 'ebpf_sensor', 'did'].map((key) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{deviceDetail[key] || '—'}</dd></div>)}
                  </dl>
                </div>
              )}
            </section>
          </aside>
        )}
      </>
    )
  }

  if (view === 'agent') {
    return <AgentView data={data} refresh={refresh} api={api} />
  }

  if (view === 'enforcement') {
    return <ContainmentView outcomes={data.outcomes} api={api} data={data} />
  }

  if (view === 'events') {
    return <EventStreamView data={data} />
  }

  if (view === 'evidence') {
    return (
      <>
        <Resource
          title="Evidence & exporter"
          copy="DID preflight, sensor, queue, and receipt publication status"
        >
          <JsonRows rows={data.exporter} />
        </Resource>
        <EvidenceControls api={api} rows={data.exporter || []} />
        <RemediationForm api={api} />
      </>
    )
  }

  if (view === 'transactions') {
    return <TransactionWorkbench api={api} />
  }

  if (view === 'integrations') {
    return <IntegrationsView data={data} api={api} refresh={refresh} />
  }

  if (view === 'settings') {
    return <SettingsView connection={connection} logout={logout} data={data} />
  }

  if (view === 'developer') {
    return <DeveloperView connection={connection} />;
  }

  if (view === 'opa') {
    return <OpaPoliciesView api={api} />;
  }

  if (view === 'policies') {
    return <PoliciesView data={data} api={api} refresh={refresh} />;
  }

  if (view === 'quality') {
    return <DetectionQualityView data={data.quality} api={api} />
  }

  return (
    <Resource title="Detection quality" copy="Measured adversarial detection and export quality">
      <JsonRows rows={data.quality} />
    </Resource>
  )
}

function DetectionQualityView({ data, api }) {
  const [bccUrl, setBccUrl] = useState('http://127.0.0.1:8080')
  const [oracleUrl, setOracleUrl] = useState('')
  const [report, setReport] = useState(null)
  const [message, setMessage] = useState('')
  const generate = async (event) => { event.preventDefault(); setMessage('Generating report…'); try { setReport(await api.detectionQualityReport(bccUrl, oracleUrl)); setMessage('Report generated from authenticated detection-quality records.') } catch (error) { setMessage(error instanceof Error ? error.message : String(error)) } }
  return <><Resource title="Detection quality" copy="Measured adversarial detection and export quality"><JsonRows rows={data} /></Resource><Resource title="Generate quality report" copy="Verify detection-quality records against BCC middleware and optional Oracle audit data."><form className="action-form" onSubmit={generate}><label>BCC middleware URL<input value={bccUrl} onChange={(event) => setBccUrl(event.target.value)} required /></label><label>Oracle URL (optional)<input value={oracleUrl} onChange={(event) => setOracleUrl(event.target.value)} /></label><button type="submit" className="primary">Generate report</button><p className="form-message" aria-live="polite">{message}</p></form>{report && <pre className="report-preview">{JSON.stringify(report, null, 2)}</pre>}</Resource></>
}
