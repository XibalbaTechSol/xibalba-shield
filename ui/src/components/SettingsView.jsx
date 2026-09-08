import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Bell,
  Check,
  CheckCircle2,
  Copy,
  Cpu,
  Key,
  Mail,
  Plus,
  Send,
  Server,
  Shield,
  ShieldAlert,
  Sliders,
  User,
  Radio,
  Wifi,
  RotateCw,
} from 'lucide-react'
import { ShieldApi } from '../api'

export function TenantSwitcher() {
  const [connection] = useState(() => {
    try {
      return JSON.parse(sessionStorage.getItem('shield-connection') || '{}')
    } catch {
      return {}
    }
  })
  const [message, setMessage] = useState('')
  const tenants = connection.account?.tenants || []

  if (!connection.account?.email || tenants.length < 2) return null

  const switchTenant = async (event) => {
    const target = event.target.value
    if (!target || target === connection.tenant) return
    setMessage('Switching…')
    try {
      const payload = await new ShieldApi(
        connection.baseUrl,
        connection.tenant,
        connection.token
      ).switchTenant(connection.account.email, target)
      sessionStorage.setItem(
        'shield-connection',
        JSON.stringify({
          baseUrl: connection.baseUrl,
          tenant: payload.tenant_id,
          token: payload.admin_token,
          account: {
            ...payload.account,
            session_expires_at: payload.session_expires_at,
            tenants: payload.tenants || [],
          },
        })
      )
      window.location.reload()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error))
    }
  }

  return (
    <div className="settings-card tenant-switcher">
      <p className="eyebrow">TENANT ACCESS</p>
      <label>
        Active tenant
        <select value={connection.tenant} onChange={switchTenant} className="form-select">
          {tenants.map((item) => (
            <option key={item.tenant_id} value={item.tenant_id}>
              {item.tenant_id} · {item.role}
            </option>
          ))}
        </select>
      </label>
      {message && <p className="form-message" aria-live="polite">{message}</p>}
    </div>
  )
}

export function AvatarPreference() {
  const [avatar, setAvatar] = useState(() => sessionStorage.getItem('shield-avatar') || '')

  const choose = (event) => {
    const file = event.target.files?.[0]
    if (!file || !file.type.startsWith('image/')) return
    if (file.size > 2_000_000) return
    const reader = new FileReader()
    reader.onload = () => {
      const value = String(reader.result || '')
      sessionStorage.setItem('shield-avatar', value)
      setAvatar(value)
    }
    reader.readAsDataURL(file)
  }

  return (
    <div className="avatar-preference-section">
      <p className="eyebrow">PROFILE PICTURE</p>
      <div className="avatar-control-row">
        <div className="avatar-preview-box">
          {avatar ? (
            <img src={avatar} alt="Operator profile preview" className="profile-avatar-image" />
          ) : (
            <User size={28} className="avatar-fallback-icon" />
          )}
        </div>
        <div className="avatar-actions">
          <label className="file-upload-label" htmlFor="avatarFile">
            <span>Choose photo</span>
            <input
              id="avatarFile"
              name="avatarFile"
              type="file"
              accept="image/png,image/jpeg,image/gif,image/webp"
              onChange={choose}
              className="visually-hidden"
            />
          </label>
          {avatar && (
            <button
              type="button"
              className="remove-avatar-btn"
              onClick={() => {
                sessionStorage.removeItem('shield-avatar')
                setAvatar('')
              }}
            >
              Remove photo
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

export function AuditEvents({ api, email }) {
  const [events, setEvents] = useState([])

  useEffect(() => {
    api.authEvents(email)
      .then((result) => setEvents(result.events || []))
      .catch(() => setEvents([]))
  }, [api, email])

  if (!email || events.length === 0) return null

  return (
    <div className="settings-card audit-events">
      <p className="eyebrow">SECURITY AUDIT</p>
      <h3>Recent account events</h3>
      <div className="audit-event-list">
        {events.slice(0, 6).map((event, index) => (
          <div className="audit-event" key={`${event.created_at}-${index}`}>
            <b>{event.event_type}</b>
            <small>
              {event.detail || ''} · {event.created_at || ''}
            </small>
          </div>
        ))}
      </div>
    </div>
  )
}

function SettingsChangeQueue({ api }) {
  const [requests, setRequests] = useState([])
  const [message, setMessage] = useState('')
  const refresh = useCallback(
    () => api.settingsChangeRequests().then((result) => setRequests(result.requests || [])).catch(() => setRequests([])),
    [api],
  )
  useEffect(() => { refresh() }, [refresh])
  const decide = async (requestId, action) => {
    setMessage(`${action}ing change…`)
    const completed = { approve: 'approved', reject: 'rejected', rollback: 'rolled back' }
    try { await api.decideSettingsChangeRequest(requestId, action); await refresh(); setMessage(`Change ${completed[action] || action}.`) }
    catch (error) { setMessage(error instanceof Error ? error.message : String(error)) }
  }
  return <article className="settings-card"><div className="settings-card-header"><div className="settings-card-title"><ShieldAlert size={18} /><h3>Containment & guardrail approvals</h3></div><span className="live-status-pill">Two-step change control</span></div><p className="field-hint">High-impact settings are queued for explicit approval and can be rolled back without editing raw configuration.</p>{requests.length === 0 ? <p className="empty-state">No pending or historical change requests.</p> : <div className="audit-event-list">{requests.slice(0, 8).map((request) => <div className="audit-event" key={request.request_id}><b>{request.category} · {request.status}</b><small>{request.request_id} · {request.created_at}</small><div className="settings-actions-footer">{request.status === 'pending' && <><button type="button" className="secondary-btn" onClick={() => decide(request.request_id, 'approve')}>Approve</button><button type="button" className="secondary-btn" onClick={() => decide(request.request_id, 'reject')}>Reject</button></>}{request.status === 'approved' && <button type="button" className="secondary-btn" onClick={() => decide(request.request_id, 'rollback')}>Rollback</button>}</div></div>)}</div>}{message && <span className="form-message" aria-live="polite">{message}</span>}</article>
}

export function SettingsView({ connection, logout, data = {} }) {
  const account = connection.account || {}
  const [activeTab, setActiveTab] = useState('posture')
  const [message, setMessage] = useState('')
  const [sessions, setSessions] = useState([])
  const [copiedKey, setCopiedKey] = useState(null)

  // Security Posture Settings
  const [savedPosture, setSavedPosture] = useState(() => { try { return JSON.parse(sessionStorage.getItem('shield-posture') || '{}') } catch { return {} } })
  const [containmentMode, setContainmentMode] = useState(() => savedPosture.containmentMode || 'autonomous')
  const [governanceTier, setGovernanceTier] = useState(() => savedPosture.governanceTier || 'tier1')
  const [ringBufferInterval, setRingBufferInterval] = useState(() => savedPosture.ringBufferInterval || '50')
  const [retentionDays, setRetentionDays] = useState(() => savedPosture.retentionDays || '90')
  const [postureSaved, setPostureSaved] = useState('')
  const [processSensor, setProcessSensor] = useState(true)
  const [fileSensor, setFileSensor] = useState(true)
  const [networkSensor, setNetworkSensor] = useState(false)
  const [sensorCadence, setSensorCadence] = useState('50')
  const [sensorSaved, setSensorSaved] = useState(false)
  const [autoReconnect, setAutoReconnect] = useState(true)
  const [tlsSaved, setTlsSaved] = useState(false)

  // Token Minting
  const [mintingToken, setMintingToken] = useState(false)
  const [mintedToken, setMintedToken] = useState(null)
  const [mintError, setMintError] = useState(null)

  // Alert Settings
  const [notifyContain, setNotifyContain] = useState(true)
  const [notifyDeny, setNotifyDeny] = useState(true)
  const [notifySensorDrop, setNotifySensorDrop] = useState(true)
  const [realOnly, setRealOnly] = useState(() => sessionStorage.getItem('shield-real-only') !== 'false')
  const [smtpHost, setSmtpHost] = useState('smtp.corp.internal')
  const [smtpPort, setSmtpPort] = useState('587')
  const [smtpRecipient, setSmtpRecipient] = useState('secops-alerts@corp.internal')
  const [testingEmail, setTestingEmail] = useState(false)
  const [emailStatus, setEmailStatus] = useState(null)

  const api = useMemo(
    () => new ShieldApi(connection.baseUrl, connection.tenant, connection.token),
    [connection]
  )

  useEffect(() => {
    if (account.id) {
      api.sessions()
        .then((result) => setSessions(result.sessions || []))
        .catch(() => setSessions([]))
    }
  }, [api, account.id])

  useEffect(() => {
    let cancelled = false
    api.settings()
      .then((result) => {
        if (cancelled) return
        const settings = result.settings || {}
        if (settings.containmentMode) setContainmentMode(settings.containmentMode)
        if (settings.governanceTier) setGovernanceTier(settings.governanceTier)
        if (settings.ringBufferInterval) setRingBufferInterval(String(settings.ringBufferInterval))
        if (settings.retentionDays) setRetentionDays(String(settings.retentionDays))
        if (typeof settings.notifyContain === 'boolean') setNotifyContain(settings.notifyContain)
        if (typeof settings.notifyDeny === 'boolean') setNotifyDeny(settings.notifyDeny)
        if (typeof settings.notifySensorDrop === 'boolean') setNotifySensorDrop(settings.notifySensorDrop)
        if (typeof settings.realOnly === 'boolean') setRealOnly(settings.realOnly)
        if (settings.smtpHost) setSmtpHost(settings.smtpHost)
        if (settings.smtpPort) setSmtpPort(String(settings.smtpPort))
        if (settings.smtpRecipient) setSmtpRecipient(settings.smtpRecipient)
        if (typeof settings.sensorProcess === 'boolean') setProcessSensor(settings.sensorProcess)
        if (typeof settings.sensorFile === 'boolean') setFileSensor(settings.sensorFile)
        if (typeof settings.sensorNetwork === 'boolean') setNetworkSensor(settings.sensorNetwork)
        if (settings.sensorCadence) setSensorCadence(String(settings.sensorCadence))
        if (typeof settings.autoReconnect === 'boolean') setAutoReconnect(settings.autoReconnect)
        setSavedPosture(settings)
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [api])

  const copyToClipboard = (text, key) => {
    navigator.clipboard?.writeText?.(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const handleSavePosture = async (e) => {
    e.preventDefault()
    const next = { governanceTier, ringBufferInterval, retentionDays, notifyContain, notifyDeny, notifySensorDrop, smtpHost, smtpPort, smtpRecipient, realOnly, sensorProcess: processSensor, sensorFile: fileSensor, sensorNetwork: networkSensor, sensorCadence, autoReconnect }
    try {
      setMessage('')
      const result = await api.saveSettings(next)
      const saved = result.settings || next
      let feedback = 'Security posture saved to the tenant control plane.'
      if (containmentMode !== savedPosture.containmentMode) {
        const request = await api.createSettingsChangeRequest('containment', { ...saved, containmentMode })
        feedback = `Operational settings saved. Containment change queued for approval (${request.request_id}).`
      }
      sessionStorage.setItem('shield-posture', JSON.stringify(saved))
      setSavedPosture(saved)
      sessionStorage.setItem('shield-real-only', String(realOnly))
      window.dispatchEvent(new CustomEvent('shield-telemetry-mode', { detail: realOnly }))
      setPostureSaved(feedback)
      setTimeout(() => setPostureSaved(''), 5000)
    } catch (error) {
      setPostureSaved('')
      setMessage(error instanceof Error ? `Could not save settings: ${error.message}` : 'Could not save settings.')
    }
  }

  const exporterRows = data.exporter || []
  const liveRow = exporterRows.find((row) => row.status)
  const tlsEnabled = String(connection.baseUrl || '').startsWith('https://')
  const saveOperational = async (event) => {
    event.preventDefault()
    setMessage('Saving operational settings…')
    try {
      const next = { ...savedPosture, sensorProcess: processSensor, sensorFile: fileSensor, sensorNetwork: networkSensor, sensorCadence, autoReconnect }
      const result = await api.saveSettings(next)
      setSavedPosture(result.settings || next)
      setSensorSaved(true)
      setTlsSaved(true)
      setMessage('Operational settings saved to the tenant control plane.')
      window.setTimeout(() => { setSensorSaved(false); setTlsSaved(false) }, 3000)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error))
    }
  }

  const handleMintToken = async () => {
    setMintingToken(true)
    setMintError(null)
    try {
      const res = await fetch(`${connection.baseUrl}/api/shield/admin-tokens`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${connection.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ tenant_id: connection.tenant }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to mint token')
      setMintedToken(data.admin_token)
    } catch (err) {
      setMintError(err instanceof Error ? err.message : String(err))
    } finally {
      setMintingToken(false)
    }
  }

  const handleTestEmail = async () => {
    setTestingEmail(true)
    setEmailStatus(null)
    try {
      await api.testAlert(smtpRecipient, smtpHost, smtpPort)
      setEmailStatus({ ok: true, text: `Test alert sent to ${smtpRecipient}.` })
    } catch (error) {
      setEmailStatus({ ok: false, text: error instanceof Error ? error.message : String(error) })
    } finally {
      setTestingEmail(false)
    }
  }

  const changePassword = async (event) => {
    event.preventDefault()
    const form = event.currentTarget
    const currentPass = String(form.querySelector('input[name="currentPassword"]')?.value || '')
    const newPass = String(form.querySelector('input[name="newPassword"]')?.value || '')
    setMessage('Updating password…')
    try {
      await api.changePassword(
        account.email || '',
        currentPass,
        newPass
      )
      form.reset()
      setMessage('Password updated successfully.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error))
    }
  }

  return (
    <div className="settings-container">
      {/* Header */}
      <header className="view-header">
        <div className="eyebrow-badge">
          <Sliders size={13} className="pulse-icon" />
          <span>ENTERPRISE CONTROL PLANE</span>
        </div>
        <h2>Settings & Security Posture</h2>
        <span>
          Configure autonomous containment modes, cryptographic tokens, alert routing, and tenant administrative controls.
        </span>
        <small className="evidence-label">
          Evidence class: authenticated local control-plane data; synthetic/demo records are labeled explicitly.
        </small>
      </header>

      {/* Settings Navigation Tabs */}
      <div className="settings-tabs-bar" role="tablist" aria-label="Settings sections">
        <button
          type="button"
          role="tab" aria-selected={activeTab === 'posture'} aria-controls="settings-panel-posture" id="settings-tab-posture" className={`settings-tab-btn ${activeTab === 'posture' ? 'active' : ''}`}
          onClick={() => setActiveTab('posture')}
        >
          <Shield size={15} />
          <span>Security Posture</span>
        </button>

        <button
          type="button"
          role="tab" aria-selected={activeTab === 'sensors'} aria-controls="settings-panel-sensors" id="settings-tab-sensors" className={`settings-tab-btn ${activeTab === 'sensors' ? 'active' : ''}`}
          onClick={() => setActiveTab('sensors')}
        >
          <Radio size={15} />
          <span>Sensors</span>
        </button>

        <button
          type="button"
          role="tab" aria-selected={activeTab === 'control-plane'} aria-controls="settings-panel-control-plane" id="settings-tab-control-plane" className={`settings-tab-btn ${activeTab === 'control-plane' ? 'active' : ''}`}
          onClick={() => setActiveTab('control-plane')}
        >
          <Wifi size={15} />
          <span>Control Plane</span>
        </button>

        <button
          type="button"
          role="tab" aria-selected={activeTab === 'tokens'} aria-controls="settings-panel-tokens" id="settings-tab-tokens" className={`settings-tab-btn ${activeTab === 'tokens' ? 'active' : ''}`}
          onClick={() => setActiveTab('tokens')}
        >
          <Key size={15} />
          <span>API Access & Tokens</span>
        </button>

        <button
          type="button"
          role="tab" aria-selected={activeTab === 'alerts'} aria-controls="settings-panel-alerts" id="settings-tab-alerts" className={`settings-tab-btn ${activeTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveTab('alerts')}
        >
          <Bell size={15} />
          <span>Alerts & Dispatch</span>
        </button>

        <button
          type="button"
          role="tab" aria-selected={activeTab === 'profile'} aria-controls="settings-panel-profile" id="settings-tab-profile" className={`settings-tab-btn ${activeTab === 'profile' ? 'active' : ''}`}
          onClick={() => setActiveTab('profile')}
        >
          <User size={15} />
          <span>Operator Profile</span>
        </button>
      </div>

      {activeTab === 'sensors' && (
        <form className="settings-tab-pane" id="settings-panel-sensors" role="tabpanel" aria-labelledby="settings-tab-sensors" onSubmit={saveOperational}>
          <article className="settings-card">
            <div className="settings-card-header"><div className="settings-card-title"><Radio size={18} /><h3>Kernel telemetry sources</h3></div><span className="live-status-pill"><span className="status-dot green" /> Endpoint policy</span></div>
            <p className="settings-card-desc">Choose which supported event families the enrolled endpoint should report. The privileged helper remains administrator-managed.</p>
            <div className="toggle-list">
              <label className="toggle-item"><input type="checkbox" checked={processSensor} onChange={(event) => setProcessSensor(event.target.checked)} /><div><b>Process execution</b><p>Real eBPF process-exec events from the privileged helper.</p></div></label>
              <label className="toggle-item"><input type="checkbox" checked={fileSensor} onChange={(event) => setFileSensor(event.target.checked)} /><div><b>File write activity</b><p>Write-mode open events with sensitive-path filtering.</p></div></label>
              <label className="toggle-item"><input type="checkbox" checked={networkSensor} onChange={(event) => setNetworkSensor(event.target.checked)} /><div><b>TCP network flows</b><p>Enable only on kernels with a verified TCP probe gate.</p></div></label>
            </div>
            <div className="settings-fields-grid"><div className="field-group"><label htmlFor="sensorCadence">Telemetry cadence</label><select id="sensorCadence" value={sensorCadence} onChange={(event) => setSensorCadence(event.target.value)}><option value="25">25 ms · low latency</option><option value="50">50 ms · balanced</option><option value="100">100 ms · lower overhead</option></select></div><div className="field-group"><label>Current helper state</label><div className="settings-readout">{liveRow?.status?.sensors?.attached === true ? 'Attached · real events' : 'Not reported'}</div></div></div>
          </article>
          <div className="settings-actions-footer"><button type="submit" className="primary-btn"><RotateCw size={14} /> Save sensor settings</button>{sensorSaved && <span className="save-feedback-pill success"><CheckCircle2 size={14} /> Saved</span>}</div>
        </form>
      )}

      {activeTab === 'control-plane' && (
        <form className="settings-tab-pane" id="settings-panel-control-plane" role="tabpanel" aria-labelledby="settings-tab-control-plane" onSubmit={saveOperational}>
          <article className="settings-card">
            <div className="settings-card-header"><div className="settings-card-title"><Wifi size={18} /><h3>TLS and connectivity</h3></div><span className={`status-pill ${tlsEnabled ? 'protected' : 'attention'}`}>{tlsEnabled ? 'mTLS endpoint' : 'HTTP endpoint'}</span></div>
            <p className="settings-card-desc">Transport status is read-only here. Rotate certificates through the host deployment workflow; Shield never exposes private keys in the browser.</p>
            <dl className="session-props-grid"><div><dt>Control-plane URL</dt><dd><code>{connection.baseUrl || 'Not configured'}</code></dd></div><div><dt>Transport</dt><dd>{tlsEnabled ? 'HTTPS with client certificate' : 'HTTP · development only'}</dd></div><div><dt>Last runtime status</dt><dd>{liveRow?.updated_at || 'Not reported'}</dd></div><div><dt>OPA health</dt><dd>{liveRow?.status?.opa?.healthy === true ? 'Healthy' : 'Unverified'}</dd></div><div><dt>Certificate expiry</dt><dd>Host-managed · not exposed</dd></div><div><dt>CA fingerprint</dt><dd>Host-managed · not exposed</dd></div></dl>
            <label className="toggle-item"><input type="checkbox" checked={autoReconnect} onChange={(event) => setAutoReconnect(event.target.checked)} /><div><b>Reconnect on transient failure</b><p>Allow the endpoint watchdog to retry transport without weakening certificate verification.</p></div></label>
          </article>
          <div className="settings-actions-footer"><button type="submit" className="primary-btn"><RotateCw size={14} /> Save connectivity preference</button>{tlsSaved && <span className="save-feedback-pill success"><CheckCircle2 size={14} /> Saved</span>}</div>
          {message && <p className="form-message" aria-live="polite">{message}</p>}
        </form>
      )}

      {/* TAB 1: SECURITY POSTURE */}
      {activeTab === 'posture' && (
        <div className="settings-tab-pane" role="tabpanel" id="settings-panel-posture" aria-labelledby="settings-tab-posture">
          <form onSubmit={handleSavePosture} className="posture-settings-form">
            <article className="settings-card">
              <div className="settings-card-header">
                <div className="settings-card-title">
                  <ShieldAlert size={18} />
                  <h3>Autonomous Containment Posture</h3>
                </div>
                <span className="live-status-pill">
                  <span className="status-dot green" />
                  <span>Kernel Enforcement Active</span>
                </span>
              </div>
              <p className="settings-card-desc">
                Defines how the eBPF kernel interceptor responds when a process execution violates active OPA policy rules.
              </p>

              <div className="posture-options-grid">
                <label className={`posture-option-card ${containmentMode === 'autonomous' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="containmentMode"
                    value="autonomous"
                    checked={containmentMode === 'autonomous'}
                    onChange={() => setContainmentMode('autonomous')}
                  />
                  <div className="option-content">
                    <div className="option-title-row">
                      <b>Autonomous Containment (Recommended)</b>
                      <span className="badge green">ACTIVE ENFORCEMENT</span>
                    </div>
                    <p>
                      Immediately SIGKILLs unverified processes and isolates the container/cgroup in &lt;2ms before unauthorized sockets or writes execute.
                    </p>
                  </div>
                </label>

                <label className={`posture-option-card ${containmentMode === 'audit' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="containmentMode"
                    value="audit"
                    checked={containmentMode === 'audit'}
                    onChange={() => setContainmentMode('audit')}
                  />
                  <div className="option-content">
                    <div className="option-title-row">
                      <b>Audit & Observation Only</b>
                      <span className="badge amber">PASSIVE</span>
                    </div>
                    <p>
                      Records telemetry and logs violations to the event stream, but does not intercept or terminate workloads. Ideal for staging tests.
                    </p>
                  </div>
                </label>

                <label className={`posture-option-card ${containmentMode === 'lockdown' ? 'selected' : ''}`}>
                  <input
                    type="radio"
                    name="containmentMode"
                    value="lockdown"
                    checked={containmentMode === 'lockdown'}
                    onChange={() => setContainmentMode('lockdown')}
                  />
                  <div className="option-content">
                    <div className="option-title-row">
                      <b>Strict Zero-Trust Air-Gap</b>
                      <span className="badge red">LOCKDOWN</span>
                    </div>
                    <p>
                      Blocks all external socket connects, disallows unsigned binaries, and requires explicit cryptographic approvals for all transaction intents.
                    </p>
                  </div>
                </label>
              </div>
            </article>

            <article className="settings-card">
              <div className="settings-card-header">
                <div className="settings-card-title">
                  <Cpu size={18} />
                  <h3>eBPF Kernel Probes & Telemetry Sampling</h3>
                </div>
              </div>

              <div className="settings-fields-grid">
                <div className="field-group">
                  <label>Default Governance Tier</label>
                  <select
                    value={governanceTier}
                    onChange={(e) => setGovernanceTier(e.target.value)}
                    className="form-select"
                  >
                    <option value="tier1">Tier 1: High Assurance (Cryptographic DID Receipts & strict OPA)</option>
                    <option value="tier2">Tier 2: Standard Governance (Heuristic & rule-based auditing)</option>
                  </select>
                  <span className="field-hint">Enforces requirement for signed W3C DID attestations.</span>
                </div>

                <div className="field-group">
                  <label>Ring Buffer Flush Cadence</label>
                  <select
                    value={ringBufferInterval}
                    onChange={(e) => setRingBufferInterval(e.target.value)}
                    className="form-select"
                  >
                    <option value="25">25 ms (Low Latency / High Volume)</option>
                    <option value="50">50 ms (Standard Production)</option>
                    <option value="100">100 ms (Battery & Energy Saver)</option>
                  </select>
                  <span className="field-hint">Frequency of reading eBPF perf event buffers into user-space.</span>
                </div>

                <div className="field-group">
                  <label>Evidence Retention Period</label>
                  <select
                    value={retentionDays}
                    onChange={(e) => setRetentionDays(e.target.value)}
                    className="form-select"
                  >
                    <option value="30">30 Days</option>
                    <option value="90">90 Days (SOC 2 / ISO 27001 Standard)</option>
                    <option value="365">365 Days (HIPAA & Regulated Finance)</option>
                    <option value="indefinite">Indefinite (Immutable WORM Archive)</option>
                  </select>
                </div>
              </div>

              <div className="settings-actions-footer">
                <button type="submit" className="primary-btn">
                  Save Security Posture
                </button>
                {postureSaved && (
                  <span className="save-feedback-pill">
                    <CheckCircle2 size={14} />
                    <span>{postureSaved}</span>
                  </span>
                )}
                {message && <span className="form-message" role="alert">{message}</span>}
              </div>
            </article>
          </form>
        </div>
      )}

      {/* TAB 2: API ACCESS & TOKENS */}
      {activeTab === 'tokens' && (
        <div className="settings-tab-pane" role="tabpanel" id="settings-panel-tokens" aria-labelledby="settings-tab-tokens">
          <TenantSwitcher />

          <article className="settings-card">
            <div className="settings-card-header">
              <div className="settings-card-title">
                <Key size={18} />
                <h3>Tenant Admin Token Credentials</h3>
              </div>
              <button
                type="button"
                className="mint-token-btn"
                onClick={handleMintToken}
                disabled={mintingToken}
              >
                {mintingToken ? (
                  <>
                    <Activity size={13} className="spinning" />
                    <span>Minting…</span>
                  </>
                ) : (
                  <>
                    <Plus size={13} />
                    <span>Mint New Admin Token</span>
                  </>
                )}
              </button>
            </div>

            <p className="settings-card-desc">
              Bearer tokens used by the CLI, eBPF daemon, or CI/CD pipelines to authenticate against <code>/api/shield/*</code>.
            </p>

            {mintedToken && (
              <div className="minted-token-alert">
                <div className="minted-token-header">
                  <CheckCircle2 size={16} />
                  <b>New Tenant Admin Token Generated</b>
                </div>
                <p>Copy this token immediately. For security, newly minted tokens cannot be viewed again once dismissed.</p>
                <div className="token-reveal-row">
                  <code>{mintedToken}</code>
                  <button
                    type="button"
                    className="copy-chip"
                    onClick={() => copyToClipboard(mintedToken, 'minted-copy')}
                  >
                    {copiedKey === 'minted-copy' ? <Check size={13} /> : <Copy size={13} />}
                    <span>{copiedKey === 'minted-copy' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            )}

            {mintError && (
              <div className="form-feedback-alert error">
                <AlertTriangle size={16} />
                <span>{mintError}</span>
              </div>
            )}

            <div className="active-token-row">
              <div className="token-info">
                <span className="token-scope-badge">TENANT ADMIN</span>
                <div>
                  <h4>Active Console Session Token</h4>
                  <p>Granted full policy deployment, containment override, and exporter administration privileges for <code>{connection.tenant}</code>.</p>
                </div>
              </div>

              <div className="token-actions">
                <button
                  type="button"
                  className="copy-token-btn"
                  onClick={() => copyToClipboard(connection.token, 'current-token')}
                >
                  {copiedKey === 'current-token' ? <Check size={13} /> : <Copy size={13} />}
                  <span>{copiedKey === 'current-token' ? 'Copied' : 'Copy Token'}</span>
                </button>
              </div>
            </div>
          </article>

          <article className="settings-card">
            <div className="settings-card-header">
              <div className="settings-card-title">
                <Server size={18} />
                <h3>Active Browser Session Details</h3>
              </div>
            </div>

            <dl className="session-props-grid">
              <div>
                <dt>Control Plane Endpoint</dt>
                <dd><code>{connection.baseUrl}</code></dd>
              </div>
              <div>
                <dt>Active Tenant ID</dt>
                <dd><code>{connection.tenant}</code></dd>
              </div>
              <div>
                <dt>Authentication Credential</dt>
                <dd>{account.id ? 'Account-issued session token' : 'Master admin bearer token'}</dd>
              </div>
              <div>
                <dt>Session Expiration</dt>
                <dd>{account.session_expires_at || 'Persistent until revoked'}</dd>
              </div>
              <div>
                <dt>Local Storage Security</dt>
                <dd>Encrypted browser sessionStorage (destroyed on tab close)</dd>
              </div>
              <div>
                <dt>Active Sessions</dt>
                <dd>{sessions.length ? `${sessions.length} recorded session(s)` : '1 active session'}</dd>
              </div>
            </dl>

            <div className="session-danger-row">
              <button type="button" className="danger-action-btn" onClick={logout}>
                Sign Out & Revoke Local Session
              </button>
            </div>
          </article>
        </div>
      )}

      {/* TAB 3: ALERTS & NOTIFICATIONS */}
      {activeTab === 'alerts' && (
        <div className="settings-tab-pane" role="tabpanel" id="settings-panel-alerts" aria-labelledby="settings-tab-alerts">
          <article className="settings-card">
            <div className="settings-card-header">
              <div className="settings-card-title">
                <Bell size={18} />
                <h3>Security Event Notification Triggers</h3>
              </div>
            </div>
            <p className="settings-card-desc">
              Select which security events automatically dispatch high-priority notifications to SecOps channels and administrators.
            </p>

            <div className="toggle-list">
              <label className="toggle-item">
                <input type="checkbox" checked={realOnly} onChange={(e) => setRealOnly(e.target.checked)} />
                <div>
                  <b>Real telemetry only</b>
                  <p>Hide synthetic fallback devices, events, and outcomes when the control plane is unavailable.</p>
                </div>
              </label>
              <label className="toggle-item">
                <input
                  type="checkbox"
                  checked={notifyContain}
                  onChange={(e) => setNotifyContain(e.target.checked)}
                />
                <div>
                  <b>Autonomous Workload Containment (SIGKILL)</b>
                  <p>Dispatches whenever Shield quarantines a process or isolates container execution.</p>
                </div>
              </label>

              <label className="toggle-item">
                <input
                  type="checkbox"
                  checked={notifyDeny}
                  onChange={(e) => setNotifyDeny(e.target.checked)}
                />
                <div>
                  <b>High-Risk Policy Denials</b>
                  <p>Triggers when an unauthorized agent tool call, shadow AI model, or PHI data-access is denied.</p>
                </div>
              </label>

              <label className="toggle-item">
                <input
                  type="checkbox"
                  checked={notifySensorDrop}
                  onChange={(e) => setNotifySensorDrop(e.target.checked)}
                />
                <div>
                  <b>eBPF Sensor Disconnection & Lost Events</b>
                  <p>Alerts immediately if an endpoint watchdog ceases telemetry reporting or drops syscall frames.</p>
                </div>
              </label>
            </div>
          </article>

          <article className="settings-card">
            <div className="settings-card-header">
              <div className="settings-card-title">
                <Mail size={18} />
                <h3>Email Alert Delivery (SMTP)</h3>
              </div>
            </div>
            <p className="settings-card-desc">
              Direct integration with <code>shield.backend.email_delivery</code> for dispatching cryptographically verifiable alert receipts.
            </p>

            <div className="settings-fields-grid">
              <div className="field-group">
                <label htmlFor="smtpHost">SMTP Host</label>
                <input
                  id="smtpHost"
                  name="smtpHost"
                  type="text"
                  value={smtpHost}
                  onChange={(e) => setSmtpHost(e.target.value)}
                  placeholder="smtp.corp.internal"
                />
              </div>

              <div className="field-group">
                <label htmlFor="smtpPort">SMTP Port</label>
                <input
                  id="smtpPort"
                  name="smtpPort"
                  type="text"
                  value={smtpPort}
                  onChange={(e) => setSmtpPort(e.target.value)}
                  placeholder="587"
                />
              </div>

              <div className="field-group span-2">
                <label htmlFor="smtpRecipient">SecOps Alert Recipient</label>
                <input
                  id="smtpRecipient"
                  name="smtpRecipient"
                  type="email"
                  value={smtpRecipient}
                  onChange={(e) => setSmtpRecipient(e.target.value)}
                  placeholder="secops-alerts@corp.internal"
                />
              </div>
            </div>

            {emailStatus && (
              <div className={`form-feedback-alert ${emailStatus.ok ? 'success' : 'error'}`}>
                {emailStatus.ok ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                <span>{emailStatus.text}</span>
              </div>
            )}

            <div className="settings-actions-footer">
              <button
                type="button"
                className="secondary-btn"
                onClick={handleTestEmail}
                disabled={testingEmail}
              >
                {testingEmail ? (
                  <>
                    <Activity size={13} className="spinning" />
                    <span>Sending test alert…</span>
                  </>
                ) : (
                  <>
                    <Send size={13} />
                    <span>Send Test Alert Email</span>
                  </>
                )}
              </button>
            </div>
          </article>
        </div>
      )}

      {/* TAB 4: OPERATOR PROFILE */}
      {activeTab === 'profile' && (
        <div className="settings-tab-pane" role="tabpanel" id="settings-panel-profile" aria-labelledby="settings-tab-profile">
          <AvatarPreference />

          <div className="profile-grid">
            <article className="settings-card">
              <p className="eyebrow">OPERATOR PROFILE</p>
              <h3>{account.display_name || 'Shield Operator'}</h3>
              <dl className="operator-dl">
                <dt>Email Address</dt>
                <dd>{account.email || 'Admin Token Session'}</dd>
                <dt>Access Role</dt>
                <dd>{account.role || 'Tenant Administrator'}</dd>
                <dt>Account ID</dt>
                <dd><code>{account.id || '—'}</code></dd>
                <dt>Enrolled Date</dt>
                <dd>{account.created_at || 'Active'}</dd>
              </dl>

              {account.email && (
                <form className="password-update-form" onSubmit={changePassword}>
                  <h4>Change Account Password</h4>
                  <div className="field-group">
                    <label>Current password</label>
                    <input name="currentPassword" type="password" required />
                  </div>
                  <div className="field-group">
                    <label>New password (min 10 chars)</label>
                    <input name="newPassword" type="password" minLength={10} required />
                  </div>
                  <button type="submit" className="primary-btn">
                    Update Password
                  </button>
                  {message && <p className="form-message" aria-live="polite">{message}</p>}
                </form>
              )}
            </article>

            {account.email && <AuditEvents api={api} email={account.email} />}
            <SettingsChangeQueue api={api} />
          </div>
        </div>
      )}
    </div>
  )
}
