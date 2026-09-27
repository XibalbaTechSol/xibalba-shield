import { useEffect, useState } from 'react'
import { AlertTriangle, BrainCircuit, CheckCircle2, LockKeyhole, Save } from 'lucide-react'

const DEFAULTS = {
  hermesEnabled: true,
  hermesAgentId: '',
  hermesTransport: 'local-spool',
  hermesAnalysisOnly: true,
  hermesRedactionMode: 'strict',
  hermesEventScope: 'all',
  hermesSpoolPath: '/var/lib/xibalba-shield/hermes',
  hermesKeyPath: '/etc/xibalba-shield/secrets/hermes-spool.key',
  hermesMaxBatch: 10,
  hermesSpoolMaxBytes: 16777216,
  hermesAutoRetry: true,
}

export function HermesAgentView({ api, data = {} }) {
  const [config, setConfig] = useState(DEFAULTS)
  const [saved, setSaved] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    api.settings().then((result) => {
      if (cancelled) return
      const settings = result.settings || {}
      setConfig((current) => ({
        ...current,
        ...Object.fromEntries(Object.keys(DEFAULTS).filter((key) => settings[key] !== undefined).map((key) => [key, settings[key]])),
      }))
    }).catch((reason) => {
      if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason))
    })
    return () => { cancelled = true }
  }, [api])

  const update = (key, value) => setConfig((current) => ({ ...current, [key]: value }))

  const save = async (event) => {
    event.preventDefault()
    setMessage('')
    setError('')
    setSaved(false)
    const maxBatch = Number(config.hermesMaxBatch)
    const spoolMaxBytes = Number(config.hermesSpoolMaxBytes)
    if (!Number.isInteger(maxBatch) || maxBatch < 1 || maxBatch > 10) {
      setError('hermesMaxBatch must be between 1 and 10')
      return
    }
    if (!Number.isInteger(spoolMaxBytes) || spoolMaxBytes < 65536 || spoolMaxBytes > 16777216) {
      setError('hermesSpoolMaxBytes must be between 65536 and 16777216')
      return
    }
    try {
      await api.saveSettings({ ...config, hermesMaxBatch: maxBatch, hermesSpoolMaxBytes: spoolMaxBytes })
      setSaved(true)
      setMessage('Hermes agent profile saved to the tenant control plane.')
      window.setTimeout(() => setSaved(false), 4000)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    }
  }

  const queued = data.hermes?.pending ?? 'Not reported'
  const hermesHealth = data.hermes?.health || 'unknown'
  const identityConfigured = Boolean(config.hermesAgentId)

  return (
    <form className="settings-tab-pane hermes-agent-view" id="settings-panel-hermes" role="tabpanel" aria-labelledby="settings-tab-hermes" onSubmit={save}>
      <article className="settings-card hermes-hero-card">
        <div className="settings-card-header">
          <div className="settings-card-title"><BrainCircuit size={18} /><h3>Hermes Shield agent</h3></div>
          <span className={`status-pill ${hermesHealth === 'healthy' ? 'protected' : 'attention'}`}><span className={`status-dot ${hermesHealth === 'healthy' ? 'green' : 'yellow'}`} /> {hermesHealth === 'healthy' ? 'Transport healthy' : 'Host verification required'}</span>
        </div>
        <p className="settings-card-desc">Configure the Shield-to-Hermes profile. Shield remains the local policy and enforcement authority; Hermes receives authenticated, redacted metadata for analysis only.</p>
        <div className="hermes-boundary-grid">
          <div><span>Authority</span><strong>Shield · local</strong><small>Hermes cannot execute commands or network actions.</small></div>
          <div><span>Transport</span><strong>HMAC local spool</strong><small>Bounded delivery with replay and acknowledgement state.</small></div>
          <div><span>Privacy</span><strong>Strict redaction</strong><small>Raw payloads, paths, prompts, and credentials are excluded.</small></div>
          <div><span>Pending Hermes records</span><strong>{queued}</strong><small>{data.hermes?.acknowledged_total || 0} acknowledged · {data.hermes?.dead_letters || 0} dead-letter</small></div>
        </div>
      </article>

      <article className="settings-card">
        <div className="settings-card-header"><div className="settings-card-title"><BrainCircuit size={18} /><h3>Agent profile</h3></div><span className="live-status-pill">Tenant-scoped</span></div>
        <div className="toggle-list">
          <label className="toggle-item"><input type="checkbox" checked={config.hermesEnabled} onChange={(event) => update('hermesEnabled', event.target.checked)} /><div><b>Enable Hermes delivery</b><p>Queue eligible Shield events for the authenticated Hermes consumer. Local enforcement never depends on Hermes availability.</p></div></label>
          <label className="toggle-item"><input type="checkbox" checked={config.hermesAutoRetry} onChange={(event) => update('hermesAutoRetry', event.target.checked)} /><div><b>Retry transient delivery failures</b><p>Keep bounded events in the local spool until acknowledgement, expiry, or capacity protection.</p></div></label>
        </div>
        <div className="settings-fields-grid">
          <div className="field-group"><label htmlFor="hermesAgentId">Hermes agent identity</label><input id="hermesAgentId" value={config.hermesAgentId} onChange={(event) => update('hermesAgentId', event.target.value)} placeholder="did:integrity:…" /><span className="field-hint">Must identify the intended Hermes profile; no identity is generated or replaced here.</span>{config.hermesEnabled && !identityConfigured && <span className="field-hint warning">Delivery is enabled, but no Hermes identity is configured; delivery cannot be verified.</span>}</div>
          <div className="field-group"><label htmlFor="hermesEventScope">Event scope</label><select id="hermesEventScope" value={config.hermesEventScope} onChange={(event) => update('hermesEventScope', event.target.value)}><option value="all">All eligible redacted events</option><option value="decisions">Policy decisions only</option><option value="network">Network events only</option></select><span className="field-hint">Scope is bounded by the Shield-Hermes contract and local policy.</span></div>
        </div>
      </article>

      <article className="settings-card">
        <div className="settings-card-header"><div className="settings-card-title"><LockKeyhole size={18} /><h3>Transport and privacy guardrails</h3></div><span className="live-status-pill">Fail-closed invariants</span></div>
        <div className="settings-fields-grid">
          <div className="field-group"><label>Transport</label><div className="settings-readout">Local authenticated spool</div><span className="field-hint">The current implementation supports the local spool transport only.</span></div>
          <div className="field-group"><label>Analysis boundary</label><div className="settings-readout">Analysis only · enforced</div><span className="field-hint">This invariant cannot be disabled from the UI.</span></div>
          <div className="field-group"><label>Redaction mode</label><div className="settings-readout">Strict · enforced</div><span className="field-hint">Secrets, emails, raw paths, prompts, and raw network payloads are rejected.</span></div>
          <div className="field-group"><label>Schema</label><div className="settings-readout">xibalba.shield.hermes.event · v1.0.0</div><span className="field-hint">Payloads are validated before durable delivery.</span></div>
        </div>
      </article>

      <article className="settings-card">
        <div className="settings-card-header"><div className="settings-card-title"><LockKeyhole size={18} /><h3>Host-managed runtime paths</h3></div><span className="status-pill attention">Host verification required</span></div>
        <p className="settings-card-desc">These paths describe the installed agent boundary. The browser never receives key material and cannot create, read, or rotate the spool key.</p>
        <div className="settings-fields-grid">
          <div className="field-group"><label htmlFor="hermesSpoolPath">Spool directory</label><input id="hermesSpoolPath" value={config.hermesSpoolPath} onChange={(event) => update('hermesSpoolPath', event.target.value)} /></div>
          <div className="field-group"><label htmlFor="hermesKeyPath">HMAC key path</label><input id="hermesKeyPath" value={config.hermesKeyPath} onChange={(event) => update('hermesKeyPath', event.target.value)} /><span className="field-hint">Path only; secret contents remain outside tenant storage and browser state.</span></div>
          <div className="field-group"><label htmlFor="hermesMaxBatch">Maximum batch</label><input id="hermesMaxBatch" type="number" inputMode="numeric" value={config.hermesMaxBatch} onChange={(event) => update('hermesMaxBatch', event.target.value)} /><span className="field-hint">Allowed range: 1–10.</span></div>
          <div className="field-group"><label htmlFor="hermesSpoolMaxBytes">Spool ceiling (bytes)</label><input id="hermesSpoolMaxBytes" type="number" inputMode="numeric" value={config.hermesSpoolMaxBytes} onChange={(event) => update('hermesSpoolMaxBytes', event.target.value)} /><span className="field-hint">Allowed range: 65,536–16 MiB.</span></div>
        </div>
        <div className="hermes-warning"><AlertTriangle size={16} /><span>Saving this profile does not mutate the host service. An operator must reconcile these values with the installed environment and restart the agent through the approved deployment path.</span></div>
      </article>

      <div className="settings-actions-footer"><button type="submit" className="primary-btn"><Save size={14} /> Save Hermes profile</button>{saved && <span className="save-feedback-pill success"><CheckCircle2 size={14} /> Saved</span>}{message && <span className="form-message" aria-live="polite">{message}</span>}{error && <span className="form-message error" role="alert">{error}</span>}</div>
    </form>
  )
}
