import { useEffect, useState } from 'react'
import { Network, Save, ShieldAlert } from 'lucide-react'

const DEFAULT_CONFIG = {
  zones: [
    { zone_id: 'management', kind: 'management', protected: true },
    { zone_id: 'recovery', kind: 'recovery', protected: true },
  ],
  topology: [],
  sensors: [],
  protected_paths: [],
  max_affected_devices: 1,
  max_affected_segments: 1,
  retention_days: 7,
  queue_limit_bytes: 16777216,
  adapter_actions: {},
}

export function NetworkView({ api }) {
  const [config, setConfig] = useState(DEFAULT_CONFIG)
  const [version, setVersion] = useState(null)
  const [requests, setRequests] = useState([])
  const [topologyText, setTopologyText] = useState('[]')
  const [sensorsText, setSensorsText] = useState('[]')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([api.networkConfig(), api.networkConfigChangeRequests()])
      .then(([payload, changes]) => {
        if (payload.config && Object.keys(payload.config).length) {
          setConfig(payload.config)
          setTopologyText(JSON.stringify(payload.config.topology || [], null, 2))
          setSensorsText(JSON.stringify(payload.config.sensors || [], null, 2))
        }
        setVersion(payload.config_version)
        setRequests(changes.requests || [])
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)))
  }, [api])

  const update = (key, value) => setConfig((current) => ({ ...current, [key]: Number(value) }))
  const save = async (event) => {
    event.preventDefault()
    setMessage('Saving network controls…')
    setError('')
    try {
      const topology = JSON.parse(topologyText)
      const sensors = JSON.parse(sensorsText)
      if (!Array.isArray(topology) || !Array.isArray(sensors)) throw new Error('Topology and sensors must each be JSON arrays')
      const nextConfig = { ...config, topology, sensors }
      setConfig(nextConfig)
      const result = await api.saveNetworkConfig(nextConfig)
      setRequests((current) => [result.request, ...current])
      setMessage(`Change ${result.request.request_id} is pending approval. No adapter action was executed.`)
    } catch (reason) {
      setMessage('')
      setError(reason instanceof Error ? reason.message : String(reason))
    }
  }

  const decide = async (requestId, action) => {
    try {
      const result = await api.decideNetworkConfigChange(requestId, action)
      setRequests((current) => current.map((item) => item.request_id === requestId ? { ...item, ...result } : item))
      if (action === 'approve') setVersion(result.proposed_version || version)
      setMessage(`Network change ${action}d.`)
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
  }

  return <>
    <article className="settings-card">
      <div className="settings-card-header">
        <div className="settings-card-title"><Network size={18} /><h3>Network control plane</h3></div>
        <span className="live-status-pill">Preview and approval gated</span>
      </div>
      <p className="settings-card-desc">Configure protected zones and blast-radius limits. Hermes remains analysis-only; production adapters are not enabled by this view.</p>
      <form className="settings-fields-grid" onSubmit={save}>
        <label>Maximum affected devices<input type="number" min="1" max="1000" value={config.max_affected_devices} onChange={(event) => update('max_affected_devices', event.target.value)} /></label>
        <label>Maximum affected segments<input type="number" min="1" max="100" value={config.max_affected_segments} onChange={(event) => update('max_affected_segments', event.target.value)} /></label>
        <label>Retention days<input type="number" min="1" max="3650" value={config.retention_days} onChange={(event) => update('retention_days', event.target.value)} /></label>
        <label>Queue limit bytes<input type="number" min="65536" max="1073741824" value={config.queue_limit_bytes} onChange={(event) => update('queue_limit_bytes', event.target.value)} /></label>
        <div className="settings-actions-footer"><button type="submit" className="primary-btn"><Save size={14} /> Save network controls</button>{version && <small>Version {version}</small>}</div>
      </form>
      <div className="settings-fields-grid">
        <label>Topology declarations (secret-free JSON)
          <textarea aria-label="Topology declarations" rows="5" value={topologyText} onChange={(event) => setTopologyText(event.target.value)} />
        </label>
        <label>Sensor declarations (secret-free JSON)
          <textarea aria-label="Sensor declarations" rows="5" value={sensorsText} onChange={(event) => setSensorsText(event.target.value)} />
        </label>
      </div>
      {message && <p className="form-message success" aria-live="polite">{message}</p>}
      {error && <p className="form-message error" role="alert"><ShieldAlert size={14} /> {error}</p>}
    </article>
    <article className="settings-card">
      <div className="settings-card-title"><ShieldAlert size={18} /><h3>Protected zones</h3></div>
      <div className="audit-event-list">{config.zones.map((zone) => <div className="audit-event" key={zone.zone_id}><b>{zone.zone_id}</b><small>{zone.kind} · {zone.protected ? 'protected' : 'not protected'}</small></div>)}</div>
    </article>
    <article className="settings-card">
      <div className="settings-card-title"><ShieldAlert size={18} /><h3>Network change approvals</h3></div>
      <div className="audit-event-list">{requests.length === 0 ? <p className="empty-state">No network configuration changes.</p> : requests.slice(0, 8).map((request) => <div className="audit-event" key={request.request_id}><b>{request.status}</b><small>{request.request_id} · {request.proposed_version}</small><div className="settings-actions-footer">{request.status === 'pending' && <><button type="button" className="secondary-btn" onClick={() => decide(request.request_id, 'approve')}>Approve</button><button type="button" className="secondary-btn" onClick={() => decide(request.request_id, 'reject')}>Reject</button></>}{request.status === 'approved' && <button type="button" className="secondary-btn" onClick={() => decide(request.request_id, 'rollback')}>Rollback</button>}</div></div>)}</div>
    </article>
  </>
}
