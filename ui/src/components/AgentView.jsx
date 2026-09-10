import { useEffect, useMemo, useState } from 'react'
import { Activity, CheckCircle2, Cpu, HardDrive, LockKeyhole, Network, RefreshCw, ShieldCheck, Wifi } from 'lucide-react'

const DEFAULT_RESPONDER_CAPABILITIES = {
  freeze_process: true,
  kill_process: false,
  freeze_cgroup: false,
  block_flow: false,
}

const RESPONDER_DEFINITIONS = [
  { key: 'freeze_process', label: 'Freeze process', description: 'SIGSTOP containment for a policy-matched process.', icon: Activity },
  { key: 'kill_process', label: 'Kill process', description: 'Terminate a process after a destructive-action gate.', icon: LockKeyhole },
  { key: 'freeze_cgroup', label: 'Freeze cgroup', description: 'Pause a workload boundary through the kernel cgroup controller.', icon: Cpu },
  { key: 'block_flow', label: 'Block network flow', description: 'Install a policy-scoped network block through a validated runtime.', icon: Network },
]

export function AgentView({ data, refresh, api }) {
  const [selected, setSelected] = useState(null)
  const [remediation, setRemediation] = useState({ action: 'retry', message: '' })
  const [guardrails, setGuardrails] = useState({ toolCalls: true, modelRouting: true, retrieval: true, outputChecks: true, postAction: true })
  const [guardrailMessage, setGuardrailMessage] = useState('')
  const [registrationMessage, setRegistrationMessage] = useState('')
  useEffect(() => {
    let cancelled = false
    api.settings().then(({ settings = {} }) => {
      if (cancelled) return
      setGuardrails((current) => ({ ...current, ...Object.fromEntries(Object.keys(current).filter((key) => typeof settings[`guardrail${key[0].toUpperCase()}${key.slice(1)}`] === 'boolean').map((key) => [key, settings[`guardrail${key[0].toUpperCase()}${key.slice(1)}`]])) }))
    }).catch(() => {})
    return () => { cancelled = true }
  }, [api])
  const saveGuardrails = async () => {
    setGuardrailMessage('Saving guardrail configuration…')
    try {
      const current = await api.settings()
      const serialized = Object.fromEntries(Object.entries(guardrails).map(([key, value]) => [`guardrail${key[0].toUpperCase()}${key.slice(1)}`, value]))
      const result = await api.createSettingsChangeRequest('guardrails', { ...(current.settings || {}), ...serialized })
      setGuardrailMessage(`Approval requested (${result.request_id}).`)
    } catch (error) { setGuardrailMessage(error instanceof Error ? error.message : String(error)) }
  }
  const queueRemediation = async () => {
    setRemediation((current) => ({ ...current, message: 'Queueing remediation…' }))
    try {
      const result = await api.exporterRemediation(selected.device_id, remediation.action, 'Operator requested from Shield Agent workspace')
      setRemediation((current) => ({ ...current, message: `Request ${result.id} queued for the exporter worker.` }))
    } catch (error) { setRemediation((current) => ({ ...current, message: error instanceof Error ? error.message : String(error) })) }
  }
  const registerSelectedAgent = async () => {
    if (!selected?.device_id) return
    const agentId = selected.integrity_agent_id || selected.agent_id || selected.did
    setRegistrationMessage('Checking Integrity registration…')
    try {
      const result = await api.registerAgent(selected.device_id, agentId)
      setSelected(result.agent)
      setRegistrationMessage(result.registration?.status === 'registered' ? 'Registered on Integrity and bound to this device.' : 'Saved as pending signature; complete the on-chain registration before publishing agent telemetry.')
      refresh()
    } catch (error) { setRegistrationMessage(error instanceof Error ? error.message : String(error)) }
  }
  const devices = data.devices || []
  const exporterByDevice = useMemo(() => Object.fromEntries((data.exporter || []).map((row) => [row.device_id, row])), [data.exporter])
  const responderStatus = useMemo(() => {
    const live = (data.exporter || []).find((row) => row.status?.responders)?.status?.responders
    return live || {}
  }, [data.exporter])
  const responderCapabilities = { ...DEFAULT_RESPONDER_CAPABILITIES, ...(responderStatus.capabilities || {}), ...(data.responder_capabilities || {}) }
  return <section className="resource agent-workspace">
    <header>
      <p className="eyebrow">SHIELD AGENT OPERATIONS</p>
      <h2>Agent workspace</h2>
      <span>Inspect endpoint posture, sensor attachment, evidence publication, and recent enforcement activity from one authenticated view.</span>
      <small className="evidence-label">Only control-plane records are shown. Missing telemetry is marked unverified.</small>
    </header>
    <div className="agent-toolbar"><span><span className="status-dot green" /> {devices.length} enrolled device{devices.length === 1 ? '' : 's'}</span><span className="evidence-label">Each device is scoped to one canonical Shield agent and Cortex memory namespace.</span><button type="button" className="secondary-btn" onClick={refresh}><RefreshCw size={14} /> Refresh agents</button></div>
    <section className="responder-panel" aria-labelledby="responder-panel-title">
      <div className="responder-panel-heading">
        <div><p className="eyebrow">RESPONSE CAPABILITIES</p><h3 id="responder-panel-title">Responder interface</h3><p>Actions are surfaced from the agent contract. Destructive responders stay unavailable until their privileged runtime gates pass.</p></div>
        <span className="responder-gate"><ShieldCheck size={15} /> Gate enforced</span>
      </div>
      <div className="responder-grid">{RESPONDER_DEFINITIONS.map(({ key, label, description, icon: Icon }) => {
        const enabled = responderCapabilities[key] === true
        return <article className={`responder-card ${enabled ? 'enabled' : 'disabled'}`} key={key}>
          <div className="responder-card-top"><span className="responder-icon"><Icon size={16} /></span><span className={`responder-status ${enabled ? 'ready' : 'locked'}`}>{enabled ? <><CheckCircle2 size={13} /> Available</> : <><LockKeyhole size={13} /> Gate required</>}</span></div>
          <h4>{label}</h4><p>{description}</p>
          <button type="button" className="responder-action" disabled aria-disabled="true" title={enabled ? 'Invoked by policy decisions from the authenticated agent' : 'Runtime validation is required before this responder can be enabled'}>{enabled ? 'Policy-driven' : 'Unavailable until validated'}</button>
        </article>
      })}</div>
      <small className="responder-note"><LockKeyhole size={13} /> No UI action can bypass policy or enable an unvalidated responder.</small>
    </section>
    <section className="settings-card guardrails-panel" aria-labelledby="guardrails-title">
      <div className="settings-card-header"><div className="settings-card-title"><ShieldCheck size={18} /><h3 id="guardrails-title">Agent guardrails</h3></div><span className="live-status-pill"><ShieldCheck size={13} /> Pre-action gates</span></div>
      <p className="settings-card-desc">Control the semantic boundaries available to instrumented agent runtimes. Kernel telemetry remains independent and continues even when a hook is unavailable.</p>
      <div className="toggle-list guardrail-grid">{[['toolCalls', 'Tool execution', 'Require policy evaluation before a tool call runs.'], ['modelRouting', 'Model routing', 'Restrict provider and endpoint selection to approved destinations.'], ['retrieval', 'Retrieval and context', 'Gate data sources before they enter agent context.'], ['outputChecks', 'Output checks', 'Review caller-supplied risk labels before release.'], ['postAction', 'Post-action verification', 'Compare expected and observed state after an action.']].map(([key, label, description]) => <label className="toggle-item" key={key}><input type="checkbox" checked={guardrails[key]} onChange={(event) => setGuardrails((current) => ({ ...current, [key]: event.target.checked }))} /><div><b>{label}</b><p>{description}</p></div></label>)}</div>
      <div className="settings-actions-footer"><button type="button" className="primary-btn" onClick={saveGuardrails}>Save guardrails</button>{guardrailMessage && <span className="form-message" aria-live="polite">{guardrailMessage}</span>}</div>
    </section>
    {devices.length === 0 ? <div className="empty"><HardDrive /><h3>No enrolled agents</h3><p>Enroll an endpoint to begin authenticated posture reporting.</p></div> : <div className="agent-grid">{devices.map((device) => {
      const id = device.device_id || device.id
      const exporter = exporterByDevice[id]?.status || {}
      const sensors = exporter.sensors || {}
      const policy = exporter.policy || {}
      return <button type="button" className="agent-card" key={id} onClick={async () => { setSelected({ loading: true, device_id: id }); try { setSelected({ loading: false, ...(await api.device(id)) }) } catch (error) { setSelected({ loading: false, device_id: id, error: error instanceof Error ? error.message : String(error) }) } }}>
        <div className="agent-card-top"><span className="agent-icon"><Cpu /></span><span className={`status-badge ${device.status === 'protected' ? 'healthy' : 'attention'}`}>{device.status || 'unverified'}</span></div>
        <h3>{id}</h3><p>{device.device_role || 'Endpoint'} · {device.last_seen_at || device.last_seen || 'last seen unavailable'}</p>
        <div className="agent-health-row"><span><ShieldCheck /> Policy</span><b>{policy.healthy === true ? 'Healthy' : device.policy_version || 'Unverified'}</b></div>
        <div className="agent-health-row"><span><Activity /> Sensors</span><b>{sensors.attached === true ? 'Attached' : 'Unverified'}</b></div>
        <div className="agent-health-row"><span><Activity /> Probe mode</span><b>{sensors.attach_mode || 'Unreported'}</b></div>
        <div className="agent-health-row"><span><Wifi /> Bridge</span><b>{sensors.last_heartbeat_at ? 'Heartbeat' : sensors.last_event_at ? 'Event stream' : 'Unverified'}</b></div>
        <div className="agent-health-row"><span><Wifi /> Evidence</span><b>{exporter.export_failures === 0 ? 'Publishing' : exporter.export_failures ? 'Attention' : 'Unverified'}</b></div>
        <small className="agent-card-link">Open agent details →</small>
      </button>
    })}</div>}
    <div className="agent-footer-note"><Activity size={15} /><span>Agent actions remain tenant-scoped and auditable. Use Evidence for worker-backed remediation.</span></div>
    {selected && <aside className="device-detail-backdrop" role="presentation" onClick={() => setSelected(null)}><section className="device-detail-drawer" role="dialog" aria-modal="true" aria-label="Agent details" onClick={(event) => event.stopPropagation()}><header className="device-detail-header"><div><p className="eyebrow">AGENT DETAIL</p><h2>{selected.device_id}</h2><span>{selected.device_role || 'Endpoint'} · {selected.status || 'unverified'}</span></div><button type="button" className="drawer-close" aria-label="Close agent details" onClick={() => setSelected(null)}>×</button></header>{selected.loading ? <p className="device-detail-loading">Loading authenticated agent state…</p> : selected.error ? <p className="form-message error">{selected.error}</p> : <><dl className="device-detail-grid">{['policy_version', 'last_seen_at', 'ip_address', 'kernel_version', 'ebpf_sensor', 'did', 'agent_id', 'registration_status', 'memory_scope'].map((key) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{selected[key] || '—'}</dd></div>)}</dl><div className="agent-remediation-panel"><p className="eyebrow">INTEGRITY IDENTITY</p><h3>Register Shield agent</h3><p>Verify the canonical DID with Integrity and bind this device to the agent-scoped Cortex memory namespace.</p><button type="button" className="primary" onClick={registerSelectedAgent}>Register / verify on Integrity</button>{registrationMessage && <p className="form-message" aria-live="polite">{registrationMessage}</p>}</div><div className="agent-remediation-panel"><p className="eyebrow">WORKER-BACKED ACTION</p><h3>Exporter remediation</h3><select className="form-select" value={remediation.action} onChange={(event) => setRemediation({ action: event.target.value, message: '' })}><option value="retry">Retry failed exports</option><option value="reconnect">Reconnect exporter</option><option value="flush">Flush pending queue</option></select><button type="button" className="primary" onClick={queueRemediation}>Queue action</button>{remediation.message && <p className="form-message" aria-live="polite">{remediation.message}</p>}</div></>}</section></aside>}
  </section>
}
