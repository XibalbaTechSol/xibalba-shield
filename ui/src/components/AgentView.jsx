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
  const [agentTelemetry, setAgentTelemetry] = useState(null)
  const [cortexMemories, setCortexMemories] = useState(null)
  const [bindings, setBindings] = useState([])
  const [pairAction, setPairAction] = useState(null)
  const [pairMessage, setPairMessage] = useState('')
  useEffect(() => { if (selected?.device_id) loadBindings(selected.device_id) }, [selected?.device_id])
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
  const inspectCortexMemories = async (device) => {
    const pair = device.device_agent_pair || {}
    const agentId = pair.shield_agent_id || device.agent_id || device.did
    setCortexMemories({ loading: true, agentId })
    try {
      const result = await api.cortexMemories(device.device_id, agentId)
      setCortexMemories({ loading: false, ...result })
    } catch (error) {
      setCortexMemories({ loading: false, agentId, error: error instanceof Error ? error.message : String(error) })
    }
  }
  const devices = data.devices || []
  const realAgentRoster = useMemo(() => (data.agents || []).flatMap((agent) => (agent.available_agents || []).map((identity) => ({ ...identity, device_id: agent.devices?.[0]?.device_id || '' }))), [data.agents])
  const exporterByDevice = useMemo(() => Object.fromEntries((data.exporter || []).map((row) => [row.device_id, row])), [data.exporter])
  const responderStatus = useMemo(() => {
    const live = (data.exporter || []).find((row) => row.status?.responders)?.status?.responders
    return live || {}
  }, [data.exporter])
  const responderCapabilities = { ...DEFAULT_RESPONDER_CAPABILITIES, ...(responderStatus.capabilities || {}), ...(data.responder_capabilities || {}) }
  const loadBindings = async (deviceId) => { try { setBindings((await api.agentBindings(deviceId)).bindings || []) } catch (error) { setPairMessage(error instanceof Error ? error.message : String(error)) } }
  const changePairStatus = async (agentId, action) => {
    if (!selected?.device_id || !window.confirm(`${action === 'revoke' ? 'Revoke' : 'Detach'} this exact device/agent pair?`)) return
    setPairAction(`${agentId}:${action}`); setPairMessage('')
    try { await api.agentBindingAction(selected.device_id, agentId, action); setPairMessage(`Pair ${action}d successfully.`); await loadBindings(selected.device_id); refresh() }
    catch (error) { setPairMessage(error instanceof Error ? error.message : String(error)) }
    finally { setPairAction(null) }
  }
  return <section className="resource agent-workspace">{selected && <section className="settings-card" aria-label="Device agent pair management"><div className="settings-card-header"><div className="settings-card-title"><ShieldCheck size={18} /><h3>Device / agent pairs</h3></div><span className="live-status-pill">{bindings.filter((binding) => !binding.unbound_at).length} active</span></div><p className="settings-card-desc">Every action targets the selected <b>device_id + agent_id</b> pair. Detach is reversible; revoke is terminal.</p>{bindings.filter((binding) => !binding.unbound_at).map((binding) => <div className="agent-roster-row" key={binding.id}><div><b>{selected.device_id}</b><small>{binding.agent_id}</small></div><button type="button" className="secondary-btn" disabled={Boolean(pairAction)} onClick={() => changePairStatus(binding.agent_id, 'detach')}>{pairAction === `${binding.agent_id}:detach` ? 'Detaching…' : 'Detach'}</button><button type="button" className="secondary-btn danger" disabled={Boolean(pairAction)} onClick={() => changePairStatus(binding.agent_id, 'revoke')}>{pairAction === `${binding.agent_id}:revoke` ? 'Revoking…' : 'Revoke'}</button></div>)}{bindings.filter((binding) => !binding.unbound_at).length === 0 && <p className="small muted">No active pairs on this device.</p>}{pairMessage && <p className="form-message" aria-live="polite">{pairMessage}</p>}</section>}
    <header>
      <p className="eyebrow">SHIELD AGENT OPERATIONS</p>
      <h2>Agent workspace</h2>
      <span>Inspect endpoint posture, sensor attachment, evidence publication, and recent enforcement activity from one authenticated view.</span>
      <small className="evidence-label">Only control-plane records are shown. Missing telemetry is marked unverified.</small>
    </header>
    <div className="agent-toolbar"><span><span className="status-dot green" /> {devices.length} enrolled device{devices.length === 1 ? '' : 's'}</span><span className="evidence-label">Each device is scoped to one canonical Shield agent and Cortex memory namespace.</span><button type="button" className="secondary-btn" onClick={refresh}><RefreshCw size={14} /> Refresh agents</button></div>
    {devices.length > 0 && <section className="hybrid-architecture-card" aria-labelledby="hybrid-architecture-title"><div><p className="eyebrow">HYBRID IDENTITY BOUNDARY</p><h3 id="hybrid-architecture-title">One device · one Shield agent · one Cortex namespace</h3><p>Shield enforces locally. Redacted events may be reasoned about by the dedicated Hermes cloud agent, while Cortex memory remains keyed to the selected Shield agent.</p></div><div className="hybrid-pair-list">{devices.map((device) => { const pair = device.device_agent_pair || {}; const hybrid = device.hybrid_architecture || {}; const cloud = hybrid.cloud_reasoning || {}; return <article className="hybrid-pair" key={pair.pair_id || device.device_id}><div className="hybrid-pair-heading"><HardDrive size={15} /><b>{pair.device_id || device.device_id}</b><span className="live-status-pill">{hybrid.mode || 'hybrid'}</span></div><dl><div><dt>Shield agent</dt><dd>{pair.shield_agent_id || device.agent_id || 'unbound'}</dd></div><div><dt>Pair ID</dt><dd>{pair.pair_id || '—'}</dd></div><div><dt>Local authority</dt><dd>{hybrid.local_enforcement?.status === 'active' ? 'Shield · active' : 'Unverified'}</dd></div><div><dt>Cloud reasoning</dt><dd>{cloud.status === 'configured' ? `Hermes · ${cloud.agent_id}` : 'Hermes · not configured'}</dd></div><div><dt>Cortex memory</dt><dd>{cloud.memory_namespace || pair.memory_namespace || '—'}</dd></div></dl></article> })}</div></section>}
    {data.cortexOutbox && <section className={`outbox-status-card ${data.cortexOutbox.dead_letter ? 'has-warning' : ''}`} aria-label="Cortex delivery status"><div><p className="eyebrow">CORTEX DELIVERY</p><h3>Durable cloud publication</h3><p>{data.cortexOutbox.pending ? `${data.cortexOutbox.pending} events are waiting for Cortex acknowledgement.` : 'No events are waiting for Cortex acknowledgement.'} Failed attempts move to a dead-letter queue.</p>{data.cortexOutbox.dead_letter > 0 && <p className="form-message error" role="status">{data.cortexOutbox.dead_letter} events need operator review.</p>}</div><div className="outbox-metrics"><span><b>{data.cortexOutbox.pending || 0}</b><small>pending</small></span><span><b>{data.cortexOutbox.sent || 0}</b><small>sent</small></span><span className={data.cortexOutbox.dead_letter ? 'danger' : ''}><b>{data.cortexOutbox.dead_letter || 0}</b><small>dead-letter</small></span><span><b>{data.cortexOutbox.delivered_total || 0}</b><small>delivered</small></span></div></section>}
    <section className="settings-card" aria-labelledby="real-agent-roster-title"><div className="settings-card-header"><div className="settings-card-title"><ShieldCheck size={18} /><h3 id="real-agent-roster-title">Real agents observed on this device</h3></div><span className="live-status-pill"><Activity size={13} /> No fixtures</span></div><p className="settings-card-desc">Only identities emitted by this device’s authenticated decisions/outcomes are listed. Select an agent in the host runtime to exercise its policy and memory boundary.</p>{realAgentRoster.length === 0 ? <p className="small muted">No agent-bearing real events have been observed yet.</p> : <div className="agent-roster">{realAgentRoster.map((agent) => <div className="agent-roster-row" key={`${agent.device_id}:${agent.agent_id}`}><div><b>{agent.name}</b><small>{agent.agent_id}</small></div><span>{agent.source}</span><button type="button" className="secondary-btn" onClick={async () => { try { const result = await api.testEvents(agent.agent_id); setAgentTelemetry({ agentId: agent.agent_id, events: result.test_events || [] }) } catch (error) { setAgentTelemetry({ agentId: agent.agent_id, error: error instanceof Error ? error.message : String(error) }) } }}>Inspect telemetry</button></div>)}</div>}{agentTelemetry && <p className="form-message" aria-live="polite">{agentTelemetry.error || `${agentTelemetry.events.length} authenticated telemetry records for ${agentTelemetry.agentId}.`}</p>}</section>
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
      return <button type="button" className="agent-card" key={id} onClick={async () => { setSelected({ loading: true, device_id: id }); setCortexMemories(null); try { setSelected({ loading: false, ...(await api.device(id)) }) } catch (error) { setSelected({ loading: false, device_id: id, error: error instanceof Error ? error.message : String(error) }) } }}>
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
    {selected && <aside className="device-detail-backdrop" role="presentation" onClick={() => setSelected(null)}><section className="device-detail-drawer" role="dialog" aria-modal="true" aria-label="Agent details" onClick={(event) => event.stopPropagation()}><header className="device-detail-header"><div><p className="eyebrow">AGENT DETAIL</p><h2>{selected.device_id}</h2><span>{selected.device_role || 'Endpoint'} · {selected.status || 'unverified'}</span></div><button type="button" className="drawer-close" aria-label="Close agent details" onClick={() => setSelected(null)}>×</button></header>{selected.loading ? <p className="device-detail-loading">Loading authenticated agent state…</p> : selected.error ? <p className="form-message error">{selected.error}</p> : <><dl className="device-detail-grid">{['policy_version', 'last_seen_at', 'ip_address', 'kernel_version', 'ebpf_sensor', 'did', 'agent_id', 'registration_status', 'memory_scope'].map((key) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{selected[key] || '—'}</dd></div>)}</dl><div className="agent-remediation-panel hybrid-detail-panel"><p className="eyebrow">HYBRID ROUTING</p><h3>{selected.device_agent_pair?.pair_id ? `Pair ${selected.device_agent_pair.pair_id}` : 'Device-agent pair'}</h3><p><b>Shield</b> remains the local enforcement authority. <b>Hermes</b> receives only redacted events when configured and reasons through the <b>Cortex</b> namespace shown below.</p><div className="hybrid-detail-values"><span><small>Shield agent</small><code>{selected.device_agent_pair?.shield_agent_id || selected.agent_id || 'unbound'}</code></span><span><small>Cortex namespace</small><code>{selected.hybrid_architecture?.cloud_reasoning?.memory_namespace || selected.device_agent_pair?.memory_namespace || '—'}</code></span><span><small>Hermes status</small><b>{selected.hybrid_architecture?.cloud_reasoning?.status || 'not configured'}</b></span></div><div className="cortex-memory-panel"><div><p className="eyebrow">SELECTED AGENT MEMORY</p><h4>Cortex evidence for this device pair</h4><p>Reads only the Cortex partition bound to this device and canonical Shield agent.</p></div><button type="button" className="secondary-btn" onClick={() => inspectCortexMemories(selected)}>Inspect Cortex memory</button>{cortexMemories?.loading && <p className="small muted">Loading authenticated Cortex memory…</p>}{cortexMemories?.error && <p className="form-message error">{cortexMemories.error}</p>}{cortexMemories && !cortexMemories.loading && !cortexMemories.error && <><div className="memory-proof-row"><span><b>{(cortexMemories.memories || []).length}</b><small>memories</small></span><code>{cortexMemories.memory_namespace}</code></div><div className="memory-preview">{(cortexMemories.memories || []).slice(0, 3).map((memory) => <article key={memory.id}><b>{memory.source?.kind || 'memory'}</b><span>{memory.content_preview || memory.content || memory.id}</span></article>)}</div></>}</div></div><div className="agent-remediation-panel"><p className="eyebrow">INTEGRITY IDENTITY</p><h3>Register Shield agent</h3><p>Verify the canonical DID with Integrity and bind this device to the agent-scoped Cortex memory namespace.</p><button type="button" className="primary" onClick={registerSelectedAgent}>Register / verify on Integrity</button>{registrationMessage && <p className="form-message" aria-live="polite">{registrationMessage}</p>}</div><div className="agent-remediation-panel"><p className="eyebrow">WORKER-BACKED ACTION</p><h3>Exporter remediation</h3><select className="form-select" value={remediation.action} onChange={(event) => setRemediation({ action: event.target.value, message: '' })}><option value="retry">Retry failed exports</option><option value="reconnect">Reconnect exporter</option><option value="flush">Flush pending queue</option></select><button type="button" className="primary" onClick={queueRemediation}>Queue action</button>{remediation.message && <p className="form-message" aria-live="polite">{remediation.message}</p>}</div></>}</section></aside>}
  </section>
}
