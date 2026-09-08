import { useEffect, useMemo, useState } from 'react'
import { Activity, CheckCircle2, LockKeyhole, Save, ShieldAlert } from 'lucide-react'
import { OutcomeTable } from './OutcomeTable'

const ACTIONS = [
  ['freeze_process', 'Freeze process', 'Pause a policy-matched process with SIGSTOP.', true],
  ['freeze_cgroup', 'Freeze cgroup', 'Pause a workload boundary after cgroup runtime proof.', false],
  ['kill_process', 'Kill process', 'Terminate only after an explicit destructive-action gate.', false],
  ['block_flow', 'Block network flow', 'Install a scoped network block after kernel runtime proof.', false],
]

export function ContainmentView({ outcomes, api, data }) {
  const [mode, setMode] = useState('approval')
  const [cooldown, setCooldown] = useState('60')
  const [message, setMessage] = useState('')
  const live = useMemo(() => (data.exporter || []).find((row) => row.status?.responders)?.status || {}, [data.exporter])
  const capabilities = live.responders?.capabilities || {}

  useEffect(() => {
    let cancelled = false
    api.settings().then(({ settings = {} }) => {
      if (cancelled) return
      if (settings.containmentMode) setMode(settings.containmentMode)
      if (settings.containmentCooldown) setCooldown(String(settings.containmentCooldown))
    }).catch(() => {})
    return () => { cancelled = true }
  }, [api])

  const save = async (event) => {
    event.preventDefault()
    setMessage('Saving containment controls…')
    try {
      const current = await api.settings()
      const result = await api.createSettingsChangeRequest('containment', { ...(current.settings || {}), containmentMode: mode, containmentCooldown: Number(cooldown) })
      setMessage(`Approval requested (${result.request_id}).`)
    } catch (error) { setMessage(error instanceof Error ? error.message : String(error)) }
  }

  return <div className="containment-view">
    <section className="resource"><header><p className="eyebrow">RESPONSE CONTROL</p><h2>Containment</h2><span>Configure the approval boundary and inspect every recorded enforcement outcome.</span><small className="evidence-label">Destructive responders cannot be enabled from the UI without runtime proof.</small></header></section>
    <form className="settings-card" onSubmit={save}>
      <div className="settings-card-header"><div className="settings-card-title"><ShieldAlert size={18} /><h3>Containment policy</h3></div><span className="live-status-pill"><LockKeyhole size={13} /> Guarded</span></div>
      <div className="settings-fields-grid"><div className="field-group"><label htmlFor="containment-mode">Response mode</label><select id="containment-mode" value={mode} onChange={(event) => setMode(event.target.value)}><option value="approval">Human approval for proposals</option><option value="autonomous">Autonomous policy-approved freeze</option><option value="audit">Audit only</option></select></div><div className="field-group"><label htmlFor="containment-cooldown">Cooldown between actions</label><select id="containment-cooldown" value={cooldown} onChange={(event) => setCooldown(event.target.value)}><option value="30">30 seconds</option><option value="60">60 seconds</option><option value="300">5 minutes</option></select></div></div>
      <div className="settings-actions-footer"><button type="submit" className="primary-btn"><Save size={14} /> Save containment policy</button>{message && <span className="form-message" aria-live="polite">{message}</span>}</div>
    </form>
    <section className="settings-card"><div className="settings-card-header"><div className="settings-card-title"><Activity size={18} /><h3>Responder readiness</h3></div><span className="live-status-pill">Live agent report</span></div><div className="responder-grid">{ACTIONS.map(([key, label, description, fallback]) => { const enabled = capabilities[key] ?? fallback; return <article className={`responder-card ${enabled ? 'enabled' : 'disabled'}`} key={key}><div className="responder-card-top"><span className={`responder-status ${enabled ? 'ready' : 'locked'}`}>{enabled ? <><CheckCircle2 size={13} /> Ready</> : <><LockKeyhole size={13} /> Proof required</>}</span></div><h4>{label}</h4><p>{description}</p></article> })}</div></section>
    <OutcomeTable outcomes={outcomes} />
  </div>
}
