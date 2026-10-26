import { useState } from 'react'
import { BrainCircuit, CheckCircle2, LockKeyhole, Save } from 'lucide-react'

const DEFAULTS = {
  inferenceEnabled: false,
  inferenceProvider: 'disabled',
  inferenceMode: 'shadow',
  inferenceModel: '',
  inferenceEndpoint: '',
  inferencePromptProfile: 'shield-risk-v1',
  inferenceSecretRef: '',
  inferenceTimeoutMs: 750,
  inferenceMaxTokens: 512,
  inferenceTemperature: 0.1,
  inferenceFailureMode: 'continue_with_policy',
  inferenceEventClasses: ['agent_event', 'tool_call', 'process_activity'],
}

export function InferenceSettings({ api, settings = {}, onSaved }) {
  const [form, setForm] = useState(() => ({ ...DEFAULTS, ...settings }))
  const [message, setMessage] = useState('')
  const [saving, setSaving] = useState(false)

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }))
  const toggleClass = (eventClass) => update('inferenceEventClasses', form.inferenceEventClasses.includes(eventClass) ? form.inferenceEventClasses.filter((item) => item !== eventClass) : [...form.inferenceEventClasses, eventClass])
  const save = async (event) => {
    event.preventDefault()
    setSaving(true); setMessage('')
    try {
      const result = await api.saveSettings({ ...settings, ...form, inferenceEnabled: form.inferenceProvider !== 'disabled' && form.inferenceEnabled, inferenceTimeoutMs: Number(form.inferenceTimeoutMs), inferenceMaxTokens: Number(form.inferenceMaxTokens), inferenceTemperature: Number(form.inferenceTemperature) })
      onSaved?.(result.settings || form)
      setMessage('Inference profile saved. Enforcement remains deterministic and policy-owned.')
    } catch (error) { setMessage(error instanceof Error ? error.message : String(error)) } finally { setSaving(false) }
  }
  return <form className="settings-tab-pane inference-settings-pane" id="settings-panel-inference" role="tabpanel" aria-labelledby="settings-tab-inference" onSubmit={save}>
    <article className="settings-card">
      <div className="settings-card-header"><div className="settings-card-title"><BrainCircuit size={18} /><div><p className="eyebrow">ADVISORY INFERENCE</p><h3>Choose the analysis provider</h3></div></div><span className="live-status-pill"><span className="status-dot green" /> Policy authority stays local</span></div>
      <p className="settings-card-desc">Jev, Lila, local classifiers, and standard LLMs can annotate a decision after Shield policy evaluation. No provider can authorize, override, or delay enforcement.</p>
      <div className="settings-fields-grid"><div className="field-group"><label htmlFor="inference-provider">Provider</label><select id="inference-provider" value={form.inferenceProvider} onChange={(event) => update('inferenceProvider', event.target.value)} className="form-select"><option value="disabled">Disabled</option><option value="jev">Jev</option><option value="lila">Lila / JSON adapter</option><option value="local_classifier">Local open-source classifier</option><option value="llm">OpenAI-compatible LLM</option></select></div><div className="field-group"><label htmlFor="inference-model">Model</label><input id="inference-model" value={form.inferenceModel} onChange={(event) => update('inferenceModel', event.target.value)} placeholder="provider default" /></div><div className="field-group"><label htmlFor="inference-endpoint">Endpoint</label><input id="inference-endpoint" value={form.inferenceEndpoint} onChange={(event) => update('inferenceEndpoint', event.target.value)} placeholder="local or approved HTTPS endpoint" /><span className="field-hint">Required for Lila and LLM adapters.</span></div><div className="field-group"><label htmlFor="inference-prompt">Prompt profile</label><input id="inference-prompt" value={form.inferencePromptProfile} onChange={(event) => update('inferencePromptProfile', event.target.value)} /><span className="field-hint">Versioned profile name; raw prompts are not stored in event evidence.</span></div></div>
      <label className="toggle-item"><input type="checkbox" checked={Boolean(form.inferenceEnabled && form.inferenceProvider !== 'disabled')} onChange={(event) => update('inferenceEnabled', event.target.checked)} disabled={form.inferenceProvider === 'disabled'} /><div><b>Enable advisory inference</b><p>Runs after local policy and writes provider status into DecisionTrace.</p></div></label>
    </article>
    <article className="settings-card"><div className="settings-card-header"><div className="settings-card-title"><LockKeyhole size={18} /><h3>Boundaries &amp; budgets</h3></div><span className="live-status-pill">Fail-open to policy path</span></div><div className="settings-fields-grid"><div className="field-group"><label htmlFor="inference-timeout">Timeout (ms)</label><input id="inference-timeout" type="number" min="50" max="5000" value={form.inferenceTimeoutMs} onChange={(event) => update('inferenceTimeoutMs', event.target.value)} /></div><div className="field-group"><label htmlFor="inference-tokens">Max tokens</label><input id="inference-tokens" type="number" min="32" max="4096" value={form.inferenceMaxTokens} onChange={(event) => update('inferenceMaxTokens', event.target.value)} /></div><div className="field-group"><label htmlFor="inference-failure">Provider failure</label><select id="inference-failure" className="form-select" value={form.inferenceFailureMode} onChange={(event) => update('inferenceFailureMode', event.target.value)}><option value="continue_with_policy">Continue with deterministic policy</option><option value="mark_unavailable">Mark advisory unavailable</option></select></div><div className="field-group"><label htmlFor="inference-secret">Secret reference</label><input id="inference-secret" value={form.inferenceSecretRef} onChange={(event) => update('inferenceSecretRef', event.target.value)} placeholder="secret://shield/providers/name" /><span className="field-hint">Reference only. API keys never enter tenant settings.</span></div></div><div className="toggle-list inference-event-classes"><b>Analyze these event classes</b>{['agent_event', 'tool_call', 'process_activity', 'file_activity', 'network_flow', 'output_check'].map((eventClass) => <label className="toggle-item" key={eventClass}><input type="checkbox" checked={form.inferenceEventClasses.includes(eventClass)} onChange={() => toggleClass(eventClass)} /><div><b>{eventClass}</b></div></label>)}</div><p className="field-hint"><CheckCircle2 size={14} /> Redaction mode is strict and causal claims are prohibited by the shared DecisionTrace contract.</p></article>
    <div className="settings-actions-footer"><button type="submit" className="primary-btn" disabled={saving}><Save size={14} /> {saving ? 'Saving…' : 'Save inference profile'}</button>{message && <p className="form-message" role="status" aria-live="polite">{message}</p>}</div>
  </form>
}
