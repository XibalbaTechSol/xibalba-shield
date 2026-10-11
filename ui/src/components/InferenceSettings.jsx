import { useEffect, useState } from 'react'
import { Brain, RotateCw } from 'lucide-react'
import {
  FAILURE_MODES, INFERENCE_PROVIDERS, REMOTE_PROVIDERS, inferenceFromSettings, parseEventClasses, validateInference,
} from '../inferenceSettings'

// Advisory inference (Jev and compatible providers). The model's output is ADVISORY ONLY: it runs after the local policy
// decision, in shadow mode, and cannot change that decision, the receipt, or enforcement. The backend enforces the same
// rules (shield/backend/settings.py); this form just never offers a value it would refuse.
export function InferenceSettings({ api }) {
  const [saved, setSaved] = useState({})
  const [form, setForm] = useState(() => toForm(inferenceFromSettings()))
  const [errors, setErrors] = useState({})
  const [status, setStatus] = useState({ kind: '', text: '' })

  useEffect(() => {
    let cancelled = false
    api.settings()
      .then((result) => {
        if (cancelled) return
        const settings = result.settings || {}
        setSaved(settings)
        setForm(toForm(inferenceFromSettings(settings)))
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [api])

  const set = (key) => (event) => {
    const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value
    setForm((current) => ({ ...current, [key]: value }))
    setErrors((current) => ({ ...current, [key]: undefined }))
  }

  const submit = async (event) => {
    event.preventDefault()
    const { errors: found, value } = validateInference({ ...form, inferenceEventClasses: parseEventClasses(form.inferenceEventClasses) })
    setErrors(found)
    if (Object.keys(found).length) {
      setStatus({ kind: 'error', text: 'Fix the highlighted fields before saving.' })
      return
    }
    setStatus({ kind: 'info', text: 'Saving advisory inference settings…' })
    try {
      const next = { ...saved, ...value }
      const result = await api.saveSettings(next)
      const stored = result.settings || next
      setSaved(stored)
      setForm(toForm(inferenceFromSettings(stored)))
      setStatus({ kind: 'ok', text: 'Advisory inference settings saved. Policy decisions are unaffected.' })
    } catch (error) {
      // The backend is the authority: show its message verbatim.
      setStatus({ kind: 'error', text: error instanceof Error ? error.message : String(error) })
    }
  }

  const remote = REMOTE_PROVIDERS.has(form.inferenceProvider)
  const field = (key) => ({ 'aria-invalid': errors[key] ? 'true' : undefined, 'aria-describedby': errors[key] ? `${key}-error` : undefined })
  const fieldError = (key) => errors[key] && <span id={`${key}-error`} className="field-hint field-error" role="alert">{errors[key]}</span>

  return (
    <form className="settings-tab-pane" id="settings-panel-inference" role="tabpanel" aria-labelledby="settings-tab-inference" onSubmit={submit} noValidate>
      <article className="settings-card">
        <div className="settings-card-header">
          <div className="settings-card-title"><Brain size={18} /><h3>Advisory inference</h3></div>
          <span className="live-status-pill"><span className="status-dot green" /> Shadow only</span>
        </div>
        <p className="settings-card-desc">
          An optional provider suggests a risk category and likely next steps for each decision. It runs after the local policy has
          already decided and cannot allow, deny, contain or change a receipt. Content is redacted before it leaves the host, and
          credentials are referenced by name, never typed here.
        </p>

        <label className="toggle-item">
          <input type="checkbox" checked={form.inferenceEnabled} onChange={set('inferenceEnabled')} />
          <div><b>Enable advisory inference</b><p>Off by default. A provider of “Disabled” keeps it off regardless.</p></div>
        </label>

        <div className="settings-fields-grid">
          <label>Provider
            <select value={form.inferenceProvider} onChange={set('inferenceProvider')} {...field('inferenceProvider')}>
              {INFERENCE_PROVIDERS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
            {fieldError('inferenceProvider')}
          </label>
          <label>If the provider fails
            <select value={form.inferenceFailureMode} onChange={set('inferenceFailureMode')}>
              {FAILURE_MODES.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
            </select>
            <span className="field-hint">Either way the policy decision stands.</span>
          </label>
          <label>Model
            <input type="text" value={form.inferenceModel} onChange={set('inferenceModel')} maxLength={128} {...field('inferenceModel')} />
            {fieldError('inferenceModel')}
          </label>
          <label>Prompt profile
            <input type="text" value={form.inferencePromptProfile} onChange={set('inferencePromptProfile')} maxLength={128} {...field('inferencePromptProfile')} />
            {fieldError('inferencePromptProfile')}
          </label>
          <label>Endpoint{remote ? ' (required)' : ''}
            <input type="url" inputMode="url" placeholder="https://" value={form.inferenceEndpoint} onChange={set('inferenceEndpoint')} maxLength={512} {...field('inferenceEndpoint')} />
            <span className="field-hint">HTTPS, or http on this machine only.</span>
            {fieldError('inferenceEndpoint')}
          </label>
          <label>Secret reference
            <input type="text" placeholder="secret://name" autoComplete="off" value={form.inferenceSecretRef} onChange={set('inferenceSecretRef')} maxLength={256} {...field('inferenceSecretRef')} />
            <span className="field-hint">The host resolves it. Raw API keys are refused.</span>
            {fieldError('inferenceSecretRef')}
          </label>
          <label>Timeout (ms)
            <input type="number" inputMode="numeric" min={50} max={5000} step={1} value={form.inferenceTimeoutMs} onChange={set('inferenceTimeoutMs')} {...field('inferenceTimeoutMs')} />
            {fieldError('inferenceTimeoutMs')}
          </label>
          <label>Max tokens
            <input type="number" inputMode="numeric" min={32} max={4096} step={1} value={form.inferenceMaxTokens} onChange={set('inferenceMaxTokens')} {...field('inferenceMaxTokens')} />
            {fieldError('inferenceMaxTokens')}
          </label>
          <label>Temperature
            <input type="number" inputMode="decimal" min={0} max={1} step={0.05} value={form.inferenceTemperature} onChange={set('inferenceTemperature')} {...field('inferenceTemperature')} />
            {fieldError('inferenceTemperature')}
          </label>
          <label>Event classes
            <input type="text" placeholder="process_activity, file_activity (blank = all)" value={form.inferenceEventClasses} onChange={set('inferenceEventClasses')} {...field('inferenceEventClasses')} />
            {fieldError('inferenceEventClasses')}
          </label>
        </div>

        <dl className="session-props-grid">
          <div><dt>Execution mode</dt><dd>Shadow only (fixed)</dd></div>
          <div><dt>Redaction</dt><dd>Strict (fixed)</dd></div>
        </dl>
      </article>

      <div className="settings-actions-footer">
        <button type="submit" className="primary-btn"><RotateCw size={14} /> Save advisory inference</button>
      </div>
      {status.text && <p className={`form-message${status.kind === 'error' ? ' field-error' : ''}`} aria-live="polite" data-status={status.kind}>{status.text}</p>}
    </form>
  )
}

// Numbers are held as strings while typing; the event-class list is a comma-separated string.
function toForm(values) {
  return {
    ...values,
    inferenceTimeoutMs: String(values.inferenceTimeoutMs),
    inferenceMaxTokens: String(values.inferenceMaxTokens),
    inferenceTemperature: String(values.inferenceTemperature),
    inferenceEventClasses: (values.inferenceEventClasses || []).join(', '),
  }
}
