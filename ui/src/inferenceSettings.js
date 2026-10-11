// Client-side mirror of the backend's inference settings rules (shield/backend/settings.py, validate_settings).
// The BACKEND stays the authority: it re-validates every save. This exists so an operator sees a precise message
// before a round trip, and so the form can never offer a value the backend is known to refuse
// (execution mode is shadow-only, redaction is strict-only, secrets are `secret://` references, never raw keys).

export const INFERENCE_PROVIDERS = [
  { value: 'disabled', label: 'Disabled' },
  { value: 'jev', label: 'Jev (deterministic fixture)' },
  { value: 'local_classifier', label: 'Local classifier' },
  { value: 'lila', label: 'Lila-compatible JSON adapter' },
  { value: 'llm', label: 'OpenAI-compatible LLM' },
]

export const FAILURE_MODES = [
  { value: 'continue_with_policy', label: 'Keep the policy decision (recommended)' },
  { value: 'mark_unavailable', label: 'Mark the advisory unavailable' },
]

// Providers that call out over the network and therefore need an endpoint.
export const REMOTE_PROVIDERS = new Set(['lila', 'llm'])

export const INFERENCE_DEFAULTS = {
  inferenceEnabled: false,
  inferenceProvider: 'disabled',
  inferenceMode: 'shadow',
  inferenceModel: '',
  inferenceEndpoint: '',
  inferencePromptProfile: '',
  inferenceSecretRef: '',
  inferenceTimeoutMs: 1000,
  inferenceMaxTokens: 256,
  inferenceTemperature: 0,
  inferenceRedactionMode: 'strict',
  inferenceFailureMode: 'continue_with_policy',
  inferenceEventClasses: [],
}

export const INFERENCE_KEYS = Object.keys(INFERENCE_DEFAULTS)

/** Pull just the inference fields out of a saved settings object, filling any gap with the safe default. */
export function inferenceFromSettings(settings = {}) {
  const out = {}
  for (const key of INFERENCE_KEYS) out[key] = settings[key] === undefined ? INFERENCE_DEFAULTS[key] : settings[key]
  return out
}

/** "a, b ,c" -> ['a','b','c'] (blanks dropped, duplicates removed, order kept). */
export function parseEventClasses(text) {
  const seen = new Set()
  const out = []
  for (const part of String(text || '').split(',')) {
    const item = part.trim()
    if (item && !seen.has(item)) { seen.add(item); out.push(item) }
  }
  return out
}

/**
 * Validate a form's values. Returns { errors: {field: message}, value: canonical settings subset }.
 * `form` holds strings for the numeric fields (as typed); `value` has real numbers.
 */
export function validateInference(form) {
  const errors = {}
  const provider = form.inferenceProvider
  if (!INFERENCE_PROVIDERS.some((p) => p.value === provider)) errors.inferenceProvider = 'Choose a provider.'

  const text = (key, max, label) => {
    const v = String(form[key] ?? '')
    if (v.length > max) errors[key] = `${label} must be at most ${max} characters.`
    return v
  }
  const model = text('inferenceModel', 128, 'Model')
  const profile = text('inferencePromptProfile', 128, 'Prompt profile')
  const endpoint = text('inferenceEndpoint', 512, 'Endpoint')
  const secretRef = text('inferenceSecretRef', 256, 'Secret reference')

  if (endpoint && !errors.inferenceEndpoint) {
    let url = null
    try { url = new URL(endpoint) } catch { /* handled below */ }
    if (!url || !['http:', 'https:'].includes(url.protocol) || !url.host) {
      errors.inferenceEndpoint = 'Endpoint must be an http(s) URL.'
    } else if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
      errors.inferenceEndpoint = 'A non-local endpoint must use HTTPS.'
    }
  }
  if (secretRef && !secretRef.startsWith('secret://') && !errors.inferenceSecretRef) {
    errors.inferenceSecretRef = 'Use a secret:// reference. Raw keys are never accepted or stored here.'
  }

  const whole = (key, lo, hi, label) => {
    const raw = String(form[key] ?? '').trim()
    const n = Number(raw)
    if (raw === '' || !Number.isInteger(n) || n < lo || n > hi) errors[key] = `${label} must be a whole number from ${lo} to ${hi}.`
    return n
  }
  const timeout = whole('inferenceTimeoutMs', 50, 5000, 'Timeout (ms)')
  const maxTokens = whole('inferenceMaxTokens', 32, 4096, 'Max tokens')
  const tempRaw = String(form.inferenceTemperature ?? '').trim()
  const temperature = Number(tempRaw)
  if (tempRaw === '' || !Number.isFinite(temperature) || temperature < 0 || temperature > 1) errors.inferenceTemperature = 'Temperature must be between 0 and 1.'

  const classes = Array.isArray(form.inferenceEventClasses) ? form.inferenceEventClasses : parseEventClasses(form.inferenceEventClasses)
  if (classes.some((c) => c.length > 64)) errors.inferenceEventClasses = 'Each event class must be at most 64 characters.'
  else if (classes.length > 32) errors.inferenceEventClasses = 'At most 32 event classes.'

  // Enabling a network provider without a destination could never work: say so now.
  const enabled = Boolean(form.inferenceEnabled) && provider !== 'disabled'
  if (enabled && REMOTE_PROVIDERS.has(provider) && !endpoint && !errors.inferenceEndpoint) {
    errors.inferenceEndpoint = 'This provider needs an endpoint.'
  }

  return {
    errors,
    value: {
      inferenceEnabled: enabled,
      inferenceProvider: provider,
      inferenceMode: 'shadow',
      inferenceModel: model,
      inferenceEndpoint: endpoint,
      inferencePromptProfile: profile,
      inferenceSecretRef: secretRef,
      inferenceTimeoutMs: timeout,
      inferenceMaxTokens: maxTokens,
      inferenceTemperature: temperature,
      inferenceRedactionMode: 'strict',
      inferenceFailureMode: form.inferenceFailureMode,
      inferenceEventClasses: classes,
    },
  }
}
