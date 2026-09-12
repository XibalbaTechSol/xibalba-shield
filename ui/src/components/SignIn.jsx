import { useEffect, useState } from 'react'
import { ArrowRight, LockKeyhole, ShieldCheck } from 'lucide-react'
import { ShieldApi } from '../api'
import { Brand } from './Brand'
import { readSession, removeSession } from '../storage'

const DEFAULT_CONTROL_PLANE = 'http://127.0.0.1:8765'

export function SignIn({ back, connect }) {
  const [mode, setMode] = useState('login')
  const [error, setError] = useState(() => readSession('shield-auth-notice'))
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const connectLocal = async () => {
    setBusy(true)
    setError('')
    try {
      const response = await fetch('/__shield_dev/session', { method: 'POST', cache: 'no-store' })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(payload.error || 'Local secure session is unavailable')
      const connection = { tenant: payload.tenant_id, token: '__shield_local_proxy__', baseUrl: window.location.origin, account: null, localDev: true }
      await new ShieldApi(connection.baseUrl, connection.tenant, connection.token).dashboard()
      connect(connection)
    } catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setBusy(false) }
  }

  useEffect(() => {
    removeSession('shield-auth-notice')
  }, [])

  const submit = async (event) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const baseUrl = DEFAULT_CONTROL_PLANE
    setBusy(true)
    setError('')

    try {
      const email = String(form.get('email') || '').trim()
      const password = String(form.get('password') || '')
      const payload = await new ShieldApi(baseUrl, '', '').auth(mode, {
        email,
        password,
        display_name: String(form.get('displayName') || ''),
        tenant_id: String(form.get('tenant') || '').trim(),
      })
      const tenant = payload.tenant_id
      // No token to carry: the session is an HttpOnly cookie the browser attaches itself.
      const api = new ShieldApi(baseUrl, tenant, '')
      await api.dashboard()
      connect({
        tenant,
        token: '',
        baseUrl,
        account: { ...payload.account, session_expires_at: payload.session_expires_at },
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="auth">
      <button className="auth-back" onClick={back} type="button">
        ← Back to Shield
      </button>
      <section className="auth-story">
        <Brand />
        <div className="auth-story-body">
          <p className="eyebrow">SECURE OPERATOR ACCESS</p>
          <h1>Your fleet.<br />One trusted boundary.</h1>
          <p>Sign in to view your protected devices, decisions, and evidence.</p>
        </div>
        <aside>
          <ShieldCheck aria-hidden="true" />
          <span>
            <b>Local-first authentication</b>
            <small>Your session is held in a secure cookie the browser cannot read.</small>
          </span>
        </aside>
      </section>

      <section className="auth-form">
        <form onSubmit={submit}>
          <span className="lock">
            <LockKeyhole aria-hidden="true" />
          </span>
          {import.meta.env.DEV && <button className="local-connect" type="button" disabled={busy} onClick={connectLocal}><ShieldCheck size={16} /> Connect to local Shield</button>}
          <div className="auth-tabs" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={mode === 'login'}
                className={mode === 'login' ? 'active' : ''}
                onClick={() => setMode('login')}
              >
                Sign in
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={mode === 'signup'}
                className={mode === 'signup' ? 'active' : ''}
                onClick={() => setMode('signup')}
              >
                Create account
              </button>
          </div>
          <h2>
            {mode === 'signup' ? 'Create your Shield account' : 'Welcome back'}
          </h2>
          <p>
            {mode === 'signup'
              ? 'Create an operator account for your organization.'
              : 'Enter your email and password to continue.'}
          </p>

          <>
              <label>
                Email
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoFocus
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@organization.com"
                />
              </label>
              {mode === 'signup' && (
                <>
                  <label htmlFor="displayName">
                    Display name
                    <input
                      id="displayName"
                      name="displayName"
                      required
                      placeholder="Alice Chen"
                    />
                  </label>
                  <label htmlFor="tenant">
                    Organization ID
                    <input id="tenant" name="tenant" placeholder="acme-production" required />
                  </label>
                </>
              )}
              <label>
                Password
                <input
                  id="password"
                  name="password"
                  type="password"
                  minLength={10}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                />
              </label>
              {import.meta.env.DEV && mode === 'login' && (
                <div className="dev-auth-helper">
                  <span>Quick-fill:</span>
                  <button
                    type="button"
                    className="chip-btn"
                    onClick={() => {
                      setEmail('admin@tenant-a.com')
                      setPassword('AdminPassword123!')
                    }}
                  >
                    admin@tenant-a.com
                  </button>
                  <button
                    type="button"
                    className="chip-btn"
                    onClick={() => {
                      setEmail('dev@example.com')
                      setPassword('DevPassword123!')
                    }}
                  >
                    dev@example.com
                  </button>
                </div>
              )}
            </>

          {error && <div className="auth-error" role="alert">{error}</div>}

          <button className="primary submit" disabled={busy} type="submit">
            {busy ? 'Connecting…' : mode === 'signup' ? 'Create account' : 'Sign in'}{' '}
            <ArrowRight aria-hidden="true" />
          </button>
          <small className="session-note">
            <LockKeyhole aria-hidden="true" /> HttpOnly session cookie
          </small>
        </form>
      </section>
    </main>
  )
}
