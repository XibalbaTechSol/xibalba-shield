import { useEffect, useState } from 'react'
import { ArrowRight, LockKeyhole, ShieldCheck } from 'lucide-react'
import { ShieldApi } from '../api'
import { Brand } from './Brand'
import { readSession, removeSession } from '../storage'

// Same origin as the UI: Caddy (and the Vite dev proxy) serve the UI and /api/* together, which
// is what lets the Secure, SameSite=Strict session cookie be stored and sent back.
const DEFAULT_CONTROL_PLANE = window.location.origin

export function SignIn({ back, connect }) {
  const [mode, setMode] = useState('login')
  const [error, setError] = useState(() => readSession('shield-auth-notice'))
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [providers, setProviders] = useState({ google: false })

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
    fetch('/api/shield/auth/providers')
      .then((res) => (res.ok ? res.json() : {}))
      .then((data) => {
        if (data && typeof data.google === 'boolean') {
          setProviders(data)
        }
      })
      .catch(() => {})
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

          {providers.google && (
            <>
              <a
                href="/api/shield/auth/oidc/login?redirect=1"
                className="google-sso-btn"
                id="google-sso-login-btn"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                </svg>
                {mode === 'signup' ? 'Sign up with Google' : 'Sign in with Google'}
              </a>
              <div className="auth-divider">
                <span>or continue with email</span>
              </div>
            </>
          )}

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
