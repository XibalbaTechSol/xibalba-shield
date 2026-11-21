import { useEffect, useState } from 'react'
import {
  Cpu,
  ShieldCheck,
  LockKeyhole,
  CheckCircle,
  ArrowRight,
  ArrowLeft,
  AlertCircle,
  Laptop,
  Server,
} from 'lucide-react'
import { Brand } from './Brand'
import { readSession } from '../storage'

export function DevicePair({ code: initialCode = '', onDone, onSignInRequired }) {
  const [code, setCode] = useState(() => {
    if (initialCode) return initialCode
    try {
      const hash = window.location.hash || ''
      if (hash.includes('code=')) {
        return hash.split('code=')[1].split('&')[0]
      }
      const params = new URLSearchParams(window.location.search)
      return params.get('code') || ''
    } catch {
      return ''
    }
  })

  const [pairInfo, setPairInfo] = useState(null)
  const [loading, setLoading] = useState(Boolean(code))
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [approved, setApproved] = useState(false)
  const [signedIn, setSignedIn] = useState(Boolean(readSession('shield-session')))

  useEffect(() => {
    // Check if user is authenticated
    fetch('/api/shield/auth/me', { credentials: 'include' })
      .then((res) => {
        if (res.ok) setSignedIn(true)
        else setSignedIn(false)
      })
      .catch(() => setSignedIn(false))
  }, [])

  useEffect(() => {
    if (!code) {
      setLoading(false)
      return
    }
    setLoading(true)
    setError('')
    fetch(`/api/shield/device/pair/${encodeURIComponent(code)}`)
      .then((res) => {
        if (!res.ok) throw new Error('Pairing request not found or expired')
        return res.json()
      })
      .then((data) => {
        setPairInfo(data)
        if (data.status === 'approved') setApproved(true)
        else if (data.status === 'expired')
          setError('This pairing request has expired. Please run shield install or shield pair again.')
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => setLoading(false))
  }, [code])

  const handleApprove = async () => {
    if (!code) return
    setBusy(true)
    setError('')
    try {
      const response = await fetch(`/api/shield/device/pair/${encodeURIComponent(code)}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({}),
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) {
        throw new Error(payload.error || 'Failed to authorize device')
      }
      setApproved(true)
      // Signal local loopback listener if provided
      if (payload.callback_url) {
        try {
          const callbackTarget = new URL(payload.callback_url)
          callbackTarget.searchParams.set('token', payload.device_token)
          callbackTarget.searchParams.set('tenant_id', payload.tenant_id)
          callbackTarget.searchParams.set('device_id', payload.device_id)
          callbackTarget.searchParams.set('agent_did', payload.agent_did)
          fetch(callbackTarget.toString(), { mode: 'no-cors' }).catch(() => {})
        } catch {
          /* loopback is best-effort */
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const isVirtual = pairInfo?.device_type?.toLowerCase().includes('virtual')

  return (
    <main className="auth">
      <button
        type="button"
        className="auth-back"
        onClick={onDone}
        aria-label="Return to previous screen"
      >
        <ArrowLeft size={16} /> Back
      </button>

      <section className="auth-story">
        <Brand />
        <div className="auth-story-body">
          <p className="eyebrow">Hybrid Endpoint Confinement</p>
          <h1>Authorize Endpoint Agent</h1>
          <p>
            Bind local Shield protection and reasoning daemons to your organization with
            device-isolated cryptographic confinement.
          </p>
        </div>
        <aside>
          <ShieldCheck />
          <span>
            <b>Cryptographic Confinement Guarantee</b>
            <small>
              The Ed25519 private key was generated on the endpoint and never leaves it.
              All policy decisions and telemetry are signed locally.
            </small>
          </span>
        </aside>
      </section>

      <section className="auth-form">
        <div style={{ width: 'min(440px, 100%)', margin: 'auto 0' }}>
          <div className="lock">
            <Cpu />
          </div>

          <h2>{approved ? 'Device Connected' : 'Endpoint Pairing'}</h2>
          <p className="sub">
            {approved
              ? `Agent on ${pairInfo?.device_name || 'your device'} is now cryptographically paired.`
              : 'Enter the pairing code or approve authorization to bind to your workspace.'}
          </p>

          {error && (
            <div className="auth-error" style={{ marginBottom: 16 }}>
              <AlertCircle size={16} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {loading ? (
            <div style={{ textAlign: 'center', padding: '32px 0', color: 'var(--muted)' }}>
              Fetching pairing request details…
            </div>
          ) : !pairInfo && !approved ? (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                const entered = new FormData(e.currentTarget).get('userCode')
                if (entered) setCode(String(entered).trim().toUpperCase())
              }}
            >
              <label htmlFor="userCode">
                Pairing Code
                <input
                  id="userCode"
                  name="userCode"
                  placeholder="SHLD-9X4A"
                  required
                  autoFocus
                  style={{
                    textTransform: 'uppercase',
                    letterSpacing: '0.12em',
                    fontWeight: 700,
                    fontSize: 16,
                    textAlign: 'center',
                    fontFamily: 'var(--font-mono)',
                  }}
                />
              </label>
              <p style={{ color: 'var(--muted)', fontSize: 12, lineHeight: 1.5, margin: '4px 0 16px' }}>
                Enter the 8-character pairing code displayed in your terminal from <code>shield install</code> or <code>shield pair</code>.
              </p>
              <button type="submit" className="primary" style={{ width: '100%', padding: '10px 16px' }}>
                Continue <ArrowRight size={16} />
              </button>
            </form>
          ) : approved ? (
            <div style={{ textAlign: 'center', padding: '12px 0' }}>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: 56,
                  height: 56,
                  background: 'color-mix(in srgb, var(--accent) 15%, transparent)',
                  border: '1px solid var(--accent)',
                  color: 'var(--accent-text)',
                  marginBottom: 16,
                }}
              >
                <CheckCircle size={32} />
              </div>
              <h3 style={{ margin: '0 0 8px 0', fontSize: 18, color: 'var(--text)' }}>
                Endpoint Paired & Active
              </h3>
              <p style={{ color: 'var(--muted)', fontSize: 13, margin: '0 0 20px 0', lineHeight: 1.5 }}>
                Your terminal has received its authentication credentials and initialized local enforcement.
              </p>
              <div
                style={{
                  background: 'var(--panel-elevated)',
                  border: '1px solid var(--line)',
                  padding: 14,
                  textAlign: 'left',
                  fontSize: 13,
                  marginBottom: 20,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--muted)' }}>Device:</span>
                  <b style={{ color: 'var(--text)' }}>{pairInfo?.device_name}</b>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--muted)' }}>Platform:</span>
                  <span style={{ color: 'var(--text)' }}>{pairInfo?.device_type || 'Endpoint'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--muted)' }}>Confined DID:</span>
                  <code style={{ fontSize: 11, color: 'var(--accent-text)' }}>
                    {(pairInfo?.agent_did || '').slice(0, 24)}…
                  </code>
                </div>
              </div>
              <button
                type="button"
                className="primary"
                style={{ width: '100%', padding: '10px 16px' }}
                onClick={onDone}
              >
                Go to Dashboard <ArrowRight size={16} />
              </button>
            </div>
          ) : (
            <div>
              <div
                style={{
                  background: 'var(--panel-elevated)',
                  border: '1px solid var(--line)',
                  padding: 16,
                  marginBottom: 16,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
                  <div
                    style={{
                      padding: 8,
                      background: 'color-mix(in srgb, var(--accent) 15%, transparent)',
                      border: '1px solid var(--line)',
                      color: 'var(--accent-text)',
                      display: 'flex',
                    }}
                  >
                    {isVirtual ? <Server size={22} /> : <Laptop size={22} />}
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 15, color: 'var(--text)' }}>{pairInfo.device_name}</h3>
                    <small style={{ color: 'var(--muted)' }}>
                      {isVirtual ? 'Virtual Machine' : 'Physical Device'} · {pairInfo.device_id.slice(0, 16)}…
                    </small>
                  </div>
                </div>

                <div style={{ display: 'grid', gap: 8, fontSize: 12.5 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--muted)' }}>Agent DID:</span>
                    <code style={{ fontSize: 11, color: 'var(--accent-text)' }}>
                      {pairInfo.agent_did.slice(0, 24)}…
                    </code>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--muted)' }}>Pairing Code:</span>
                    <b style={{ letterSpacing: '0.08em', color: 'var(--text)' }}>{pairInfo.code}</b>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--muted)' }}>Expires in:</span>
                    <span style={{ color: 'var(--text)' }}>
                      {Math.floor(pairInfo.expires_in / 60)}m {pairInfo.expires_in % 60}s
                    </span>
                  </div>
                </div>
              </div>

              {!signedIn ? (
                <div>
                  <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 14, textAlign: 'center' }}>
                    Please sign in to your Shield account to authorize this device:
                  </p>
                  <button
                    type="button"
                    className="primary"
                    style={{ width: '100%', padding: '10px 16px', marginBottom: 8 }}
                    onClick={onSignInRequired}
                  >
                    <LockKeyhole size={16} /> Sign in to Authorize
                  </button>
                </div>
              ) : (
                <div style={{ display: 'flex', gap: 10 }}>
                  <button
                    type="button"
                    className="button"
                    style={{
                      flex: 1,
                      padding: '10px 16px',
                      background: 'transparent',
                      border: '1px solid var(--line)',
                      color: 'var(--text)',
                      cursor: 'pointer',
                    }}
                    onClick={() => setPairInfo(null)}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="primary"
                    style={{ flex: 2, padding: '10px 16px' }}
                    disabled={busy}
                    onClick={handleApprove}
                  >
                    {busy ? 'Authorizing…' : 'Authorize & Pair Device'}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </section>
    </main>
  )
}
