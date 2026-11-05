import { useEffect, useState } from 'react'
import { Cpu, ShieldCheck, LockKeyhole, CheckCircle, ArrowRight, AlertCircle, Laptop, Server } from 'lucide-react'
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
        else if (data.status === 'expired') setError('This pairing request has expired. Please run shield install or shield pair again.')
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
    <div className="signin-shell">
      <main className="signin-card" style={{ maxWidth: 540 }}>
        <header className="signin-header">
          <Brand />
          <p className="kicker">Hybrid Endpoint Confinement</p>
          <h2>{approved ? 'Device Connected' : 'Authorize Endpoint Agent'}</h2>
          <p className="signin-lede">
            {approved
              ? `Agent on ${pairInfo?.device_name || 'your device'} is now cryptographically paired.`
              : 'Authorize a local Shield protection and reasoning agent to bind to your workspace.'}
          </p>
        </header>

        {error && (
          <div className="form-message error" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {loading ? (
          <p className="device-detail-loading" style={{ textAlign: 'center', padding: '24px 0' }}>
            Fetching pairing request details…
          </p>
        ) : !pairInfo && !approved ? (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              const entered = new FormData(e.currentTarget).get('userCode')
              if (entered) setCode(String(entered).trim().toUpperCase())
            }}
            className="signin-form"
          >
            <div className="form-field">
              <label htmlFor="userCode">Pairing Code</label>
              <input
                id="userCode"
                name="userCode"
                placeholder="e.g. SHLD-9X4A"
                required
                autoFocus
                style={{ textTransform: 'uppercase', letterSpacing: 2, fontWeight: 700, fontSize: 18, textAlign: 'center' }}
              />
              <small className="muted">Enter the 8-character pairing code displayed in your terminal from <code>shield install</code> or <code>shield pair</code>.</small>
            </div>
            <button type="submit" className="button primary" style={{ width: '100%' }}>
              Continue <ArrowRight size={16} />
            </button>
          </form>
        ) : approved ? (
          <div style={{ textAlign: 'center', padding: '16px 0' }}>
            <div style={{ display: 'inline-flex', padding: 16, background: '#ecfdf5', borderRadius: '50%', color: '#059669', marginBottom: 16 }}>
              <CheckCircle size={40} />
            </div>
            <h3 style={{ margin: '0 0 8px 0' }}>Endpoint Paired & Active</h3>
            <p style={{ color: '#64748b', fontSize: 14, margin: '0 0 20px 0' }}>
              Your terminal has received its authentication credentials and initialized local enforcement.
            </p>
            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: 14, textAlign: 'left', fontSize: 13, marginBottom: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ color: '#64748b' }}>Device:</span>
                <b>{pairInfo?.device_name}</b>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ color: '#64748b' }}>Platform:</span>
                <span>{pairInfo?.device_type || 'Endpoint'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#64748b' }}>Confined DID:</span>
                <code style={{ fontSize: 11 }}>{(pairInfo?.agent_did || '').slice(0, 24)}…</code>
              </div>
            </div>
            <button type="button" className="button primary" style={{ width: '100%' }} onClick={onDone}>
              Go to Dashboard <ArrowRight size={16} />
            </button>
          </div>
        ) : (
          <div className="signin-form">
            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: 16, marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                <div style={{ padding: 10, background: '#e0f2fe', borderRadius: 8, color: '#0284c7' }}>
                  {isVirtual ? <Server size={22} /> : <Laptop size={22} />}
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: 16 }}>{pairInfo.device_name}</h3>
                  <small style={{ color: '#64748b' }}>
                    {isVirtual ? 'Virtual Machine' : 'Physical Device'} · {pairInfo.device_id.slice(0, 16)}…
                  </small>
                </div>
              </div>

              <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Agent DID:</span>
                  <code style={{ fontSize: 11 }}>{pairInfo.agent_did.slice(0, 24)}…</code>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Pairing Code:</span>
                  <b style={{ letterSpacing: 1 }}>{pairInfo.code}</b>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#64748b' }}>Expires in:</span>
                  <span>{Math.floor(pairInfo.expires_in / 60)}m {pairInfo.expires_in % 60}s</span>
                </div>
              </div>
            </div>

            <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: 12, marginBottom: 20, display: 'flex', gap: 10 }}>
              <ShieldCheck size={20} color="#16a34a" style={{ flexShrink: 0, marginTop: 2 }} />
              <div style={{ fontSize: 12, color: '#166534', lineHeight: 1.4 }}>
                <b>Cryptographic Confinement Guarantee:</b>
                <br />
                The Ed25519 private key was generated on this device and never leaves it. All policy decisions and telemetry from this device are signed locally.
              </div>
            </div>

            {!signedIn ? (
              <div>
                <p style={{ fontSize: 14, color: '#475569', marginBottom: 12, textAlign: 'center' }}>
                  Please sign in to your Shield account to authorize this device:
                </p>
                <button
                  type="button"
                  className="button primary"
                  style={{ width: '100%', marginBottom: 8 }}
                  onClick={onSignInRequired}
                >
                  <LockKeyhole size={16} /> Sign in to Authorize
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  type="button"
                  className="button secondary"
                  style={{ flex: 1 }}
                  onClick={() => setPairInfo(null)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="button primary"
                  style={{ flex: 2 }}
                  disabled={busy}
                  onClick={handleApprove}
                >
                  {busy ? 'Authorizing…' : 'Authorize & Pair Device'}
                </button>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
