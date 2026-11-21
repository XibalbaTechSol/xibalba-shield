import { useEffect, useState } from 'react'
import { ShieldApi } from './api'
import { Landing } from './components/Landing'
import { SignIn } from './components/SignIn'
import { Dashboard } from './components/Dashboard'
import { DevicePair } from './components/DevicePair'
import './App.css'
import { readSession, writeSession, removeSession } from './storage'

export default function App() {
  const isPairRoute = () => {
    try {
      const hash = window.location.hash || ''
      const search = window.location.search || ''
      return hash.startsWith('#pair') || search.includes('pair=')
    } catch {
      return false
    }
  }

  const getInitialRouteState = () => {
    try {
      const hash = window.location.hash || ''
      if (isPairRoute()) return { view: 'pair', mode: 'login' }
      if (hash.startsWith('#signup')) return { view: 'signin', mode: 'signup' }
      if (hash.startsWith('#signin') || hash.startsWith('#login')) return { view: 'signin', mode: 'login' }
      if (hash.startsWith('#dashboard') || hash.startsWith('#console')) {
        return readSession('shield-session')
          ? { view: 'dashboard', mode: 'login' }
          : { view: 'signin', mode: 'login' }
      }
      return readSession('shield-session')
        ? { view: 'dashboard', mode: 'login' }
        : { view: 'landing', mode: 'login' }
    } catch {
      return { view: 'landing', mode: 'login' }
    }
  }

  const [routeState, setRouteState] = useState(getInitialRouteState)
  const view = routeState.view
  const authMode = routeState.mode

  const setView = (newView, mode = 'login') => {
    const validMode = mode === 'signup' ? 'signup' : 'login'
    setRouteState({ view: newView, mode: validMode })
    try {
      if (newView === 'signin') {
        window.location.hash = validMode === 'signup' ? '#signup' : '#signin'
      } else if (newView === 'landing') {
        if (window.location.hash.startsWith('#signin') || window.location.hash.startsWith('#signup') || window.location.hash.startsWith('#pair')) {
          window.history.replaceState(null, '', window.location.pathname)
        }
      } else if (newView === 'dashboard') {
        if (window.location.hash.startsWith('#signin') || window.location.hash.startsWith('#signup')) {
          window.location.hash = '#dashboard'
        }
      }
    } catch {
      /* ignore hash errors */
    }
  }

  const [connection, setConnection] = useState(() =>
    JSON.parse(readSession('shield-connection', '{}'))
  )
  const connect = (conn) => {
    setConnection(conn)
    writeSession('shield-connection', JSON.stringify(conn))
    writeSession('shield-session', '1')
    if (isPairRoute()) {
      setView('pair')
    } else {
      setView('dashboard')
    }
  }

  useEffect(() => {
    const handleHash = () => {
      const hash = window.location.hash || ''
      if (isPairRoute()) {
        setRouteState({ view: 'pair', mode: 'login' })
      } else if (hash.startsWith('#signup')) {
        setRouteState({ view: 'signin', mode: 'signup' })
      } else if (hash.startsWith('#signin') || hash.startsWith('#login')) {
        setRouteState({ view: 'signin', mode: 'login' })
      } else if (hash.startsWith('#dashboard') || hash.startsWith('#console')) {
        if (readSession('shield-session')) {
          setRouteState({ view: 'dashboard', mode: 'login' })
        } else {
          setRouteState({ view: 'signin', mode: 'login' })
        }
      }
    }
    window.addEventListener('hashchange', handleHash)
    return () => window.removeEventListener('hashchange', handleHash)
  }, [])

  useEffect(() => {
    // Automatically restore session if returning from Supabase OAuth or active cookie exists
    const checkOAuthAndSession = async () => {
      const hash = window.location.hash || ''
      if (hash && hash.includes('access_token=')) {
        const params = new URLSearchParams(hash.replace(/^#/, ''))
        const accessToken = params.get('access_token')
        if (accessToken) {
          try {
            const response = await fetch('/api/shield/auth/supabase/session', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ access_token: accessToken }),
            })
            if (response.ok) {
              const payload = await response.json()
              if (payload && payload.account && payload.tenant_id) {
                window.history.replaceState(null, '', window.location.pathname)
                connect({
                  tenant: payload.tenant_id,
                  token: '',
                  baseUrl: window.location.origin,
                  account: { ...payload.account, session_expires_at: payload.session_expires_at },
                })
                return
              }
            }
          } catch {
            /* fall back to normal checkMe */
          }
        }
      }

      try {
        const response = await fetch('/api/shield/auth/me', { credentials: 'include' })
        if (response.ok) {
          const payload = await response.json()
          if (payload && payload.account && payload.tenant_id) {
            connect({
              tenant: payload.tenant_id,
              token: '',
              baseUrl: window.location.origin,
              account: { ...payload.account, session_expires_at: payload.session_expires_at },
            })
            if (window.location.search) {
              const url = new URL(window.location.href)
              url.search = ''
              window.history.replaceState({}, document.title, url.toString())
            }
          }
        } else if (response.status === 401 && readSession('shield-session')) {
          removeSession('shield-session')
          removeSession('shield-connection')
          setView('landing')
        }
      } catch {
        /* local sign-out / network error */
      }
    }
    checkOAuthAndSession()
  }, [])

  const signOutLocally = (notice = '') => {
    const textNotice = typeof notice === 'string' ? notice : ''
    if (textNotice) {
      writeSession('shield-auth-notice', textNotice)
    } else {
      removeSession('shield-auth-notice')
    }
    removeSession('shield-session')
    removeSession('shield-connection')
    setView(textNotice ? 'signin' : 'landing')
  }

  // User-initiated sign-out. The session lives in an HttpOnly cookie this code cannot see, so the
  // server call is the only way to revoke it and clear the cookie. Gate on the tenant alone.
  const logout = async (notice = '') => {
    if (connection.tenant) {
      try {
        await new ShieldApi(connection.baseUrl, connection.tenant, connection.token).auth(
          'logout',
          { tenant_id: connection.tenant }
        )
      } catch {
        /* local sign-out still proceeds if the control plane is unavailable */
      }
    }
    signOutLocally(notice)
  }

  // A dashboard poll was refused. Never revoke the session on the strength of that alone: the
  // cookie is shared by every tab, so a tab still showing an old tenant (the cookie now belongs
  // to another one) would otherwise end the live session of the tab the user is working in.
  // Ask the server who this browser is now, and only sign this tab out locally.
  const handleUnauthorized = async () => {
    if (connection.token) {
      // Machine-minted admin token, not a cookie session: nothing shared to protect.
      await logout('Session expired. Sign in again to reconnect to this tenant.')
      return
    }
    let me = null
    try {
      const response = await fetch('/api/shield/auth/me', { credentials: 'include' })
      if (response.ok) {
        me = await response.json()
      } else if (response.status !== 401) {
        return // control plane trouble, not a lost session: the next poll retries
      }
    } catch {
      return // network error: the next poll retries
    }
    if (me && me.account && me.tenant_id) {
      if (me.tenant_id === connection.tenant) return // the session is fine; the refusal was transient
      signOutLocally(`You are signed in to ${me.tenant_id} in another tab. Sign in again to return to ${connection.tenant}.`)
      return
    }
    signOutLocally('Session expired. Sign in again to reconnect to this tenant.')
  }

  if (view === 'landing') {
    return <Landing next={(mode = 'login') => setView('signin', mode)} />
  }

  if (view === 'signin') {
    return (
      <SignIn
        back={() => setView(isPairRoute() ? 'pair' : 'landing')}
        connect={connect}
        initialMode={authMode}
      />
    )
  }

  if (view === 'pair') {
    return (
      <DevicePair
        onDone={() => {
          if (window.location.hash.startsWith('#pair')) {
            window.location.hash = ''
          }
          setView(readSession('shield-session') ? 'dashboard' : 'landing')
        }}
        onSignInRequired={() => setView('signin', 'login')}
      />
    )
  }

  return <Dashboard connection={connection} logout={logout} onUnauthorized={handleUnauthorized} />
}
