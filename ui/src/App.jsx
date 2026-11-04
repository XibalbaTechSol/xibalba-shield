import { useEffect, useState } from 'react'
import { ShieldApi } from './api'
import { Landing } from './components/Landing'
import { SignIn } from './components/SignIn'
import { Dashboard } from './components/Dashboard'
import './App.css'
import { readSession, writeSession, removeSession } from './storage'

export default function App() {
  const [view, setView] = useState(() =>
    readSession('shield-session')
      ? 'dashboard'
      : 'landing'
  )

  const [connection, setConnection] = useState(() =>
    JSON.parse(readSession('shield-connection', '{}'))
  )
  const connect = (conn) => {
    setConnection(conn)
    writeSession('shield-connection', JSON.stringify(conn))
    writeSession('shield-session', '1')
    setView('dashboard')
  }

  useEffect(() => {
    // Automatically restore session if an active cookie exists (e.g. returning from Google OAuth)
    const checkMe = async () => {
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
    checkMe()
  }, [])

  const logout = async (notice = '') => {
    // The session lives in an HttpOnly cookie this code cannot see, so the server call is the
    // only way to revoke it and clear the cookie. Gate on the tenant alone.
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

  if (view === 'landing') {
    return <Landing next={() => setView('signin')} />
  }

  if (view === 'signin') {
    return <SignIn back={() => setView('landing')} connect={connect} />
  }

  return <Dashboard connection={connection} logout={logout} />
}
