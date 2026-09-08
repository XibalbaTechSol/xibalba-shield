import { useState } from 'react'
import { ShieldApi } from './api'
import { Landing } from './components/Landing'
import { SignIn } from './components/SignIn'
import { Dashboard } from './components/Dashboard'
import './App.css'

export default function App() {
  const [view, setView] = useState(() =>
    sessionStorage.getItem('shield-session')
      ? 'dashboard'
      : 'landing'
  )

  const [connection, setConnection] = useState(() =>
    JSON.parse(sessionStorage.getItem('shield-connection') || '{}')
  )

  const connect = (conn) => {
    setConnection(conn)
    sessionStorage.setItem('shield-connection', JSON.stringify(conn))
    sessionStorage.setItem('shield-session', '1')
    setView('dashboard')
  }

  const logout = async (notice = '') => {
    if (connection.tenant && connection.token) {
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
      sessionStorage.setItem('shield-auth-notice', textNotice)
    } else {
      sessionStorage.removeItem('shield-auth-notice')
    }
    sessionStorage.removeItem('shield-session')
    sessionStorage.removeItem('shield-connection')
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
