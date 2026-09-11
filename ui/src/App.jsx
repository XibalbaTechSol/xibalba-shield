import { useState } from 'react'
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
