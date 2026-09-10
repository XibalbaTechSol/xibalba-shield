import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  Bell,
  CircleUserRound,
  Database,
  FileCheck2,
  Gauge,
  HardDrive,
  LockKeyhole,
  LogOut,
  Menu,
  ServerCog,
  Sliders,
  TriangleAlert,
  X,
  Shield,
} from 'lucide-react'
import { ShieldApi } from '../api'
import { Brand } from './Brand'
import { Overview } from './Overview'
import { ResourceView } from './ResourceView'

const NAV = [
  ['overview', Gauge, 'Overview'],
  ['devices', HardDrive, 'Devices'],
  ['agent', Shield, 'Shield agent'],
  ['events', Activity, 'Event stream'],
  ['enforcement', LockKeyhole, 'Enforcement'],
  ['policies', FileCheck2, 'Policies'],
  ['transactions', Shield, 'Transactions'],
  ['evidence', Database, 'Evidence'],
  ['quality', Activity, 'Detection quality'],
  ['integrations', ServerCog, 'Integrations'],
  ['opa', Shield, 'OPA policies'],

]
const VIEW_LABELS = Object.fromEntries([...NAV, ['settings', null, 'Settings'], ['developer', null, 'Developer']].map(([id, , label]) => [id, label]))

export function Dashboard({ connection, logout }) {
  const [realOnly, setRealOnly] = useState(() => sessionStorage.getItem('shield-real-only') !== 'false')
  const [menu, setMenu] = useState(false)
  const [view, setView] = useState('overview')
  const [data, setData] = useState({
    summary: null,
    agents: [],
    devices: [],
    outcomes: [],
    exporter: [],
    integrations: [],
    quality: [],
    events: [],
  })
  const [status, setStatus] = useState({
    state: 'connecting',
    message: 'Connecting to control plane',
  })
  const [refreshing, setRefreshing] = useState(false);



  const api = useMemo(
    () => new ShieldApi(connection.baseUrl, connection.tenant, connection.token),
    [connection]
  )

  const refresh = useCallback(async () => {
    setRefreshing(true)
    const results = await Promise.allSettled([
      api.dashboard(),
      api.devices(),
      api.agents(),
      api.enforcementOutcomes(),
      api.exporterStatus(),
      api.integrations(),
      api.detectionQuality(),
      api.testEvents(),
    ])
    const [summary, devices, agents, outcomes, exporter, integrations, quality, events] = results
    const live = summary.status === 'fulfilled'
    const visibleDevices = devices.status === 'fulfilled'
      ? devices.value.devices.filter((device) => !device.synthetic)
      : []
    const visibleDeviceIds = new Set(visibleDevices.map((device) => device.device_id || device.id))
    const visibleExporter = exporter.status === 'fulfilled'
      ? exporter.value.exporter_status.filter((row) => !realOnly || visibleDeviceIds.has(row.device_id))
      : []
    const visibleSummary = summary.status === 'fulfilled'
      ? {
          ...summary.value,
          devices: visibleDevices,
          device_count: visibleDevices.length,
          latest_decisions: (summary.value.latest_decisions || []).filter((row) => {
            const decision = row.decision || {}
            return visibleDeviceIds.has(decision.device_id || decision.event_ref?.device_id)
          }),
          exporter_status: visibleExporter,
        }
      : null

    setData((current) => ({
      summary: live ? visibleSummary : (realOnly ? null : current.summary),
      agents: agents.status === 'fulfilled' ? agents.value.agents : current.agents,
      devices: devices.status === 'fulfilled' ? visibleDevices : [],
      outcomes: outcomes.status === 'fulfilled' ? outcomes.value.enforcement_outcomes.filter((row) => !row.outcome?.synthetic) : [],
      exporter: exporter.status === 'fulfilled' ? visibleExporter : current.exporter,
      integrations: integrations.status === 'fulfilled' ? integrations.value.integrations : current.integrations,
      quality: quality.status === 'fulfilled' ? quality.value.detection_quality : current.quality,
      events: events.status === 'fulfilled' ? events.value.test_events : current.events,
    }))

    const failure = summary.reason?.message || 'Authentication failed'
    if (!live && /401|unauthorized|invalid admin token|admin token required/i.test(failure)) {
      logout('Session expired. Sign in again to reconnect to this tenant.')
      return
    }

    setStatus(
      live
        ? { state: 'live', message: 'Control plane live' }
        : { state: 'error', message: failure }
    )
    setRefreshing(false)
  }, [api, logout, realOnly])

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect
    refresh()
  }, [refresh])

  useEffect(() => {
    const interval = window.setInterval(() => refresh(), 15000)
    return () => window.clearInterval(interval)
  }, [refresh])

  useEffect(() => {
    const handleMode = (event) => {
      const enabled = Boolean(event.detail)
      setRealOnly(Boolean(enabled))
      if (enabled) setData((current) => ({ ...current, devices: [], outcomes: [], events: [], exporter: [], integrations: [], quality: [] }))
    }
    window.addEventListener('shield-telemetry-mode', handleMode)
    return () => window.removeEventListener('shield-telemetry-mode', handleMode)
  }, [])

  const protectedCount =
    data.summary?.device_count ?? data.devices.filter((d) => d.status !== 'attention').length

  const openView = (id) => {
    setView(id)
    setMenu(false)
  }

  return (
    <main className="console">
      <aside className={menu ? 'side open' : 'side'} aria-label="Console navigation">
        <header>
          <Brand />
          <button
            type="button"
            className="menu-close-btn"
            aria-label="Close navigation"
            onClick={() => setMenu(false)}
          >
            <X aria-hidden="true" />
          </button>
        </header>

        <nav>
          <small>OPERATIONS</small>
          {NAV.slice(0, 5).map(([id, Icon, label]) => (
            <button
              key={id}
              type="button"
              className={view === id ? 'active' : ''}
              onClick={() => openView(id)}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
              {id === 'devices' && <i>{data.devices.length}</i>}
            </button>
          ))}

          <small>CONTROL</small>
          {NAV.slice(5, 9).map(([id, Icon, label]) => (
            <button
              key={id}
              type="button"
              className={view === id ? 'active' : ''}
              onClick={() => openView(id)}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
            </button>
          ))}

          <small>SYSTEM</small>
          {NAV.slice(9).map(([id, Icon, label]) => (
            <button
              key={id}
              type="button"
              className={view === id ? 'active' : ''}
              onClick={() => openView(id)}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="bottom-profile" style={{ marginTop: 'auto', padding: '1rem 0.75rem 0' }}>
          <nav aria-label="Account navigation" className="account-nav">
            <button
              type="button"
              className={view === 'settings' ? 'active' : ''}
              onClick={() => openView('settings')}
            >
              <Sliders aria-hidden="true" />
              <span>Settings</span>
            </button>
            <button
              type="button"
              className="logout-nav-item"
              onClick={() => logout()}
            >
              <LogOut aria-hidden="true" />
              <span>Log out</span>
            </button>
          </nav>
          <button
            type="button"
            className="profile-btn"
            aria-label="Open operator profile settings"
            onClick={() => openView('settings')}
          >
            <CircleUserRound aria-hidden="true" />
            <span className="profile-name">{connection.account?.display_name || 'Operator profile'}</span>
          </button>
        </div>
      </aside>

      <section className="main">
        <header className="top">
          <button
            aria-label="Toggle navigation menu"
            className="hamb"
            type="button"
            onClick={() => setMenu(true)}
          >
            <Menu aria-hidden="true" />
          </button>
          <div className="top-title">
            <h1>{VIEW_LABELS[view] || 'Shield console'}</h1>
            <p>{connection.tenant} · {connection.baseUrl}</p>
          </div>
          <div className="tools">
            <button
              aria-label="Refresh data"
              title="Refresh"
              type="button"
              onClick={refresh}
              disabled={refreshing}
            >
              <Activity className={refreshing ? 'spinning' : ''} aria-hidden="true" />
            </button>
            <button aria-label="View notifications" title="Notifications" type="button">
              <Bell aria-hidden="true" />
            </button>
            <span
              className={`connection ${status.state}`}
              title={status.message}
              role="status"
              aria-live="polite"
            >
              <i aria-hidden="true" />
              {status.state === 'live'
                ? 'Control plane live'
                : status.state === 'connecting'
                ? 'Connecting'
                : 'Disconnected'}
            </span>
            {realOnly && <span className="telemetry-mode-badge" role="status">REAL TELEMETRY ONLY</span>}
          </div>
        </header>

        {status.state === 'error' && (
          <div className="api-alert" role="alert">
            <TriangleAlert aria-hidden="true" />
            <span>
              <b>Control plane unavailable</b>: {status.message}. {realOnly ? 'Real telemetry only is enabled; synthetic fallback data is hidden.' : 'Showing clearly labeled preview data where available.'}
            </span>
            <button type="button" onClick={refresh}>Retry</button>
          </div>
        )}

        <div className="content">
          {view === 'overview' ? (
            <Overview
              data={data}
              protectedCount={protectedCount}
              openView={openView}
              preview={status.state !== 'live'}
            />
          ) : (
            <ResourceView
              view={view}
              data={data}
              api={api}
              refresh={refresh}
              connection={connection}
              logout={logout}
            />
          )}
        </div>
      </section>
    </main>
  )
}
