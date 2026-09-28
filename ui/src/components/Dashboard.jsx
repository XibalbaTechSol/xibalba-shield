import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  Bell,
  Gauge,
  HardDrive,
  LogOut,
  Moon,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Sliders,
  Sun,
  TriangleAlert,
  X,
  Workflow,
  FileSearch,
} from 'lucide-react'
import { ShieldApi } from '../api'
import { Brand } from './Brand'
import { Overview } from './Overview'
import { ResourceView } from './ResourceView'
import { readSession, writeSession } from '../storage'

function sharedScopeFromUrl() {
  try {
    const params = new URLSearchParams(window.location.search)
    return { agentId: params.get('agent_id') || '', storeId: params.get('store_id') || '' }
  } catch {
    return { agentId: '', storeId: '' }
  }
}

function writeSharedScope(agentId, storeId = '') {
  try {
    const url = new URL(window.location.href)
    if (agentId) url.searchParams.set('agent_id', agentId); else url.searchParams.delete('agent_id')
    if (storeId) url.searchParams.set('store_id', storeId); else url.searchParams.delete('store_id')
    window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`)
  } catch {}
}

async function fetchCortexNamespaces() {
  const response = await fetch('/cortex-api/api/agents', { credentials: 'include', headers: { Accept: 'application/json' } })
  if (!response.ok) throw new Error(`Cortex namespace roster unavailable (${response.status})`)
  const payload = await response.json()
  return (payload.agents || []).filter((agent) => agent.agent_id && agent.store_id)
}

const NAV = [
  ['overview', Gauge, 'Posture', 'COMMAND CENTER'],
  ['agent', HardDrive, 'Agent', 'OPERATIONS'],
  ['network', Activity, 'Network', 'OPERATIONS'],
  ['decisions', Workflow, 'Decisions', 'GOVERNANCE'],
  ['evidence', FileSearch, 'Evidence', 'ASSURANCE'],
  ['configuration', Sliders, 'Configuration', 'SYSTEM'],
]
const VIEW_LABELS = Object.fromEntries(NAV.map(([id, , label]) => [id, label]))

export function Dashboard({ connection, logout, theme = 'command-center', onThemeChange }) {
  const [realOnly, setRealOnly] = useState(() => readSession('shield-real-only') !== 'false')
  const [menu, setMenu] = useState(false)
  const [navCollapsed, setNavCollapsed] = useState(false)
  const [profileMenu, setProfileMenu] = useState(false)
  const [view, setView] = useState('overview')
  const [timeRange, setTimeRange] = useState('24h')
  const [selectedAgentId, setSelectedAgentId] = useState(() => {
    const shared = sharedScopeFromUrl()
    return shared.agentId || readSession('shield-selected-agent')
  })
  const [selectedStoreId, setSelectedStoreId] = useState(() => sharedScopeFromUrl().storeId)
  const [sharedNamespaces, setSharedNamespaces] = useState([])
  const [data, setData] = useState({
    summary: null,
    agents: [],
    devices: [],
    outcomes: [],
    exporter: [],
    integrations: [],
    quality: [],
    events: [],
    cortexOutbox: null,
    hermes: null,
    hermesDeliveries: [],
    resources: null,
  })
  const [status, setStatus] = useState({
    state: 'connecting',
    message: 'Connecting to control plane',
  })
  const [refreshing, setRefreshing] = useState(false);
  const lightMode = theme === 'light'
  const toggleTheme = () => {
    const nextTheme = lightMode ? 'command-center' : 'light'
    writeSession('shield-console-theme', nextTheme)
    onThemeChange?.(nextTheme)
  }



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
      api.cortexOutbox(),
      api.hermesStatus(),
      api.hermesDeliveries(),
      api.runtimeResources(),
      fetchCortexNamespaces().catch(() => []),
    ])
    const [summary, devices, agents, outcomes, exporter, integrations, quality, events, cortexOutbox, hermes, hermesDeliveries, resources, cortexNamespaces] = results
    const live = summary.status === 'fulfilled'
    const summaryDevices = summary.status === 'fulfilled' ? (summary.value.devices || []) : []
    const visibleDevices = (devices.status === 'fulfilled' ? devices.value.devices : summaryDevices)
      .filter((device) => !device.synthetic)
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
      devices: visibleDevices,
      outcomes: outcomes.status === 'fulfilled' ? outcomes.value.enforcement_outcomes.filter((row) => !row.outcome?.synthetic) : [],
      exporter: exporter.status === 'fulfilled' ? visibleExporter : current.exporter,
      integrations: integrations.status === 'fulfilled' ? integrations.value.integrations : current.integrations,
      quality: quality.status === 'fulfilled' ? quality.value.detection_quality : current.quality,
      events: events.status === 'fulfilled' ? events.value.test_events : current.events,
      cortexOutbox: cortexOutbox.status === 'fulfilled' ? cortexOutbox.value.outbox : current.cortexOutbox,
      hermes: hermes.status === 'fulfilled' ? hermes.value.hermes : current.hermes,
      hermesDeliveries: hermesDeliveries.status === 'fulfilled' ? hermesDeliveries.value.deliveries : current.hermesDeliveries,
      resources: resources.status === 'fulfilled' ? resources.value.resources : current.resources,
    }))

    if (cortexNamespaces.status === 'fulfilled') setSharedNamespaces(cortexNamespaces.value)

    if (agents.status === 'fulfilled') {
      const available = agents.value.agents || []
      const shared = sharedScopeFromUrl()
      const current = available.some((agent) => agent.agent_id === selectedAgentId)
        ? selectedAgentId
        : (shared.agentId && available.some((agent) => agent.agent_id === shared.agentId) ? shared.agentId : available[0]?.agent_id || '')
      if (current) {
        setSelectedAgentId(current)
        writeSession('shield-selected-agent', current)
      }
    }

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
  }, [api, logout, realOnly, selectedAgentId])

  const namespaceOptions = sharedNamespaces.length
    ? sharedNamespaces.map((agent) => ({ ...agent, namespaceKey: `${agent.store_id}\0${agent.agent_id}` }))
    : data.agents.flatMap((group) => (group.available_agents || []).map((agent) => ({ ...agent, store_id: '', namespaceKey: agent.agent_id })))
  const selectedNamespace = namespaceOptions.find((agent) => agent.agent_id === selectedAgentId && agent.store_id === selectedStoreId)
    || namespaceOptions.find((agent) => agent.agent_id === selectedAgentId)

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect
    refresh()
  }, [refresh])

  useEffect(() => {
    const interval = window.setInterval(() => refresh(), 5000)
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
    <main className={`console ${theme === 'command-center' ? 'theme-command-center' : 'theme-light'}`}>
      <aside className={`side${menu ? ' open' : ''}${navCollapsed ? ' collapsed' : ''}`} aria-label="Console navigation">
        <header>
          <Brand />
          <button
            type="button"
            className="nav-collapse-btn"
            aria-label={navCollapsed ? 'Expand navigation' : 'Collapse navigation'}
            title={navCollapsed ? 'Expand navigation' : 'Collapse navigation'}
            onClick={() => setNavCollapsed((collapsed) => !collapsed)}
          >
            {navCollapsed ? <PanelLeftOpen aria-hidden="true" /> : <PanelLeftClose aria-hidden="true" />}
          </button>
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
          {['COMMAND CENTER', 'OPERATIONS', 'GOVERNANCE', 'ASSURANCE', 'SYSTEM'].map((section) => <div key={section} className="nav-group">
            <small>{section}</small>
            {NAV.filter(([, , , group]) => group === section).map(([id, Icon, label]) => (
            <button
              key={id}
              type="button"
              className={view === id ? 'active' : ''}
              onClick={() => openView(id)}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
              {id === 'fleet' && <i>{data.devices.length}</i>}
            </button>
            ))}
          </div>)}
        </nav>
        <div className="bottom-profile" style={{ marginTop: 'auto', padding: '1rem 0.75rem 0' }}>
          {profileMenu && <div className="profile-menu" role="menu">
            <button type="button" role="menuitem" onClick={() => { setProfileMenu(false); openView('settings') }}>Settings</button>
            <button type="button" role="menuitem" onClick={() => logout()}>Log out</button>
          </div>}
          <nav aria-label="Account navigation" className="account-nav">
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
            aria-expanded={profileMenu}
            onClick={() => setProfileMenu((open) => !open)}
          >
            <span className="profile-avatar" aria-hidden="true">{(connection.account?.display_name || 'Operator profile').trim().slice(0, 1).toUpperCase()}</span>
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
          <div className="command-brand">
            <Brand />
          </div>
          <div className="top-title">
            <h1>{VIEW_LABELS[view] || 'Shield console'}</h1>
            <p>{connection.tenant} · {connection.baseUrl}</p>
          </div>
          <div className="header-identity" aria-label="Current Shield workspace">
            <span className="header-identity-kicker">SHIELD CONTROL PLANE</span>
            <strong>Operator console</strong>
            <small>{connection.tenant || 'Authenticated tenant'}</small>
          </div>
          <div className="tools">
            <label className="shared-agent-picker">
              <span>Namespace</span>
              <select
                aria-label="Shared agent namespace"
                value={selectedNamespace?.namespaceKey || ''}
                onChange={(event) => {
                  const next = event.target.value
                  const selected = namespaceOptions.find((agent) => agent.namespaceKey === next)
                  if (!selected) return
                  setSelectedAgentId(selected.agent_id)
                  setSelectedStoreId(selected.store_id || '')
                  writeSession('shield-selected-agent', selected.agent_id)
                  writeSharedScope(selected.agent_id, selected.store_id || '')
                }}
              >
                <option value="">Select agent</option>
                {namespaceOptions.map((agent) => (
                  <option key={agent.namespaceKey} value={agent.namespaceKey}>{agent.name || agent.agent_name || agent.agent_id} · {agent.store_id ? (agent.writable === false || agent.store_access === 'read_only' ? 'read only' : 'writable') : 'Shield local'}</option>
                ))}
              </select>
            </label>
            <button
              aria-label={lightMode ? 'Switch to dark mode' : 'Switch to light mode'}
              title={lightMode ? 'Switch to dark mode' : 'Switch to light mode'}
              type="button"
              className="theme-toggle"
              onClick={toggleTheme}
            >
              {lightMode ? <Moon aria-hidden="true" /> : <Sun aria-hidden="true" />}
            </button>
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
            <button
              type="button"
              className="audit-packet-button"
              onClick={() => openView('evidence')}
            >
              Export audit packet
            </button>
          </div>
          <nav className="command-nav" aria-label="Control plane navigation">
            {[
              ['overview', 'Posture'],
              ['agent', 'Agent'],
              ['network', 'Network'],
              ['decisions', 'Decisions'],
              ['evidence', 'Evidence'],
              ['configuration', 'Configuration'],
            ].map(([id, label]) => (
              <button key={id} type="button" className={view === id ? 'active' : ''} onClick={() => openView(id)}>
                {label}
              </button>
            ))}
          </nav>
        </header>

        {status.state === 'error' && (
          <div className="api-alert" role="alert">
            <TriangleAlert aria-hidden="true" />
            <span>
              <b>Control plane unavailable</b>: {status.message}. {realOnly ? 'Authenticated telemetry mode is enabled; synthetic fallback data is hidden.' : 'Showing clearly labeled preview data where available.'}
            </span>
            <button type="button" onClick={refresh}>Retry</button>
          </div>
        )}

        <div className={`content ${view}-page`}>
          {view === 'overview' ? (
            <Overview
              data={data}
              protectedCount={protectedCount}
              openView={openView}
              timeRange={timeRange}
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
                theme={theme}
                onThemeChange={onThemeChange}
                timeRange={timeRange}
              />
          )}
        </div>
      </section>
    </main>
  )
}
