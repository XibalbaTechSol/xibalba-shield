import { useEffect, useState } from 'react'
import { Activity, LockKeyhole, ShieldCheck, TriangleAlert, Unplug, Cpu, Database, MemoryStick, X } from 'lucide-react'
import { Metric, PanelTitle } from './Common'
import { OutcomeTable } from './OutcomeTable'

// Same keys and order as AgentView's own responder grid, so the two surfaces cannot drift apart.
// The descriptions are static because they describe what a responder does; every piece of *state*
// comes from `exporter-status`.
const RESPONDER_DEFINITIONS = [
  { key: 'freeze_process', label: 'Freeze process', description: 'Pause a policy-matched process with SIGSTOP.' },
  { key: 'freeze_cgroup', label: 'Freeze cgroup', description: 'Pause a workload boundary after cgroup runtime proof.' },
  { key: 'kill_process', label: 'Kill process', description: 'Terminate only after an explicit destructive-action gate.' },
  { key: 'block_flow', label: 'Block network flow', description: 'Install a scoped network block after kernel runtime proof.' },
]

function Sparkline({ values, label, unit = '' }) {
  const points = values.filter((value) => Number.isFinite(value))
  if (points.length === 0) return <div className="sparkline-empty">Collecting live samples…</div>
  const min = Math.min(...points)
  const max = Math.max(...points)
  const range = max - min || 1
  const coordinates = points.map((value, index) => {
    const x = points.length === 1 ? 50 : (index / (points.length - 1)) * 100
    const y = max === min ? 50 : 91 - ((value - min) / range) * 82
    return { x, y }
  })
  const path = coordinates.map(({ x, y }) => `${x},${y}`).join(' ')
  return <div className="sparkline-wrap"><svg className="sparkline" viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label={`${label} live graph`}><line x1="0" y1="25" x2="100" y2="25" className="sparkline-grid" /><line x1="0" y1="50" x2="100" y2="50" className="sparkline-grid" /><line x1="0" y1="75" x2="100" y2="75" className="sparkline-grid" /><polyline points={path} fill="none" stroke="currentColor" strokeWidth="1.5" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" />{coordinates.map(({ x, y }, index) => <circle key={`${x}-${index}`} cx={x} cy={y} r="2" fill="currentColor" vectorEffect="non-scaling-stroke" />)}</svg><small>{points.at(-1).toFixed(1)}{unit} now · range {min.toFixed(1)}–{max.toFixed(1)}{unit}</small></div>
}

export function Overview({ data, protectedCount, openView, preview: _preview = false }) {
  const preview = _preview
  const [history, setHistory] = useState([])
  const actionCounts = data.summary?.decisions_by_action || {}
  const contained = data.summary
    ? (actionCounts.deny || 0) + (actionCounts.contain || 0)
    : (data.outcomes || []).filter((outcome) => ['deny', 'blocked', 'contain', 'contained'].includes(String(outcome.action || outcome.decision).toLowerCase())).length
  const latestStatus = data.exporter?.[0]?.status || data.summary?.exporter_status?.[0]?.status || {}
  const sensors = latestStatus.sensors || {}
  const exporter = latestStatus.exporter || {}
  const probeMode = sensors.attach_mode || (sensors.attached === true ? 'direct probe' : 'not attached')
  // `exporter-status` already reports the DID preflight and the responder gates per device. This
  // panel used to state both as literal strings -- "DID readback pending", and a four-row table
  // whose proof counts disagreed with what the device actually reported -- so a reader could not
  // tell a gated responder from a ready one. Everything below is read from the payload.
  const didPreflight = latestStatus.did_preflight || {}
  const didDetail = didPreflight.did_loaded === undefined
    ? 'no DID preflight reported'
    : [
      didPreflight.did_loaded ? 'DID loaded' : 'no DID loaded',
      didPreflight.oracle_configured === false
        ? 'oracle not configured'
        : didPreflight.oracle_reachable
          ? (didPreflight.oracle_registered === true ? 'registered' : didPreflight.oracle_registered === false ? 'not registered' : 'registration unread')
          : 'oracle unreachable',
      didPreflight.bcc_middleware_reachable ? 'middleware reachable' : 'middleware unreachable',
    ].join(' · ')
  // Prefer the backend publication counter and say so; fall back to the device-side exporter's own
  // failures only when the backend has not reported, and label that differently.
  const evidenceFailures = exporter.backend_evidence?.publish_failures != null
    ? { value: exporter.backend_evidence.publish_failures, label: 'backend publications' }
    : exporter.export_failures != null
      ? { value: exporter.export_failures, label: 'device exports' }
      : { value: null, label: 'not reported' }
  const responderStatus = latestStatus.responders || {}
  const responderReady = responderStatus.readiness?.ready || {}
  const responderMissing = responderStatus.readiness?.missing || {}
  const responderCapabilities = responderStatus.capabilities || {}
  // `ready` covers only the gated responders; freeze_process is policy-capable without a gate, so
  // its own capability flag is what says whether it can act.
  const responderRows = RESPONDER_DEFINITIONS.map(({ key, label, description }) => {
    const missing = Array.isArray(responderMissing[key]) ? responderMissing[key] : []
    const ready = key in responderReady ? responderReady[key] === true : responderCapabilities[key] === true
    const reported = key in responderReady || key in responderCapabilities
    return {
      key,
      label,
      description,
      detail: !reported
        ? 'not reported'
        : missing.length
          ? `${missing.length} missing ${missing.length === 1 ? 'proof' : 'proofs'} · ${missing.join(' · ')}`
          : ready ? 'policy-driven · no outstanding proofs' : 'gated · no proofs reported',
      state: !reported ? 'Unverified' : ready ? 'Ready' : 'Proof required',
    }
  })
  const respondersReported = responderRows.some((row) => row.state !== 'Unverified')
  const respondersReadyCount = responderRows.filter((row) => row.state === 'Ready').length
  const bridgeDetail = sensors.last_heartbeat_at
    ? `heartbeat ${sensors.last_heartbeat_at}`
    : sensors.last_event_at
      ? `events ${sensors.last_event_at}`
      : 'no heartbeat reported'

  const enrolledCount = data.devices?.length || 0
  const hermes = data.hermes || {}
  const resource = data.resources || {}
  const cpuCores = Array.isArray(resource.cpu_cores) ? resource.cpu_cores.slice(0, 4) : []
  const memory = resource.memory || {}
  const rollups = data.summary?.decision_observation_rollups || []
  const latestBucket = rollups.reduce((latest, row) => row.bucket_start > latest ? row.bucket_start : latest, '')
  const latestBucketCount = rollups
    .filter((row) => row.bucket_start === latestBucket)
    .reduce((total, row) => total + Number(row.count || 0), 0)
  const reportedEventRate = Number(data.summary?.latest_metrics?.events_per_sec)
  const eventRate = Number.isFinite(reportedEventRate)
    ? reportedEventRate
    : latestBucketCount > 0
      ? latestBucketCount / 60
      : null
  const policyVersions = [...new Set((data.devices || []).map((device) => device.policy_version).filter(Boolean))]
  const runtimePolicyVersions = [...new Set((data.exporter || []).map((row) => row.status?.policy?.active_policy_version).filter(Boolean))]
  const policyConflict = runtimePolicyVersions.length > 0 && policyVersions.length > 0 && runtimePolicyVersions.some((version) => !policyVersions.includes(version))
  useEffect(() => {
    if (!data.resources && !data.summary) return
    // oxlint-disable-next-line react/set-state-in-effect -- append each authenticated polling sample to the chart window
    setHistory((current) => [...current, {
      cpu: Number.isFinite(resource.cpu_percent) ? resource.cpu_percent : null,
      memory: Number.isFinite(resource.rss_bytes) ? resource.rss_bytes / 1024 / 1024 : null,
      events: Number.isFinite(eventRate) ? eventRate : null,
      at: resource.sampled_at || new Date().toISOString(),
    }].slice(-30))
  }, [data.resources, data.summary, eventRate, resource.cpu_percent, resource.rss_bytes, resource.sampled_at])
  const readiness = [
    ['Endpoint observation', sensors.attached === true, sensors.attached === true ? 'live sensor evidence' : 'no live sensor proof'],
    ['Local policy authority', latestStatus.policy?.healthy === true, latestStatus.policy?.active_policy_hash || 'policy hash not reported'],
    ['Evidence export', exporter.backend_evidence?.verified === true, exporter.backend_evidence?.receipt_id || 'receipt not verified'],
    ['Hermes analysis transport', hermes.healthy === true, hermes.health || 'not configured'],
    ['Gateway / NAC authority', null, 'external API not identified'],
  ]

  return (
    <>
      <section className="welcome">
        <div>
          <p className="eyebrow">OPERATIONAL POSTURE</p>
          <h2>Is the fleet protected right now?</h2>
          <span>{preview ? 'Control plane unavailable: synthetic and preview records are not shown.' : 'Authenticated telemetry, policy decisions, and containment outcomes across the enrolled fleet.'}</span>
        </div>
        <button className="primary" type="button" onClick={() => openView('decisions')} disabled={preview} title={preview ? 'Reconnect to the control plane before deploying policy' : undefined}>
          <ShieldCheck aria-hidden="true" /> Deploy policy
        </button>
      </section>

      <section className="metrics" aria-label="Key operational metrics">
        <Metric
          Icon={ShieldCheck}
          label="Enrolled devices"
          value={data.summary?.device_count ?? enrolledCount}
          detail={`${protectedCount} protected · ${Math.max(0, enrolledCount - protectedCount)} attention`}
          tone="green"
        />
        <Metric
          Icon={LockKeyhole}
          label="Contained / denied"
          value={contained}
          detail="recorded decisions"
          tone="green"
        />
        {/* This tile used to read `spool_pending == null ? '—' : '—'`, so it rendered an em-dash
            whatever the device reported. `exporter-status` carries no positive "exported" total to
            put there -- only failure and queue counters -- so the tile now reports the failures,
            which were otherwise invisible in the console while the spool sat at zero.
            `backend_evidence.publish_failures` and `export_failures` are *different* counters
            (213 and 45 on this host), so the detail line names which one is on screen rather than
            letting the number change meaning per device without saying so. */}
        <Metric
          Icon={X}
          label="Evidence failures"
          value={evidenceFailures.value ?? '—'}
          detail={evidenceFailures.label}
          tone={(evidenceFailures.value ?? 0) > 0 ? 'amber' : 'green'}
        />
        <Metric
          Icon={TriangleAlert}
          label="Exporter queue"
          value={exporter.spool_pending ?? exporter.queue_depth ?? '—'}
          detail="pending evidence"
          tone="amber"
        />
      </section>

      <section className="mock-posture-grid" aria-label="Posture readiness">
        <article className="panel posture-runtime-panel">
          <PanelTitle title="Runtime health" copy="Latest watchdog publication" status={sensors.attached === true ? 'Healthy' : 'Unverified'} />
          <div className="sensor-list">
            {[
              ['Policy', latestStatus.policy?.healthy, latestStatus.policy?.active_policy_hash],
              ['OPA', latestStatus.opa?.healthy, 'policy evaluator · shield/policy'],
              ['Probe', sensors.attached, probeMode],
              ['Bridge', sensors.attached, bridgeDetail],
              ['Lost events', sensors.lost_events === 0, `${sensors.lost_events ?? 0} lost events`],
              ['Evidence exporter', exporter.export_failures === 0, `${exporter.spool_pending ?? 0} spooled · ${didDetail}`]
            ].map(([name, healthy, detail]) => (
              <div className="sensor" key={`posture-${name}`}>
                <span><Activity aria-hidden="true" /></span>
                <p><b>{name}</b><small>{detail || 'not reported'}</small></p>
                <strong className={`status-badge ${healthy === true ? 'healthy' : healthy === false ? 'attention' : 'unknown'}`}>{healthy === true ? 'Healthy' : healthy === false ? 'Attention' : 'Unverified'}</strong>
              </div>
            ))}
          </div>
        </article>
        <article className="panel responder-panel">
          <PanelTitle
            title="Responder readiness"
            copy="Live agent report"
            status={respondersReported ? `${respondersReadyCount} of ${responderRows.length} ready` : 'Unverified'}
          />
          <p className="responder-copy">Destructive responders cannot be enabled from the UI without runtime proof.</p>
          <div className="responder-grid">
            {responderRows.map(({ key, label, description, detail, state }) => (
              <div className="responder-item" key={key}>
                <b>{label}</b><span>{description}</span><small>{detail}</small><strong className={state === 'Ready' ? 'ready' : ''}>{state}</strong>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="panel live-telemetry-panel" aria-label="Live runtime telemetry">
        <PanelTitle title="Live runtime telemetry" copy={`${history.length} samples · refreshes every 5 seconds`} status={resource.sampled_at ? 'Streaming' : 'Waiting'} />
        <div className="live-telemetry-grid">
          <article className="telemetry-chart"><div className="telemetry-chart-heading"><span><Cpu size={15} /> CPU</span><b>{resource.cpu_percent == null ? '—' : `${resource.cpu_percent.toFixed(1)}%`}</b></div><Sparkline values={history.map((sample) => sample.cpu)} label="CPU utilization" unit="%" /></article>
          <article className="telemetry-chart"><div className="telemetry-chart-heading"><span><Database size={15} /> Runtime RSS</span><b>{resource.rss_bytes == null ? '—' : `${(resource.rss_bytes / 1024 / 1024).toFixed(1)} MB`}</b></div><Sparkline values={history.map((sample) => sample.memory)} label="Runtime resident set" unit=" MB" /><small className="telemetry-scope-note">Local process sample aggregate; not Shield service RSS.</small></article>
          <article className="telemetry-chart"><div className="telemetry-chart-heading"><span><Activity size={15} /> Observations</span><b>{Number.isFinite(eventRate) ? eventRate.toFixed(1) : '—'}</b></div><Sparkline values={history.map((sample) => sample.events)} label="Observation rate" unit="/s" /></article>
          <article className="resource-widget" aria-label="CPU cores and memory usage">
            <div className="telemetry-chart-heading"><span><Cpu size={15} /> CPU / memory</span><b>{cpuCores.length === 4 ? '4 cores' : 'Waiting'}</b></div>
            <div className="resource-widget-section">
              <div className="resource-widget-label"><span>CPU cores</span><small>{cpuCores.length === 4 ? 'live host sample' : 'collecting samples'}</small></div>
              <div className="core-bars">
                {[0, 1, 2, 3].map((index) => {
                  const core = cpuCores[index]
                  const percent = Number.isFinite(core?.percent) ? core.percent : null
                  return <div className="core-bar" key={core?.id || `core-${index}`}><div className="core-bar-heading"><span>{core?.label || `Core ${index + 1}`}</span><b>{percent == null ? '—' : `${percent.toFixed(1)}%`}</b></div><div className="core-bar-track"><i style={{ width: `${percent == null ? 0 : Math.min(100, Math.max(0, percent))}%` }} /></div></div>
                })}
              </div>
            </div>
            <div className="resource-widget-section memory-usage">
              <div className="resource-widget-label"><span><MemoryStick size={13} /> Memory usage</span><b>{Number.isFinite(memory.percent) ? `${memory.percent.toFixed(1)}%` : '—'}</b></div>
              <div className="memory-bar-track"><i style={{ width: `${Number.isFinite(memory.percent) ? Math.min(100, Math.max(0, memory.percent)) : 0}%` }} /></div>
              <small>{Number.isFinite(memory.used_bytes) && Number.isFinite(memory.total_bytes) ? `${(memory.used_bytes / 1024 / 1024 / 1024).toFixed(1)} GB used of ${(memory.total_bytes / 1024 / 1024 / 1024).toFixed(1)} GB` : 'Memory sample unavailable'}</small>
            </div>
          </article>
        </div>
        <p className="telemetry-footnote">Source: authenticated local runtime process sampling and Shield decision telemetry. CPU cores and memory are host-level runtime samples; missing samples remain unverified.</p>
      </section>

      {policyConflict && <section className="api-alert" role="alert"><TriangleAlert aria-hidden="true" /><span><b>Policy state differs across authorities.</b> The control plane reports {policyVersions.join(', ')}, while runtime status reports {runtimePolicyVersions.join(', ')}. Reconcile before deploying or evaluating enforcement.</span><button type="button" onClick={() => openView('decisions')}>Review policy</button></section>}

      <section className="command-grid" aria-label="Control plane readiness">
        <article className="panel readiness-panel">
          <PanelTitle title="Control plane readiness" copy="Evidence-backed capability map" />
          <div className="readiness-list">
            {readiness.map(([name, healthy, detail]) => (
              <div className="readiness-row" key={name}>
                <span className={`readiness-icon ${healthy === true ? 'good' : healthy === false ? 'warn' : 'unknown'}`}>
                  {healthy === true ? <X size={15} /> : healthy === false ? <TriangleAlert size={15} /> : <Unplug size={15} />}
                </span>
                <div><b>{name}</b><small>{detail}</small></div>
                <strong>{healthy === true ? 'verified' : healthy === false ? 'attention' : 'external'}</strong>
              </div>
            ))}
          </div>
        </article>
        <article className="panel operator-panel">
          <PanelTitle title="Next operator actions" copy="Keep the enforcement boundary explicit" />
          <ol>
            <li><b>Review Hermes queue</b><span>{hermes.pending ?? 0} pending · {hermes.dead_letters ?? 0} dead-letter</span></li>
            <li><b>Confirm host service ownership</b><span>systemd unit remains separate from unmanaged backend processes</span></li>
            <li><b>Authorize gateway integration</b><span>requires model/API, disposable scope, and rollback owner</span></li>
          </ol>
        </article>
      </section>

      <OutcomeTable outcomes={data.outcomes} />
    </>
  )
}
