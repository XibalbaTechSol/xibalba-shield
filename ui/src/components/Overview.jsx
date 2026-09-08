import { Activity, LockKeyhole, ShieldCheck, TriangleAlert } from 'lucide-react'
import { Metric, PanelTitle } from './Common'
import { OutcomeTable } from './OutcomeTable'

export function Overview({ data, protectedCount, openView, preview: _preview = false }) {
  const preview = _preview
  const actionCounts = data.summary?.decisions_by_action || {}
  const contained = data.summary
    ? (actionCounts.deny || 0) + (actionCounts.contain || 0)
    : (data.outcomes || []).filter((outcome) => ['deny', 'blocked', 'contain', 'contained'].includes(String(outcome.action || outcome.decision).toLowerCase())).length
  const latestStatus = data.exporter?.[0]?.status || data.summary?.exporter_status?.[0]?.status || {}
  const sensors = latestStatus.sensors || {}
  const exporter = latestStatus.exporter || {}
  const probeMode = sensors.attach_mode || (sensors.attached === true ? 'direct probe' : 'not attached')
  const bridgeDetail = sensors.last_heartbeat_at
    ? `heartbeat ${sensors.last_heartbeat_at}`
    : sensors.last_event_at
      ? `events ${sensors.last_event_at}`
      : 'no heartbeat reported'

  const enrolledCount = data.devices?.length || 0
  const visiblePercent = enrolledCount ? Math.round((protectedCount / enrolledCount) * 100) : 0

  return (
    <>
      <section className="welcome">
        <div>
          <p className="eyebrow">OPERATIONAL POSTURE</p>
          <h2>Fleet command center.</h2>
          <span>{preview ? 'Preview mode: synthetic fallback data is shown until the control plane reconnects.' : 'Authenticated telemetry, policy decisions, and containment outcomes.'}</span>
        </div>
        <button className="primary" type="button" onClick={() => openView('policies')} disabled={preview} title={preview ? 'Reconnect to the control plane before deploying policy' : undefined}>
          <ShieldCheck aria-hidden="true" /> Deploy policy
        </button>
      </section>

      <section className="metrics" aria-label="Key operational metrics">
        <Metric
          Icon={ShieldCheck}
          label="Enrolled devices"
          value={data.summary?.device_count ?? enrolledCount}
          detail="tenant-scoped"
          tone="green"
        />
        <Metric
          Icon={Activity}
          label="Latest event rate"
          value={data.summary?.latest_metrics?.events_per_sec ?? '—'}
          detail="events per second"
        />
        <Metric
          Icon={LockKeyhole}
          label="Contained / denied"
          value={contained}
          detail="recorded decisions"
          tone="green"
        />
        <Metric
          Icon={TriangleAlert}
          label="Exporter queue"
          value={exporter.spool_pending ?? exporter.queue_depth ?? '—'}
          detail="pending evidence"
          tone="amber"
        />
      </section>

      <section className="panels">
        <article className="panel fleet">
          <PanelTitle title="Fleet health" copy={preview ? 'Preview device inventory' : 'Authenticated device inventory'} />
          <div className="fleet-body">
            <div className="donut" role="img" aria-label={`Fleet coverage: ${visiblePercent}% visible`}>
              <span>
                <b>{visiblePercent}%</b>
                <small>{preview ? 'preview protected' : 'protected'}</small>
              </span>
            </div>
            <div className="legend">
              <p>
                <i className="g" aria-hidden="true" />
                <span>Enrolled</span>
                <b>{enrolledCount}</b>
              </p>
              <p>
                <i className="a" aria-hidden="true" />
                <span>Lost events</span>
                <b>{sensors.lost_events ?? '—'}</b>
              </p>
              <p>
                <i aria-hidden="true" />
                <span>Queue depth</span>
                <b>{exporter.queue_depth ?? '—'}</b>
              </p>
            </div>
          </div>
        </article>

        <article className="panel sensors">
          <PanelTitle
            title="Runtime health"
            copy="Latest watchdog publication"
            status={sensors.attached === true ? 'Operational' : 'Unverified'}
          />
          <div className="sensor-list">
            {[
              ['Policy', latestStatus.policy?.healthy, latestStatus.policy?.active_policy_hash],
              ['OPA', latestStatus.opa?.healthy, 'policy evaluator'],
              ['Probe', sensors.attached, probeMode],
              ['Bridge', sensors.attached, bridgeDetail],
              ['Lost events', sensors.lost_events === 0, `${sensors.lost_events ?? 0} lost events`],
              ['Evidence exporter', exporter.export_failures === 0, `${exporter.spool_pending ?? 0} spooled`]
            ].map(([name, healthy, detail]) => (
              <div className="sensor" key={name}>
                <span>
                  <Activity aria-hidden="true" />
                </span>
                <p>
                  <b>{name}</b>
                  <small>{detail || 'not reported'}</small>
                </p>
                <strong className={`status-badge ${healthy === true ? 'healthy' : healthy === false ? 'attention' : 'unknown'}`}>
                  {healthy === true ? 'healthy' : healthy === false ? 'attention' : 'unknown'}
                </strong>
              </div>
            ))}
          </div>
        </article>
      </section>

      <OutcomeTable outcomes={data.outcomes} />
    </>
  )
}
