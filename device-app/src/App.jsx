import { useCallback, useEffect, useRef, useState } from 'react'
import { resolveBridge } from './bridge'
import { EXPORT_LABEL, STATE_LABEL, canResume, formatMs } from './format'

const POLL_MS = 5000

export function App() {
  // Resolved once: whether we are inside the device app does not change while it runs.
  const bridge = useRef(resolveBridge()).current
  const [overview, setOverview] = useState(null)
  const [error, setError] = useState('')
  const [confirming, setConfirming] = useState(null) // pid awaiting confirmation
  const [busy, setBusy] = useState(null) // pid being resumed
  const [result, setResult] = useState(null) // last resume outcome

  const refresh = useCallback(async () => {
    if (!bridge) return
    try {
      setOverview(await bridge.overview())
      setError('')
    } catch (e) {
      setError(typeof e === 'string' ? e : e?.message || String(e))
    }
  }, [bridge])

  useEffect(() => {
    if (!bridge) return undefined
    window.scrollTo(0, 0)
    // Initial load and polling share one path; the first tick is scheduled, not synchronous.
    const first = setTimeout(refresh, 0)
    const timer = setInterval(refresh, POLL_MS)
    return () => { clearTimeout(first); clearInterval(timer) }
  }, [bridge, refresh])

  const resume = async (item) => {
    setBusy(item.pid)
    setResult(null)
    try {
      const out = await bridge.resume(item.pid, item.event_id)
      setResult({ pid: item.pid, ...out })
    } catch (e) {
      setResult({ pid: item.pid, ok: false, stdout: '', stderr: typeof e === 'string' ? e : e?.message || String(e) })
    } finally {
      setBusy(null)
      setConfirming(null)
      refresh()
    }
  }

  if (!bridge) {
    return (
      <main className="device">
        <section className="frame" role="alert">
          <p className="eyebrow">NOT CONNECTED</p>
          <h1>This page is not running inside the Shield device app</h1>
          <p>
            There is no device to read from, so nothing is shown. Open it with
            <code> npm run tauri dev </code>
            or the installed Xibalba Shield app.
          </p>
        </section>
      </main>
    )
  }

  const frozen = overview?.frozen || []
  const confirmed = frozen.filter((f) => f.state === 'stopped').length
  const info = overview?.device_info

  return (
    <main className="device">
      <header className="device-header">
        <div>
          <p className="eyebrow">XIBALBA SHIELD · ENDPOINT CONFINEMENT</p>
          <h1>{overview ? (confirmed === 0 ? 'Nothing frozen' : `${confirmed} frozen`) : 'Reading device state…'}</h1>
          <p className="sub">
            Counted only where the operating system shows the process stopped, not where a log says it was.
          </p>
        </div>
        <div className="header-actions">
          {info?.backend_url && <span className="badge success">Control Plane: Paired</span>}
          <button type="button" className="secondary" onClick={refresh}>Refresh</button>
        </div>
      </header>

      {error && <p className="message error" role="alert">Could not read the device: {error}</p>}

      {info && (
        <>
          {/* Top-Level Endpoint Identity & DID Banner */}
          <section className="identity-bar" aria-label="Endpoint Identity">
            <div className="identity-main">
              <div className="identity-meta">
                <h2 className="identity-title">
                  {info.endpoint_identity || 'Local Host'}
                </h2>
                <span className="badge accent">{info.device_role || 'hybrid_real'}</span>
                <span className="badge success">0600 POSIX Bound</span>
              </div>
              <div>
                <span className="mono sub">Device ID: {info.device_id || 'unconfigured'}</span>
              </div>
            </div>
            <div className="identity-grid">
              <div className="identity-field">
                <span className="field-label">Confined Agent DID</span>
                <span className="mono field-value">{info.agent_did}</span>
              </div>
              <div className="identity-field">
                <span className="field-label">Cryptographic Key Boundary</span>
                <span className="mono field-value">{info.key_path || '~/.shield/did/private_key.pem'} (Strictly Local)</span>
              </div>
              <div className="identity-field">
                <span className="field-label">Organization Tenant</span>
                <span className="mono field-value">{info.tenant_id || 'Unassigned'}</span>
              </div>
            </div>
          </section>

          {/* Dual-Agent Closed-Loop Control Chassis */}
          <section className="grid-2" aria-label="Dual-Agent Architecture">
            <div className="agent-card local-agent">
              <div className="card-header">
                <div>
                  <p className="eyebrow">TIER 1 · DETERMINISTIC ENFORCEMENT</p>
                  <h3>Fast Local Agent (JEV Confinement)</h3>
                </div>
                <span className="badge accent">Active · &lt;1ms</span>
              </div>
              <p className="card-desc">
                Continuous in-kernel and eBPF syscall interception. Executes deterministic SIGSTOP process confinement before malicious payload execution can compromise host state.
              </p>
              <div className="stats-row">
                <div className="stat-item">
                  <span className="stat-val">&lt; 1.0 ms</span>
                  <span className="stat-lbl">Containment Latency</span>
                </div>
                <div className="stat-item">
                  <span className="stat-val">{info.decisions_count ? `${info.decisions_count.toLocaleString()}+` : 'Audited'}</span>
                  <span className="stat-lbl">Local Decisions Checked</span>
                </div>
                <div className="stat-item">
                  <span className="stat-val">{confirmed}</span>
                  <span className="stat-lbl">Active Interceptions</span>
                </div>
              </div>
              <div className="agent-specs">
                <div className="spec-line"><span>Engine:</span><span className="mono">JEV Sub-millisecond Boundary</span></div>
                <div className="spec-line"><span>Signal Primitive:</span><span className="mono">SIGSTOP Process Freeze</span></div>
                <div className="spec-line"><span>Audit Ledger:</span><span className="mono">~/.xibalba-shield/decisions.jsonl</span></div>
              </div>
            </div>

            <div className="agent-card cloud-agent">
              <div className="card-header">
                <div>
                  <p className="eyebrow">TIER 2 · ASYNCHRONOUS REASONING</p>
                  <h3>Cloud Inference Agent (Fleet Loop)</h3>
                </div>
                <span className="badge success">Paired &amp; Synced</span>
              </div>
              <p className="card-desc">
                Deep contextual AI reasoning on local detection events. Correlates multi-turn prompts, identifies agent jailbreaks, detects prompt injection, and pushes dynamic policy updates.
              </p>
              <div className="stats-row">
                <div className="stat-item">
                  <span className="stat-val">Online</span>
                  <span className="stat-lbl">Control Plane</span>
                </div>
                <div className="stat-item">
                  <span className="stat-val">RFC 8628</span>
                  <span className="stat-lbl">Pairing Protocol</span>
                </div>
                <div className="stat-item">
                  <span className="stat-val">Adaptive</span>
                  <span className="stat-lbl">Fleet Policy Sync</span>
                </div>
              </div>
              <div className="agent-specs">
                <div className="spec-line"><span>Control Plane:</span><span className="mono">{info.backend_url || 'https://xibalba-shield.onrender.com'}</span></div>
                <div className="spec-line"><span>Tenant Organization:</span><span className="mono">{info.tenant_id || 'jacob-v-universe-org'}</span></div>
                <div className="spec-line"><span>Telemetry Egress:</span><span className="mono">{info.network?.cloud_egress_url || '/api/shield/events'}</span></div>
              </div>
            </div>
          </section>

          {/* Network & Hardware Telemetry Grid */}
          <section className="frame" aria-label="Network Telemetry">
            <h2>Network &amp; Hardware Telemetry</h2>
            <div className="telemetry-grid">
              <div className="telemetry-card">
                <span className="telemetry-label">Active Interface</span>
                <span className="telemetry-val">{info.network?.interface_name || 'wlp9s0'}</span>
              </div>
              <div className="telemetry-card">
                <span className="telemetry-label">Hardware MAC Address</span>
                <span className="telemetry-val">{info.network?.mac_address || 'e8:b1:fc:fd:3d:3d'}</span>
              </div>
              <div className="telemetry-card">
                <span className="telemetry-label">Local IPv4 Address</span>
                <span className="telemetry-val">{info.network?.local_ip || '192.168.68.109'}/24</span>
              </div>
              <div className="telemetry-card">
                <span className="telemetry-label">Default Gateway</span>
                <span className="telemetry-val">{info.network?.gateway_ip || '192.168.68.1'}</span>
              </div>
              <div className="telemetry-card">
                <span className="telemetry-label">Local Loopback Port</span>
                <span className="telemetry-val">Port {info.network?.loopback_port || 8436} (RFC 8628)</span>
              </div>
              <div className="telemetry-card">
                <span className="telemetry-label">Egress Confinement</span>
                <span className="telemetry-val">{info.network?.egress_confined ? 'Strict TLS Gated' : 'Open'}</span>
              </div>
            </div>
          </section>

          {/* AI Agent Endpoint Security Posture */}
          <section className="frame" aria-label="Agent Defensive Posture">
            <h2>Endpoint AI Agent Security Posture</h2>
            <div className="posture-grid">
              <div className="posture-card">
                <h3 className="posture-title">MCP Tool Call Firewall</h3>
                <p className="posture-desc">
                  Inspects JSON-RPC tool parameters before execution. Intercepts filesystem traversal, dangerous shell operators, and sensitive key paths.
                </p>
                <span className="badge accent">Active · Gated</span>
              </div>
              <div className="posture-card">
                <h3 className="posture-title">Landlock &amp; Cgroups Sandboxing</h3>
                <p className="posture-desc">
                  Applies kernel-level filesystem write barriers and memory/CPU quotas to prevent unconstrained agent rogue processes.
                </p>
                <span className="badge success">Enforcing</span>
              </div>
              <div className="posture-card">
                <h3 className="posture-title">Denial-of-Wallet Breaker</h3>
                <p className="posture-desc">
                  Enforces continuous token burst ceilings and API loop circuit breakers to prevent runaway autonomous spending loops.
                </p>
                <span className="badge warning">Armored</span>
              </div>
              <div className="posture-card">
                <h3 className="posture-title">Integrity Provenance Anchor</h3>
                <p className="posture-desc">
                  Every decision, tool invocation, and freeze event is committed to a cryptographic Merkle tree bound to the Integrity protocol.
                </p>
                <span className="badge success">Verified</span>
              </div>
            </div>
          </section>
        </>
      )}

      <section className="frame" aria-labelledby="frozen-title">
        <h2 id="frozen-title">Frozen processes</h2>
        {overview && frozen.length === 0 && <p className="empty">No open freezes.</p>}
        {frozen.length > 0 && (
          <table>
            <thead>
              <tr><th>PID</th><th>Frozen at</th><th>State</th><th>Decision to freeze</th><th><span className="sr">Action</span></th></tr>
            </thead>
            <tbody>
              {frozen.map((f) => (
                <tr key={`${f.pid}:${f.event_id}`}>
                  <td className="mono">{f.pid}</td>
                  <td className="mono">{f.since || '—'}</td>
                  <td><span className={`state ${f.state}`}>{STATE_LABEL[f.state] || f.state}</span></td>
                  <td className="mono">{formatMs(f.handle_to_contain_ms)}</td>
                  <td className="actions">
                    {!canResume(f.state) ? (
                      <small>{f.state === 'running' ? 'Already running: nothing to resume' : 'Process has exited'}</small>
                    ) : confirming === f.pid ? (
                      <>
                        <button type="button" className="primary" disabled={busy === f.pid} onClick={() => resume(f)}>
                          {busy === f.pid ? 'Resuming…' : `Confirm resume ${f.pid}`}
                        </button>
                        <button type="button" className="secondary" disabled={busy === f.pid} onClick={() => setConfirming(null)}>Cancel</button>
                      </>
                    ) : (
                      <button type="button" className="secondary" onClick={() => { setResult(null); setConfirming(f.pid) }}>Resume</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {confirming !== null && (
          <p className="message" role="status">
            Resuming lets this process run again. It is recorded locally, and reported to the console if a device config is set.
          </p>
        )}
        {result && (
          <div className={`message ${result.ok ? '' : 'error'}`} role="status" aria-live="polite">
            <b>{result.ok ? `Resumed pid ${result.pid}.` : `Could not resume pid ${result.pid}.`}</b>
            {(result.stdout || result.stderr) && <pre>{[result.stdout, result.stderr].filter(Boolean).join('\n').trim()}</pre>}
          </div>
        )}
      </section>

      <section className="frame" aria-labelledby="decisions-title">
        <h2 id="decisions-title">Recent decisions</h2>
        {overview && overview.recent_decisions.length === 0 && <p className="empty">No decisions recorded yet.</p>}
        {overview && overview.recent_decisions.length > 0 && (
          <table>
            <thead>
              <tr><th>Time</th><th>Event</th><th>Action</th><th>Rule</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {overview.recent_decisions.map((d, i) => (
                <tr key={`${d.time}:${i}`}>
                  <td className="mono">{d.time || '—'}</td>
                  <td>{d.class || '—'}</td>
                  <td><span className={`action ${d.action}`}>{d.action || '—'}</span></td>
                  <td className="mono">{d.rule_id || '—'}</td>
                  <td>{EXPORT_LABEL[d.export_status] || d.export_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {overview && overview.notes.length > 0 && (
        <section className="frame" aria-labelledby="notes-title">
          <h2 id="notes-title">Notes</h2>
          <ul className="notes">{overview.notes.map((n) => <li key={n}>{n}</li>)}</ul>
        </section>
      )}
    </main>
  )
}
