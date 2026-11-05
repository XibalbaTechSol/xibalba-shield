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

  return (
    <main className="device">
      <header className="device-header">
        <div>
          <p className="eyebrow">XIBALBA SHIELD · THIS DEVICE</p>
          <h1>{overview ? (confirmed === 0 ? 'Nothing frozen' : `${confirmed} frozen`) : 'Reading device state…'}</h1>
          <p className="sub">
            Counted only where the operating system shows the process stopped, not where a log says it was.
          </p>
        </div>
        <button type="button" className="secondary" onClick={refresh}>Refresh</button>
      </header>

      {error && <p className="message error" role="alert">Could not read the device: {error}</p>}

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
