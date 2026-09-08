import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import { PanelTitle } from './Common'

export function OutcomeTable({ outcomes }) {
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && selected) {
        setSelected(null)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [selected])

  return (
    <>
      <article className="panel events">
        <PanelTitle
          title="Enforcement outcomes"
          copy="Recorded containment attempts, including failures"
        />
        <div className="event-table" role="region" aria-label="Enforcement outcomes table" tabIndex={0}>
          <header>
            <span>RESULT</span>
            <span>ACTION</span>
            <span>DEVICE</span>
            <span>DETAIL</span>
            <span>TIME</span>
          </header>
          {outcomes && outcomes.length > 0 ? (
            outcomes.slice(0, 20).map((record, i) => {
              const o = record.outcome || record
              const decision = o.completed === false ? 'failed' : o.decision || o.action || 'recorded'
              return (
                <button
                  className="event-row"
                  type="button"
                  key={record.id || i}
                  onClick={() => setSelected(record)}
                  aria-haspopup="dialog"
                >
                  <span>
                    <i className={decision} aria-hidden="true" />
                    <b>{decision}</b>
                  </span>
                  <code>{o.action || '—'}</code>
                  <span>{record.device_id || o.device_id || '—'}</span>
                  <code className="detail-truncate" title={o.error || o.target || o.event_id || ''}>
                    {o.error || o.target || o.event_id || '—'}
                  </code>
                  <small>{record.created_at || o.time || '—'}</small>
                </button>
              )
            })
          ) : (
            <div className="empty-row">No enforcement outcomes returned.</div>
          )}
        </div>
      </article>

      {selected && (
        <aside
          className="event-drawer"
          role="dialog"
          aria-modal="true"
          aria-label="Enforcement event details"
        >
          <header>
            <div>
              <p className="eyebrow">EVENT DETAIL</p>
              <h3>Enforcement record</h3>
            </div>
            <button
              type="button"
              aria-label="Close details"
              className="drawer-close"
              onClick={() => setSelected(null)}
            >
              <X aria-hidden="true" />
            </button>
          </header>
          <pre>{JSON.stringify(selected, null, 2)}</pre>
        </aside>
      )}
    </>
  )
}
