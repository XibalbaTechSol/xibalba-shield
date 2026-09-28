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
          copy="Containment attempts and their verified runtime outcomes"
        />
        <div className="event-table outcome-ledger" role="region" aria-label="Enforcement outcomes table" tabIndex={0}>
          <header>
            <span>OUTCOME</span>
            <span>DEVICE / TARGET</span>
            <span>RUNTIME DETAIL</span>
            <span>TIME</span>
          </header>
          {outcomes && outcomes.length > 0 ? (
            outcomes.slice(0, 20).map((record, i) => {
              const o = record.outcome || record
              const decision = o.completed === false ? 'failed' : o.decision || o.action || 'recorded'
              return (
                <button
                  className="event-row outcome-row"
                  type="button"
                  key={record.id || i}
                  onClick={() => setSelected(record)}
                  aria-haspopup="dialog"
                >
                  <span className="outcome-status-cell">
                    <i className={decision} aria-hidden="true" />
                    <span><b>{decision}</b><small>{o.action || 'recorded'}</small></span>
                  </span>
                  <span className="outcome-target-cell"><b>{record.device_id || o.device_id || '—'}</b><small>{o.target || o.event_id || 'No target recorded'}</small></span>
                  <span className="outcome-detail-cell"><code className="detail-truncate" title={o.error || o.reason || o.event_id || ''}>{o.error || o.reason || o.event_id || 'No failure detail recorded'}</code><small>{o.completed === false ? 'Runtime proof failed' : 'Recorded locally'}</small></span>
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
