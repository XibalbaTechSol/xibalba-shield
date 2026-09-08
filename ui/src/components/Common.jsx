import { useMemo } from 'react'
import { Database } from 'lucide-react'
import { ShieldApi } from '../api'
import { TenantSwitcher, AvatarPreference, AuditEvents } from './SettingsView'

export function Metric({ Icon, label, value, detail, tone }) {
  return (
    <article className="metric">
      <div>
        <span className={tone || ''}>
          <Icon aria-hidden="true" />
        </span>
        {label}
      </div>
      <b>{value}</b>
      <small>{detail}</small>
    </article>
  )
}

export function PanelTitle({ title, copy, status }) {
  return (
    <header className="panel-title">
      <div>
        <h3>{title}</h3>
        <p>{copy}</p>
      </div>
      {status && (
        <span>
          <i aria-hidden="true" />
          {status}
        </span>
      )}
    </header>
  )
}

export function JsonRows({ rows }) {
  if (!rows || rows.length === 0) {
    return (
      <div className="json-rows">
        <div className="empty">
          <Database aria-hidden="true" />
          <h3>No records returned</h3>
          <p>The authenticated endpoint returned an empty collection.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="json-rows">
      {rows.map((row, i) => {
        const dec = row.decision || {}
        const device = row.device_id || dec.device_id || row.event?.device_id || ''
        const action = dec.decision?.action || row.action || (dec.class && dec.class !== 'policy_decision' ? dec.class : '') || row.event_type || row.kind || ''
        const ruleName = dec.rule?.name || row.rule?.name || ''
        const time = row.received_at || row.created_at || row.updated_at || dec.time || row.time || ''

        let title = row.integration_id || ''
        if (!title && device && action) {
          title = `${device} · ${action.toUpperCase()}${ruleName ? ` (${ruleName})` : ''}`
        } else if (!title && device) {
          title = `${device}${row.status?.bcc_middleware ? ` · middleware ${row.status.bcc_middleware}` : ''}`
        } else if (!title) {
          title = row.event_type || row.kind || `Record ${i + 1}`
        }

        return (
          <details key={row.id || dec.invocation_id || i}>
            <summary>
              <span>{title}</span>
              <span>{time}</span>
            </summary>
            <pre>{JSON.stringify(row, null, 2)}</pre>
          </details>
        )
      })}
    </div>
  )
}

export function Resource({ title, copy, children }) {
  const connection = title === 'Account & control plane'
    ? (() => {
        try {
          return JSON.parse(sessionStorage.getItem('shield-connection') || '{}')
        } catch {
          return {}
        }
      })()
    : {}

  const resourceApi = useMemo(
    () =>
      title === 'Account & control plane' && connection.baseUrl
        ? new ShieldApi(connection.baseUrl, connection.tenant, connection.token)
        : null,
    [title, connection.baseUrl, connection.tenant, connection.token]
  )

  return (
    <section className="resource">
      <header>
        <p className="eyebrow">LIVE CONTROL PLANE</p>
        <h2>{title}</h2>
        <span>{copy}</span>
        <small className="evidence-label">
          Evidence class: authenticated local control-plane data; synthetic/demo records are labeled explicitly.
        </small>
      </header>
      {title === 'Account & control plane' && (
        <>
          <TenantSwitcher />
          <AvatarPreference />
          {resourceApi && <AuditEvents api={resourceApi} email={connection.account?.email || ''} />}
        </>
      )}
      {children}
    </section>
  )
}

export function ActionForm({
  title,
  copy,
  fields,
  submit,
  buttonText = 'Submit',
  successText = 'Action completed successfully.'
}) {
  const handleSubmit = async (event) => {
    event.preventDefault()
    const form = event.currentTarget
    const submitBtn = form.querySelector('button[type="submit"]') || form.querySelector('button')
    const messageEl = form.querySelector('.form-message')
    
    if (submitBtn) submitBtn.disabled = true
    if (messageEl) {
      messageEl.textContent = 'Submitting…'
      messageEl.className = 'form-message pending'
    }

    try {
      await submit(Object.fromEntries(new FormData(form)))
      if (messageEl) {
        messageEl.textContent = successText
        messageEl.className = 'form-message success'
      }
      form.reset()
    } catch (error) {
      if (messageEl) {
        messageEl.textContent = `Error: ${error.message}`
        messageEl.className = 'form-message error'
      }
    } finally {
      if (submitBtn) submitBtn.disabled = false
    }
  }

  return (
    <Resource title={title} copy={copy || 'Writes require the connected tenant admin credential.'}>
      <form className="action-form" onSubmit={handleSubmit}>
        {fields.map(([name, label]) => (
          <label key={name}>
            {label}
            <input name={name} required />
          </label>
        ))}
        <button type="submit" className="primary">{buttonText}</button>
        <p className="form-message" aria-live="polite"></p>
      </form>
    </Resource>
  )
}
