import { useEffect, useState } from 'react'

// A pack is "loaded" only if OPA's /v1/policies lists it; "differs" means OPA's copy is not
// byte-identical to the file Shield ships (hash compare done by the backend).
function loadedLabel(policy, daemon) {
  if (daemon && !daemon.reachable) return 'Unknown (OPA unreachable)'
  if (!policy.loaded) return 'Not loaded'
  return policy.in_sync ? 'Loaded' : 'Loaded — differs from file'
}

export function OpaPoliciesView({ api }) {
  const [policies, setPolicies] = useState([])
  const [daemon, setDaemon] = useState(null)
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    const fetch = async () => {
      try {
        const data = await api.opaPolicies()
        if (!cancelled) {
          setPolicies(data.policies || [])
          setDaemon(data)
          setLoading(false)
        }
      } catch (e) {
        if (!cancelled) {
          setError(e.message)
          setLoading(false)
        }
      }
    }
    fetch()
    return () => { cancelled = true }
  }, [api])

  if (loading) return <section className="resource"><p>Loading OPA policies…</p></section>
  if (error) return <section className="resource"><p className="form-message error" role="alert">Unable to load OPA policies: {error}</p></section>

  return (
    <section className="resource">
      <header className="panel-title">
        <h2>OPA Policies</h2>
        <p>Shield's Rego policy packs, and whether the running Open Policy Agent has each one loaded. Read-only.</p>
      </header>
      {daemon && (
        <p className={daemon.reachable ? 'field-hint' : 'form-message error'} role="status">
          {/* Every value here is read from the OPA daemon itself (health, version, /v1/policies). */}
          OPA {daemon.opa_version || 'version unknown'} · {daemon.daemon_status} · {daemon.opa_url}
          {daemon.reachable ? ` · ${daemon.loaded_policy_count} policies loaded in total` : ''}
        </p>
      )}
      {policies.length === 0 && <p className="empty-state">No OPA policy bundles are available.</p>}
      <table className="policy-table">
        <thead>
          <tr><th>Name</th><th>Version</th><th>In running OPA</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {policies.map((p, i) => (
            <tr key={i}>
              <td>{p.name}</td>
              <td>{p.version || '—'}</td>
              <td title={p.loaded_id || ''}>{loadedLabel(p, daemon)}</td>
              <td>
                <button type="button" onClick={() => setSelected(p)}>View source</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
        {selected && (
          <div className="opa-source-backdrop" role="presentation" onClick={() => setSelected(null)}>
            <section className="opa-source-modal" role="dialog" aria-modal="true" aria-label="OPA policy source" aria-labelledby="opa-source-title" onClick={e => e.stopPropagation()}>
              <header className="opa-source-header">
                <div>
                  <p className="eyebrow">POLICY SOURCE</p>
                  <h3 id="opa-source-title">{selected.name}</h3>
                  <span>{selected.version || 'Unversioned'} · {selected.file || 'Rego bundle'}</span>
                </div>
                <button type="button" className="drawer-close" aria-label="Close policy source" onClick={() => setSelected(null)}>×</button>
              </header>
              <pre className="opa-source-code">{selected.rego || selected.source || 'Policy source is unavailable.'}</pre>
              <footer className="opa-source-footer">
                <span>Source is read-only and loaded from the authenticated control plane.</span>
                <button type="button" className="secondary-btn" onClick={() => setSelected(null)}>Close</button>
              </footer>
            </section>
          </div>
        )}
    </section>
  )
}
