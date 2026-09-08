import { useEffect, useState } from 'react'

export function OpaPoliciesView({ api }) {
  const [policies, setPolicies] = useState([])
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
        <p>Tenant policy bundles currently loaded by the Open Policy Agent evaluator.</p>
      </header>
      {policies.length === 0 && <p className="empty-state">No OPA policy bundles are available.</p>}
      <table className="policy-table">
        <thead>
          <tr><th>Name</th><th>Version</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {policies.map((p, i) => (
            <tr key={i}>
              <td>{p.name}</td>
              <td>{p.version || '—'}</td>
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
