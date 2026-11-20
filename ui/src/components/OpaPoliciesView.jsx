import { useEffect, useState } from 'react'
import { FileCode, Save, Plus, RefreshCw, CheckCircle2, AlertTriangle, Code2 } from 'lucide-react'

// A pack is "loaded" only if OPA's /v1/policies lists it; "differs" means OPA's copy is not
// byte-identical to the file Shield ships (hash compare done by the backend).
function loadedLabel(policy, daemon) {
  if (daemon && !daemon.reachable) return 'Unknown (OPA unreachable)'
  if (!policy.loaded) return 'Not loaded'
  return policy.in_sync ? 'Loaded (in sync)' : 'Loaded — differs from file'
}

export function OpaPoliciesView({ api }) {
  const [policies, setPolicies] = useState([])
  const [daemon, setDaemon] = useState(null)
  const [selected, setSelected] = useState(null)
  const [editContent, setEditContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saveStatus, setSaveStatus] = useState(null)
  const [error, setError] = useState(null)
  const [isCreatingNew, setIsCreatingNew] = useState(false)
  const [newPolicyId, setNewPolicyId] = useState('')

  const fetchPolicies = async () => {
    try {
      setLoading(true)
      const data = await api.opaPolicies()
      setPolicies(data.policies || [])
      setDaemon(data)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPolicies()
  }, [api])

  const handleSelect = (policy) => {
    setSelected(policy)
    setEditContent(policy.rego || '')
    setSaveStatus(null)
    setIsCreatingNew(false)
  }

  const handleCreateNew = () => {
    setIsCreatingNew(true)
    setSelected({
      id: 'custom-pack',
      name: 'New Custom Rego Policy',
      version: 'custom-2026.11',
      file: 'custom-pack.rego',
      rego: 'package shield.policy\n\n# Custom Rego Guardrail Policy\ndefault allow = true\n\n# Deny execution when conditions match\ndeny[msg] {\n  input.action == "unauthorized_egress"\n  msg := "Blocked unauthorized egress by custom guardrail"\n}\n',
    })
    setNewPolicyId('custom-security-pack')
    setEditContent('package shield.policy\n\n# Custom Rego Guardrail Policy\ndefault allow = true\n\n# Deny execution when conditions match\ndeny[msg] {\n  input.action == "unauthorized_egress"\n  msg := "Blocked unauthorized egress by custom guardrail"\n}\n')
    setSaveStatus(null)
  }

  const handleSave = async () => {
    const targetId = isCreatingNew ? newPolicyId.trim() : selected.id
    if (!targetId) {
      setSaveStatus({ error: 'Policy ID cannot be empty.' })
      return
    }
    if (!editContent.trim()) {
      setSaveStatus({ error: 'Rego policy content cannot be empty.' })
      return
    }
    if (!editContent.includes('package ')) {
      setSaveStatus({ error: 'Rego policy must declare a package (e.g. package shield.policy).' })
      return
    }

    try {
      setSaving(true)
      setSaveStatus(null)
      const res = await api.updateOpaPolicy(targetId, editContent, true)
      setSaveStatus({
        success: true,
        message: `Policy '${res.id}' saved to disk (${res.file}) and ${res.deployed ? 'successfully deployed to running OPA daemon' : 'staged (OPA not reachable)'}. Hash: ${res.hash.slice(0, 20)}...`,
      })
      await fetchPolicies()
      if (isCreatingNew) {
        setIsCreatingNew(false)
      }
    } catch (e) {
      setSaveStatus({ error: e.message || 'Failed to save policy pack' })
    } finally {
      setSaving(false)
    }
  }

  if (loading && policies.length === 0) return <section className="resource"><p>Loading OPA policies…</p></section>
  if (error && policies.length === 0) return <section className="resource"><p className="form-message error" role="alert">Unable to load OPA policies: {error}</p></section>

  return (
    <section className="resource" style={{ padding: '1.25rem', background: 'var(--bg-surface, #121824)', borderRadius: '8px', border: '1px solid var(--border-color, #1f293d)' }}>
      <header className="panel-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FileCode size={20} color="var(--accent-color, #38bdf8)" />
            OPA Policy Studio & Rego Live Editor
          </h2>
          <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.85rem', color: '#94a3b8' }}>
            View, author, and deploy OPA Rego policy packs directly to the running kernel enforcement evaluator.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button type="button" className="secondary-btn" onClick={fetchPolicies} title="Refresh policies from OPA" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', padding: '0.4rem 0.75rem', fontSize: '0.85rem' }}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
          <button type="button" className="primary-btn" onClick={handleCreateNew} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', padding: '0.4rem 0.75rem', fontSize: '0.85rem', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
            <Plus size={14} /> New Policy Pack
          </button>
        </div>
      </header>

      {daemon && (
        <div style={{ padding: '0.6rem 0.85rem', borderRadius: '6px', background: daemon.reachable ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', border: `1px solid ${daemon.reachable ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`, marginBottom: '1rem', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {daemon.reachable ? <CheckCircle2 size={16} color="#10b981" /> : <AlertTriangle size={16} color="#ef4444" />}
          <span>
            <strong>OPA Engine:</strong> {daemon.opa_version || 'unknown'} · <strong>Status:</strong> {daemon.daemon_status} · <strong>Endpoint:</strong> {daemon.opa_url} · <strong>Package:</strong> {daemon.package_path} · <strong>Active Policies:</strong> {daemon.loaded_policy_count}
          </span>
        </div>
      )}

      <table className="policy-table" style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem', marginBottom: '1rem' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #2d3748', color: '#a0aec0' }}>
            <th style={{ padding: '0.5rem' }}>Policy ID</th>
            <th style={{ padding: '0.5rem' }}>Name</th>
            <th style={{ padding: '0.5rem' }}>Version</th>
            <th style={{ padding: '0.5rem' }}>Evaluator Sync</th>
            <th style={{ padding: '0.5rem', textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {policies.map((p) => {
            const isSelected = selected && selected.id === p.id && !isCreatingNew
            return (
              <tr key={p.id} style={{ borderBottom: '1px solid #1a202c', background: isSelected ? 'rgba(56, 189, 248, 0.08)' : 'transparent' }}>
                <td style={{ padding: '0.5rem', fontFamily: 'monospace', color: '#e2e8f0' }}>{p.id}</td>
                <td style={{ padding: '0.5rem', fontWeight: 500 }}>{p.name}</td>
                <td style={{ padding: '0.5rem', color: '#cbd5e1' }}>{p.version || '—'}</td>
                <td style={{ padding: '0.5rem' }}>
                  <span style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    padding: '0.2rem 0.5rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    background: p.in_sync ? 'rgba(16, 185, 129, 0.2)' : (p.loaded ? 'rgba(245, 158, 11, 0.2)' : 'rgba(148, 163, 184, 0.2)'),
                    color: p.in_sync ? '#34d399' : (p.loaded ? '#fbbf24' : '#94a3b8'),
                  }}>
                    {loadedLabel(p, daemon)}
                  </span>
                </td>
                <td style={{ padding: '0.5rem', textAlign: 'right' }}>
                  <button
                    type="button"
                    onClick={() => handleSelect(p)}
                    style={{
                      background: isSelected ? '#38bdf8' : '#1e293b',
                      color: isSelected ? '#0f172a' : '#f8fafc',
                      border: '1px solid #334155',
                      borderRadius: '4px',
                      padding: '0.25rem 0.6rem',
                      fontSize: '0.8rem',
                      cursor: 'pointer',
                      fontWeight: 500,
                    }}
                  >
                    {isSelected ? 'Editing' : 'View & Edit'}
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {selected && (
        <div className="policy-editor-card" style={{ border: '1px solid #2563eb', borderRadius: '8px', padding: '1rem', background: '#0a0e17' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Code2 size={18} color="#38bdf8" />
              <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>
                {isCreatingNew ? 'Create New OPA Policy' : `Editing Policy Pack: ${selected.name}`}
              </h3>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                className="secondary-btn"
                onClick={() => setSelected(null)}
                style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem', background: '#1e293b', border: '1px solid #334155', color: '#cbd5e1', borderRadius: '4px', cursor: 'pointer' }}
              >
                Close Editor
              </button>
              <button
                type="button"
                className="primary-btn"
                onClick={handleSave}
                disabled={saving}
                style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.35rem 0.85rem', fontSize: '0.8rem', background: '#22c55e', border: 'none', color: '#fff', borderRadius: '4px', cursor: saving ? 'not-allowed' : 'pointer', fontWeight: 600 }}
              >
                <Save size={14} />
                {saving ? 'Saving & Deploying…' : 'Save & Deploy to OPA'}
              </button>
            </div>
          </div>

          {isCreatingNew && (
            <div style={{ marginBottom: '0.75rem' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', color: '#94a3b8', marginBottom: '0.25rem' }}>
                Policy ID (alphanumeric & dashes):
              </label>
              <input
                type="text"
                value={newPolicyId}
                onChange={(e) => setNewPolicyId(e.target.value)}
                placeholder="e.g. custom-compliance-pack"
                style={{ width: '100%', padding: '0.4rem 0.6rem', background: '#111827', border: '1px solid #374151', color: '#fff', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.85rem' }}
              />
            </div>
          )}

          {saveStatus && saveStatus.success && (
            <div style={{ padding: '0.5rem 0.75rem', background: 'rgba(34, 197, 94, 0.15)', border: '1px solid #22c55e', borderRadius: '4px', color: '#4ade80', fontSize: '0.8rem', marginBottom: '0.75rem' }}>
              ✓ {saveStatus.message}
            </div>
          )}

          {saveStatus && saveStatus.error && (
            <div style={{ padding: '0.5rem 0.75rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', borderRadius: '4px', color: '#f87171', fontSize: '0.8rem', marginBottom: '0.75rem' }}>
              ✕ Error: {saveStatus.error}
            </div>
          )}

          <div style={{ position: 'relative' }}>
            <textarea
              rows={16}
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              placeholder="package shield.policy..."
              spellCheck="false"
              style={{
                width: '100%',
                padding: '0.75rem',
                fontFamily: '"JetBrains Mono", Consolas, Monaco, monospace',
                fontSize: '0.85rem',
                lineHeight: '1.45',
                background: '#040711',
                color: '#38bdf8',
                border: '1px solid #1e293b',
                borderRadius: '6px',
                resize: 'vertical',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.5rem', fontSize: '0.75rem', color: '#64748b' }}>
            <span>Target File: <code>{isCreatingNew ? `${newPolicyId || 'custom'}.rego` : selected.file}</code></span>
            <span>{editContent.length} characters · {editContent.split('\n').length} lines · Evaluator: Rego v1</span>
          </div>
        </div>
      )}
    </section>
  )
}
