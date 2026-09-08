import { useEffect, useState } from 'react'
import { FileCheck2, Shield, CheckCircle2, HardDrive, RotateCcw, Sliders, LockKeyhole } from 'lucide-react'

const PRESELECTED_POLICIES = [
  {
    id: 'smb',
    name: 'SMB & Autonomous Workspace',
    version: 'smb-2026.08',
    category: 'Local Workstation & Agent Safety',
    description: 'Endpoint defense against unverified autonomous workloads. Automatically contains shadow AI processes, blocks unregistered agent tools, and monitors sensitive file paths.',
    badge: 'Recommended for Workstations',
    rules: [
      {
        rule_id: 'smb-contain-shadow-ai-processes',
        name: 'Contain shadow AI process paths',
        action: 'contain',
        detail: 'Matches process execution in */ai/*, */llm-tools/*, */shadow-agent/*',
      },
      {
        rule_id: 'smb-deny-unregistered-agent-tools',
        name: 'Deny unregistered agent tool activity',
        action: 'deny',
        detail: 'Blocks tool invocations when agent registration is false',
      },
      {
        rule_id: 'smb-escalate-sensitive-file-write',
        name: 'Escalate sensitive file writes',
        action: 'escalate',
        detail: 'Flags writes to /home/*/.ssh/*, /etc/*, /var/secrets/*',
      },
    ],
    doc: {
      policy_version: 'smb-2026.08',
      rules: [
        {
          rule_id: 'smb-contain-shadow-ai-processes',
          name: 'Contain known shadow AI process paths',
          version: '1.0.0',
          conditions: [{ type: 'process', match: { exe_path: ['*/ai/*', '*/llm-tools/*', '*/shadow-agent/*'] } }],
          actions: [{ type: 'contain', message: 'Unregistered AI workload path contained.' }],
        },
        {
          rule_id: 'smb-deny-unregistered-agent-tools',
          name: 'Deny unregistered agent tool activity',
          version: '1.0.0',
          conditions: [{ type: 'agent', match: { registered: [false] } }],
          actions: [{ type: 'deny', message: 'Agent is not registered on this endpoint.' }],
        },
        {
          rule_id: 'smb-escalate-sensitive-file-write',
          name: 'Escalate sensitive file write metadata',
          version: '1.0.0',
          conditions: [{ type: 'file', match: { path: ['/home/*/.ssh/*', '/etc/*', '/var/secrets/*'] } }],
          actions: [{ type: 'escalate', message: 'Sensitive path write observed.' }],
        },
      ],
    },
  },
  {
    id: 'professional-services',
    name: 'Professional Services & Client Data',
    version: 'professional-services-2026.08',
    category: 'Corporate Governance',
    description: 'Balanced policy for consulting and client data confidentiality. Denies unregistered agents, restricts unapproved LLM endpoints, and flags client contract or financial attachment.',
    badge: 'Standard Governance',
    rules: [
      {
        rule_id: 'ps-deny-unregistered-agents',
        name: 'Deny unregistered agent activity',
        action: 'deny',
        detail: 'Blocks unregistered agent execution across tenant endpoints',
      },
      {
        rule_id: 'ps-deny-unapproved-model-routing',
        name: 'Deny unapproved model endpoints',
        action: 'deny',
        detail: 'Restricts routing to unapproved HTTP / external AI gateways',
      },
      {
        rule_id: 'ps-escalate-client-data-context',
        name: 'Escalate client-data context attachment',
        action: 'escalate',
        detail: 'Audits context attachment of contracts, customer records, and financials',
      },
    ],
    doc: {
      policy_version: 'professional-services-2026.08',
      rules: [
        {
          rule_id: 'ps-deny-unregistered-agents',
          name: 'Deny unregistered agent activity',
          version: '1.0.0',
          conditions: [{ type: 'agent', match: { registered: [false] } }],
          actions: [{ type: 'deny', message: 'Unregistered agent activity denied.' }],
        },
        {
          rule_id: 'ps-deny-unapproved-model-routing',
          name: 'Deny unapproved model endpoints',
          version: '1.0.0',
          conditions: [{ type: 'context', match: { model_endpoint: ['https://unapproved.example/*', 'http://*'] } }],
          actions: [{ type: 'deny', message: 'Model endpoint is not approved for this tenant.' }],
        },
        {
          rule_id: 'ps-escalate-client-data-context',
          name: 'Escalate client-data context attachment',
          version: '1.0.0',
          conditions: [{ type: 'context', match: { data_sources: ['client_contracts', 'customer_records', 'financial_docs'] } }],
          actions: [{ type: 'escalate', message: 'Client data source attached to agent context.' }],
        },
      ],
    },
  },
  {
    id: 'regulated',
    name: 'Regulated Enterprise & Healthcare',
    version: 'regulated-2026.08',
    category: 'Zero Trust & Strict Compliance',
    description: 'High-assurance posture for healthcare, PHI, and financial institutions. Enforces PHI data-source denial, blocks unregistered agents, denies high-risk output releases, and audits sensitive writes.',
    badge: 'HIPAA / Regulated',
    rules: [
      {
        rule_id: 'regulated-deny-unregistered-agents',
        name: 'Deny unregistered agent activity',
        action: 'deny',
        detail: 'Zero-tolerance block for any non-allowlisted agent runtime',
      },
      {
        rule_id: 'regulated-deny-phi-context',
        name: 'Deny PHI-bearing data context',
        action: 'deny',
        detail: 'Prevents EHR, patient record, and claims PHI attachment',
      },
      {
        rule_id: 'regulated-deny-high-risk-output',
        name: 'Deny high-risk output release',
        action: 'deny',
        detail: 'Rejects autonomous output with high or critical risk rating',
      },
      {
        rule_id: 'regulated-escalate-sensitive-write',
        name: 'Escalate regulated sensitive-path writes',
        action: 'escalate',
        detail: 'Strict audit on /home/*/.ssh/*, /etc/*, /var/lib/*/secrets/*',
      },
    ],
    doc: {
      policy_version: 'regulated-2026.08',
      rules: [
        {
          rule_id: 'regulated-deny-unregistered-agents',
          name: 'Deny unregistered agent activity',
          version: '1.0.0',
          conditions: [{ type: 'agent', match: { registered: [false] } }],
          actions: [{ type: 'deny', message: 'Unregistered agent activity denied in regulated mode.' }],
        },
        {
          rule_id: 'regulated-deny-phi-context',
          name: 'Deny PHI-bearing data-source context',
          version: '1.0.0',
          conditions: [{ type: 'context', match: { data_sources: ['ehr_encounter', 'patient_record', 'claims_phi'] } }],
          actions: [{ type: 'deny', message: 'PHI-bearing data source cannot be attached to this agent context.' }],
        },
        {
          rule_id: 'regulated-deny-high-risk-output',
          name: 'Deny high-risk output release',
          version: '1.0.0',
          conditions: [{ type: 'activity', match: { risk_level: ['high', 'critical'] } }],
          actions: [{ type: 'deny', message: 'High-risk output release denied.' }],
        },
        {
          rule_id: 'regulated-escalate-sensitive-write',
          name: 'Escalate regulated sensitive-path writes',
          version: '1.0.0',
          conditions: [{ type: 'file', match: { path: ['/home/*/.ssh/*', '/etc/*', '/var/lib/*/secrets/*', '/var/secrets/*'] } }],
          actions: [{ type: 'escalate', message: 'Sensitive regulated path write observed.' }],
        },
      ],
    },
  },
]

export function PoliciesView({ data, api, refresh }) {
  const [selectedId, setSelectedId] = useState('smb')
  const [targetDevice, setTargetDevice] = useState(() => data.devices?.[0]?.device_id || 'xibalba-desktop')
  const [deploying, setDeploying] = useState(false)
  const [deployResult, setDeployResult] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')
  const [rollbackMsg, setRollbackMsg] = useState('')
  const [rollbackError, setRollbackError] = useState(false)
  const [history, setHistory] = useState([])
  const [rollbackTarget, setRollbackTarget] = useState(null)
  const [approvalThreshold, setApprovalThreshold] = useState('75')
  const [autoContain, setAutoContain] = useState(true)
  const [humanApproval, setHumanApproval] = useState(true)
  const [enforcementMessage, setEnforcementMessage] = useState('')

  useEffect(() => {
    let cancelled = false
    api.settings().then(({ settings = {} }) => {
      if (cancelled) return
      if (settings.approvalThreshold !== undefined) setApprovalThreshold(String(settings.approvalThreshold))
      if (typeof settings.autoContain === 'boolean') setAutoContain(settings.autoContain)
      if (typeof settings.humanApproval === 'boolean') setHumanApproval(settings.humanApproval)
    }).catch(() => {})
    return () => { cancelled = true }
  }, [api])

  const saveEnforcement = async (event) => {
    event.preventDefault()
    setEnforcementMessage('Saving enforcement controls…')
    try {
      const current = await api.settings()
      const result = await api.createSettingsChangeRequest('containment', { ...(current.settings || {}), approvalThreshold: Number(approvalThreshold), autoContain, humanApproval })
      setEnforcementMessage(`Approval requested (${result.request_id}).`)
    } catch (error) {
      setEnforcementMessage(error instanceof Error ? error.message : String(error))
    }
  }

  const selectedPolicy = PRESELECTED_POLICIES.find((p) => p.id === selectedId) || PRESELECTED_POLICIES[0]
  const currentDevice = data.devices?.find((d) => (d.device_id || d.id) === targetDevice) || data.devices?.[0]

  const handleDeploy = async () => {
    if (!targetDevice) {
      setErrorMsg('Please select or specify a target device.')
      return
    }
    setDeploying(true)
    setErrorMsg('')
    setDeployResult(null)
    try {
      const res = await api.deployPolicy(targetDevice, selectedPolicy.doc)
      setDeployResult(res)
      await refresh()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setDeploying(false)
    }
  }

  const handleRollback = async (e) => {
    e.preventDefault()
    if (!targetDevice) return
    setRollbackMsg('Loading policy history…')
    setRollbackError(false)
    try {
      const result = await api.policyHistory(targetDevice)
      const latest = rollbackTarget || result.history?.[0]
      setHistory(result.history || [])
      if (!latest) throw new Error(`No previous policy is available for ${targetDevice}.`)
      if (!window.confirm(`Rollback ${targetDevice} to ${latest.policy_version}?`)) {
        setRollbackMsg('')
        return
      }
      await api.rollbackPolicy(targetDevice, latest.id)
      setRollbackMsg(`Successfully rolled back ${targetDevice} to ${latest.policy_version}.`)
      await refresh()
    } catch (error) {
      setRollbackMsg(error instanceof Error ? error.message : String(error))
      setRollbackError(true)
    }
  }
  const loadHistory = async () => {
    setRollbackMsg('Loading policy history…')
    try { const result = await api.policyHistory(targetDevice); setHistory(result.history || []); setRollbackMsg(`${result.history?.length || 0} historical versions loaded.`) } catch (error) { setRollbackMsg(error instanceof Error ? error.message : String(error)); setRollbackError(true) }
  }

  return (
    <div className="policies-view">
      <section className="resource">
        <header>
          <p className="eyebrow">PRESELECTED POLICY BUNDLES</p>
          <h2>Active Policy Governance</h2>
          <span>Select from three pre-engineered zero-trust policy profiles, deploy to enrolled devices, or inspect rollback history.</span>
          <small className="evidence-label">
            Evidence class: authenticated local control-plane data; synthetic/demo records are labeled explicitly.
          </small>
        </header>

        <form className="policy-enforcement-panel settings-card" onSubmit={saveEnforcement}>
          <div className="settings-card-header"><div className="settings-card-title"><Sliders size={18} /><h3>Enforcement controls</h3></div><span className="live-status-pill"><LockKeyhole size={13} /> Policy-gated</span></div>
          <p className="settings-card-desc">Define when Shield acts automatically and when a human must approve a proposal. Changes are tenant-scoped and auditable.</p>
          <div className="settings-fields-grid"><div className="field-group"><label htmlFor="approval-threshold">Human approval below confidence</label><select id="approval-threshold" value={approvalThreshold} onChange={(event) => setApprovalThreshold(event.target.value)}><option value="50">50%</option><option value="60">60%</option><option value="75">75% · recommended</option><option value="90">90%</option></select><span className="field-hint">Only a policy decision can authorize containment.</span></div><div className="field-group"><label>Active policy</label><div className="settings-readout">{selectedPolicy.version}</div></div></div>
          <div className="toggle-list"><label className="toggle-item"><input type="checkbox" checked={autoContain} onChange={(event) => setAutoContain(event.target.checked)} /><div><b>Auto-contain policy matches</b><p>Pause eligible workloads when the active policy returns contain.</p></div></label><label className="toggle-item"><input type="checkbox" checked={humanApproval} onChange={(event) => setHumanApproval(event.target.checked)} /><div><b>Require human approval for low confidence</b><p>Keep decisions below the configured threshold in the approval queue.</p></div></label></div>
          <div className="settings-actions-footer"><button type="submit" className="primary-btn"><Sliders size={14} /> Save enforcement controls</button>{enforcementMessage && <span className="form-message" aria-live="polite">{enforcementMessage}</span>}</div>
        </form>

        {/* 3 Preselected Policy Cards */}
        <div className="policy-bundles-grid">
          {PRESELECTED_POLICIES.map((bundle) => {
            const isSelected = bundle.id === selectedId
            const isActiveOnDevice = currentDevice?.policy_version === bundle.version
            return (
              <div
                key={bundle.id}
                className={`policy-bundle-card ${isSelected ? 'selected' : ''}`}
                onClick={() => setSelectedId(bundle.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setSelectedId(bundle.id) }}
              >
                <div className="policy-bundle-header">
                  <span className="policy-category-tag">{bundle.category}</span>
                  {isActiveOnDevice && (
                    <span className="policy-active-pill">
                      <CheckCircle2 size={12} /> Active on Device
                    </span>
                  )}
                </div>

                <h3 className="policy-bundle-title">{bundle.name}</h3>
                <code className="policy-bundle-version">{bundle.version}</code>
                <p className="policy-bundle-desc">{bundle.description}</p>

                <div className="policy-rules-summary">
                  <b>Included Rules ({bundle.rules.length})</b>
                  <ul>
                    {bundle.rules.map((rule) => (
                      <li key={rule.rule_id}>
                        <span className={`action-badge ${rule.action}`}>{rule.action.toUpperCase()}</span>
                        <span className="rule-name">{rule.name}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="policy-bundle-footer">
                  <span className="policy-badge-label">{bundle.badge}</span>
                  <button
                    type="button"
                    className={`select-bundle-btn ${isSelected ? 'active' : ''}`}
                    onClick={(e) => {
                      e.stopPropagation()
                      setSelectedId(bundle.id)
                    }}
                  >
                    {isSelected ? 'Selected' : 'Select'}
                  </button>
                </div>
              </div>
            )
          })}
        </div>

        {/* Deployment Section */}
        <div className="policy-deploy-panel">
          <div className="deploy-panel-header">
            <div className="deploy-panel-title">
              <Shield size={18} className="icon-green" />
              <div>
                <h3>Deploy Selected Policy: {selectedPolicy.name}</h3>
                <p>Applies cryptographic policy bundle <code>{selectedPolicy.version}</code> with {selectedPolicy.rules.length} enforcement rules to the target device.</p>
              </div>
            </div>
          </div>

          <div className="deploy-controls-row">
            <div className="deploy-field">
              <label htmlFor="target-device-select">
                <HardDrive size={14} /> Target Endpoint Device
              </label>
              <select
                id="target-device-select"
                value={targetDevice}
                onChange={(e) => setTargetDevice(e.target.value)}
                className="form-select"
              >
                {(data.devices || []).map((d) => {
                  const devId = d.device_id || d.id
                  return (
                    <option key={devId} value={devId}>
                      {devId} ({d.device_role || d.os || 'Endpoint'})
                    </option>
                  )
                })}
              </select>
            </div>

            <div className="deploy-action">
              <button
                type="button"
                className="deploy-button"
                onClick={handleDeploy}
                disabled={deploying}
              >
                {deploying ? (
                  <>Deploying Policy…</>
                ) : (
                  <>
                    <FileCheck2 size={16} /> Deploy {selectedPolicy.version}
                  </>
                )}
              </button>
            </div>
          </div>

          {deployResult && (
            <div className="deploy-success-alert">
              <CheckCircle2 size={16} />
              <div>
                <b>Policy Deployed Successfully</b>
                <p>
                  Version: <code>{deployResult.policy_version}</code> · Hash: <code>{deployResult.policy_hash}</code> ({deployResult.rules} rules active)
                </p>
              </div>
            </div>
          )}

          {errorMsg && (
            <div className="deploy-error-alert">
              <p>Deployment failed: {errorMsg}</p>
            </div>
          )}
        </div>
      </section>

      {/* Rollback & History */}
      <section className="resource" style={{ marginTop: '24px' }}>
        <header>
          <p className="eyebrow">REVERSION CONTROLS</p>
          <h2>Rollback a Policy</h2>
          <span>Restores the most recent prior policy version from cryptographic history for <code>{targetDevice}</code>.</span>
        </header>
        <form className="action-form" onSubmit={handleRollback}>
          <label>
            Device ID
            <input
              name="deviceId"
              required
              value={targetDevice}
              onChange={(e) => setTargetDevice(e.target.value)}
              placeholder="xibalba-desktop"
            />
          </label>
          <button type="submit" className="primary">
            <RotateCcw size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
            Load & Rollback to Previous
          </button>
          <button type="button" className="secondary-btn" onClick={loadHistory}>Load version timeline</button>
          {rollbackMsg && (
            <p className={`form-message ${rollbackError ? 'error' : 'success'}`} aria-live="polite">
              {rollbackMsg}
            </p>
          )}
        </form>
        {history.length > 0 && <div className="policy-history-timeline"><p className="eyebrow">VERSION TIMELINE</p>{history.map((entry) => <button type="button" key={entry.id} className={`policy-history-row ${rollbackTarget?.id === entry.id ? 'selected' : ''}`} onClick={() => setRollbackTarget(entry)}><span><b>{entry.policy_version}</b><small>{entry.created_at}</small></span><code>{entry.policy_hash}</code></button>)}<small className="field-hint">Select a version, then confirm rollback. Hashes are read-only control-plane evidence.</small></div>}
      </section>
    </div>
  )
}
