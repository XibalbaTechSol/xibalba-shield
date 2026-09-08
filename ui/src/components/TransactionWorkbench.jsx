import { useState } from 'react'
import { CheckCircle2, KeyRound, Play, ShieldAlert } from 'lucide-react'

export function TransactionWorkbench({ api }) {
  const [form, setForm] = useState(() => ({ deviceId: '', deviceToken: '', agentId: 'operator-console', requestId: `console-${Date.now()}`, chainId: '1', to: '0x0000000000000000000000000000000000000001', functionSelector: '0x00000000', valueWei: '0' }))
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [approverId, setApproverId] = useState('')
  const [approvalMessage, setApprovalMessage] = useState('')
  const [approval, setApproval] = useState(null)

  const update = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }))
  const simulate = async (event) => {
    event.preventDefault()
    setBusy(true); setError(''); setResult(null)
    try {
      const decision = await api.transactionSimulation(form.deviceId, {
        agent_id: form.agentId, request_id: form.requestId, chain_id: Number(form.chainId),
        to: form.to, function_selector: form.functionSelector, value_wei: Number(form.valueWei),
      }, form.deviceToken)
      setResult(decision)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally { setBusy(false) }
  }
  const createApproval = async () => {
    const intentHash = result?.decision?.intent_hash
    if (!intentHash || !approverId.trim()) return
    setApprovalMessage('Creating approval…')
    try {
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString()
      const approval = await api.createApproval({ device_id: form.deviceId, intent_hash: intentHash, approver_id: approverId.trim(), expires_at: expiresAt })
      setApproval(approval)
      setApprovalMessage(`Approval ${approval.approval_id || 'created'} expires ${expiresAt}.`)
    } catch (err) {
      setApprovalMessage(err instanceof Error ? err.message : String(err))
    }
  }
  const verifyApproval = async () => {
    if (!approval?.intent_hash) return
    setApprovalMessage('Verifying approval…')
    try {
      const result = await api.verifyApproval(form.deviceId, approval.intent_hash, form.deviceToken)
      setApprovalMessage(result.authorized ? 'Approval is valid and ready for consumption.' : `Approval is not valid: ${result.reason}`)
    } catch (err) { setApprovalMessage(err instanceof Error ? err.message : String(err)) }
  }
  const consumeApproval = async () => {
    if (!approval?.approval_id) return
    setApprovalMessage('Consuming approval…')
    try {
      await api.consumeApproval({ device_id: form.deviceId, approval_id: approval.approval_id, intent_hash: approval.intent_hash })
      setApprovalMessage('Approval consumed. It cannot be replayed.')
    } catch (err) { setApprovalMessage(err instanceof Error ? err.message : String(err)) }
  }

  return <section className="resource transaction-workbench">
    <header>
      <p className="eyebrow">TRANSACTION GOVERNANCE</p>
      <h2>Transaction & Approval Workbench</h2>
      <span>Simulate a device-authenticated intent before broadcast. Shield never signs or broadcasts from this console.</span>
      <small className="evidence-label">Device credentials are used only for this request and are never persisted.</small>
    </header>
    <form className="transaction-form" onSubmit={simulate}>
      <label>Device ID<input required value={form.deviceId} onChange={update('deviceId')} placeholder="demo-linux-001" /></label>
      <label>Device token<input required type="password" value={form.deviceToken} onChange={update('deviceToken')} /></label>
      <label>Agent ID<input required value={form.agentId} onChange={update('agentId')} /></label>
      <label>Chain ID<input required type="number" min="1" value={form.chainId} onChange={update('chainId')} /></label>
      <label>Destination<input required value={form.to} onChange={update('to')} /></label>
      <label>Function selector<input required value={form.functionSelector} onChange={update('functionSelector')} /></label>
      <label>Value (wei)<input required type="number" min="0" value={form.valueWei} onChange={update('valueWei')} /></label>
      <button type="submit" className="primary" disabled={busy}><Play size={14} /> {busy ? 'Simulating…' : 'Simulate intent'}</button>
    </form>
    {error && <p className="form-message error" role="alert">{error}</p>}
    {result && <div className={`transaction-result ${result.decision?.action === 'allow' ? 'success' : 'warning'}`}>
      {result.decision?.action === 'allow' ? <CheckCircle2 /> : <ShieldAlert />}
      <div><b>{result.decision?.action?.toUpperCase() || 'DECISION'}</b><p>{result.decision?.reason || 'No reason returned.'}</p><small>{result.decision?.intent_hash || 'No intent hash'}</small></div>
    </div>}
    {result?.decision?.action === 'escalate' && <div className="approval-panel">
      <div><b>Human approval required</b><p>Bind an approver to this exact intent hash before execution can proceed.</p></div>
      <label>Approver ID<input value={approverId} onChange={(event) => setApproverId(event.target.value)} placeholder="secops.operator" /></label>
      <button type="button" className="primary" onClick={createApproval} disabled={!approverId.trim()}>Create approval</button>
      {approval && <div className="approval-actions"><button type="button" className="secondary-btn" onClick={verifyApproval}>Verify approval</button><button type="button" className="danger-action-btn" onClick={consumeApproval}>Consume approval</button></div>}
      {approvalMessage && <p className="form-message" aria-live="polite">{approvalMessage}</p>}
    </div>}
    <div className="transaction-note"><KeyRound size={15} /><span>Approval creation remains a separate admin action after an intent returns <code>escalate</code>.</span></div>
  </section>
}
