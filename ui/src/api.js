export class ShieldApi {
  constructor(baseUrl, tenantId, adminToken) {
    this.baseUrl = String(baseUrl || window.location.origin).replace(/\/+$/, '')
    this.tenantId = String(tenantId || '').trim()
    this.adminToken = String(adminToken || '').trim()
    this.devProxy = this.adminToken === '__shield_local_proxy__'
  }

  async request(endpoint, { method = 'GET', body, tenant = true, token } = {}) {
    const url = new URL(`${this.baseUrl}${endpoint}`)
    if (tenant && this.tenantId) url.searchParams.set('tenant_id', this.tenantId)
    const headers = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (this.devProxy && !token) headers['X-Shield-Dev-Auth'] = '1'
    else if (token || this.adminToken) headers.Authorization = `Bearer ${token || this.adminToken}`
    // The operator session is an HttpOnly cookie this code cannot read, so it has to ride along
    // on every request. `adminToken` remains only for machine-minted tokens passed in explicitly.
    const response = await fetch(url, { method, headers, credentials: 'include', body: body === undefined ? undefined : JSON.stringify(body) })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(payload.error || payload.message || `${response.status} ${response.statusText}`)
    return payload
  }

  auth(path, input) { return this.request(`/api/shield/auth/${path}`, { method: 'POST', body: input, tenant: false }) }
  switchTenant(email, targetTenantId) { return this.request('/api/shield/auth/switch-tenant', { method: 'POST', body: { email, current_tenant_id: this.tenantId, target_tenant_id: targetTenantId }, tenant: false }) }
  sessions() { return this.request('/api/shield/auth/sessions') }
  authEvents(email = '') { return this.request(`/api/shield/auth/events${email ? `?email=${encodeURIComponent(email)}` : ''}`) }
  testEvents(agentId = '') { return this.request(`/api/shield/test-events${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ''}`) }
  changePassword(email, currentPassword, newPassword) { return this.request('/api/shield/auth/password', { method: 'POST', body: { tenant_id: this.tenantId, email, current_password: currentPassword, new_password: newPassword }, tenant: false }) }
  health() { return this.request('/api/shield/health', { tenant: false }) }
  dashboard() { return this.request('/api/shield/dashboard-summary') }
  devices() { return this.request('/api/shield/devices') }
  agents() { return this.request('/api/shield/agents') }
  agentBindings(deviceId) { return this.request(`/api/shield/devices/${encodeURIComponent(deviceId)}/agent-bindings`) }
  cortexOutbox() { return this.request('/api/shield/cortex-outbox') }
  cortexMemories(deviceId, agentId, limit = 20) { return this.request(`/api/shield/cortex-memories?device_id=${encodeURIComponent(deviceId)}&agent_id=${encodeURIComponent(agentId)}&limit=${limit}`) }
  registerAgent(deviceId, agentId, oracleUrl = '') { return this.request('/api/shield/agents/register', { method: 'POST', body: { tenant_id: this.tenantId, device_id: deviceId, agent_id: agentId, oracle_url: oracleUrl }, tenant: false }) }
  agentBindingAction(deviceId, agentId, action) { return this.request(`/api/shield/devices/${encodeURIComponent(deviceId)}/agent-bindings/${encodeURIComponent(agentId)}/${action}`, { method: 'POST', body: { tenant_id: this.tenantId }, tenant: false }) }
  device(id) { return this.request(`/api/shield/devices/${encodeURIComponent(id)}`) }
  exporterStatus() { return this.request('/api/shield/exporter-status') }
  exporterRemediation(deviceId, action = 'retry', reason = '') { return this.request('/api/shield/exporter-remediation', { method: 'POST', body: { tenant_id: this.tenantId, device_id: deviceId, action, reason }, tenant: false }) }
  integrations() { return this.request('/api/shield/integrations') }
  settings() { return this.request('/api/shield/settings') }
  saveSettings(settings) { return this.request('/api/shield/settings', { method: 'POST', body: { tenant_id: this.tenantId, settings }, tenant: false }) }
  settingsAudit() { return this.request('/api/shield/settings/audit') }
  settingsChangeRequests() { return this.request('/api/shield/settings/change-requests') }
  createSettingsChangeRequest(category, settings, requestedBy = 'tenant-admin') {
    return this.request('/api/shield/settings/change-requests', { method: 'POST', body: { tenant_id: this.tenantId, category, settings, requested_by: requestedBy }, tenant: false })
  }
  decideSettingsChangeRequest(requestId, action, actorId = 'tenant-admin') {
    return this.request(`/api/shield/settings/change-requests/${encodeURIComponent(requestId)}`, { method: 'POST', body: { tenant_id: this.tenantId, action, approver_id: actorId, actor_id: actorId }, tenant: false })
  }
  testAlert(recipient, smtpHost = '', smtpPort = '') {
    return this.request('/api/shield/test-alert', { method: 'POST', body: { tenant_id: this.tenantId, recipient, smtp_host: smtpHost, smtp_port: smtpPort }, tenant: false })
  }
  detectionQuality() { return this.request('/api/shield/detection-quality') }
  detectionQualityReport(bccMiddlewareUrl, oracleUrl = '') { return this.request('/api/shield/detection-quality/report', { method: 'POST', body: { tenant_id: this.tenantId, bcc_middleware_url: bccMiddlewareUrl, oracle_url: oracleUrl }, tenant: false }) }
  opaPolicies() { return this.request('/api/shield/opa/policies') }
  enforcementOutcomes(deviceId = '') { return this.request(`/api/shield/enforcement-outcomes${deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : ''}`) }
  deployPolicy(deviceId, policy) { return this.request(`/api/shield/policies/${encodeURIComponent(this.tenantId)}/${encodeURIComponent(deviceId)}`, { method: 'POST', body: policy, tenant: false }) }
  policyHistory(deviceId) { return this.request(`/api/shield/policy-history?device_id=${encodeURIComponent(deviceId)}`) }
  rollbackPolicy(deviceId, historyId) { return this.request('/api/shield/policy-history/rollback', { method: 'POST', body: { tenant_id: this.tenantId, device_id: deviceId, history_id: historyId }, tenant: false }) }
  enrollDevice(deviceId, deviceRole = 'workstation') { return this.request('/api/shield/enroll', { method: 'POST', body: { tenant_id: this.tenantId, device_id: deviceId, device_role: deviceRole }, tenant: false }) }
  createIntegration(integrationId, kind, config) { return this.request('/api/shield/integrations', { method: 'POST', body: { tenant_id: this.tenantId, integration_id: integrationId, kind, config }, tenant: false }) }
  testIntegration(integrationId) { return this.request('/api/shield/integrations/test', { method: 'POST', body: { tenant_id: this.tenantId, integration_id: integrationId }, tenant: false }) }
  evaluateOpa(policy, input) { return this.request('/api/shield/opa/evaluate', { method: 'POST', body: { tenant_id: this.tenantId, policy, input }, tenant: false }) }
  transactionIntent(deviceId, intent, deviceToken) { return this.request('/api/shield/transaction-intents', { method: 'POST', body: { ...intent, tenant_id: this.tenantId, device_id: deviceId }, tenant: false, token: deviceToken }) }
  transactionSimulation(deviceId, intent, deviceToken) { return this.request('/api/shield/transaction-simulations', { method: 'POST', body: { ...intent, tenant_id: this.tenantId, device_id: deviceId }, tenant: false, token: deviceToken }) }
  createApproval(body) { return this.request('/api/shield/transaction-approvals', { method: 'POST', body: { ...body, tenant_id: this.tenantId }, tenant: false }) }
  consumeApproval(body) { return this.request('/api/shield/transaction-approvals/consume', { method: 'POST', body: { ...body, tenant_id: this.tenantId }, tenant: false }) }
  verifyApproval(deviceId, intentHash, deviceToken) { return this.request('/api/shield/transaction-approvals/verify', { method: 'POST', body: { tenant_id: this.tenantId, device_id: deviceId, intent_hash: intentHash }, tenant: false, token: deviceToken }) }
  issueApproval(body) { return this.request('/api/shield/transaction-approvals', { method: 'POST', body: { ...body, tenant_id: this.tenantId }, tenant: false }) }

  // Backwards-compatible names used by the initial UI.
  getDashboardSummary() { return this.dashboard() }
  getDevices() { return this.devices() }
  getEnforcementOutcomes(deviceId = '') { return this.enforcementOutcomes(deviceId) }
}
