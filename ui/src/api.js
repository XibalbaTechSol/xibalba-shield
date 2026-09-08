export class ShieldApi {
  constructor(baseUrl, tenantId, adminToken) {
    this.baseUrl = String(baseUrl || window.location.origin).replace(/\/+$/, '')
    this.tenantId = String(tenantId || '').trim()
    this.adminToken = String(adminToken || '').trim()
  }

  async request(endpoint, { method = 'GET', body, tenant = true } = {}) {
    const url = new URL(`${this.baseUrl}${endpoint}`)
    if (tenant && this.tenantId) url.searchParams.set('tenant_id', this.tenantId)
    const headers = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (this.adminToken) headers.Authorization = `Bearer ${this.adminToken}`
    const response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(payload.error || payload.message || `${response.status} ${response.statusText}`)
    return payload
  }

  auth(path, input) { return this.request(`/api/shield/auth/${path}`, { method: 'POST', body: input, tenant: false }) }
  switchTenant(email, targetTenantId) { return this.request('/api/shield/auth/switch-tenant', { method: 'POST', body: { email, current_tenant_id: this.tenantId, target_tenant_id: targetTenantId }, tenant: false }) }
  sessions() { return this.request('/api/shield/auth/sessions') }
  authEvents(email = '') { return this.request(`/api/shield/auth/events${email ? `?email=${encodeURIComponent(email)}` : ''}`) }
  changePassword(email, currentPassword, newPassword) { return this.request('/api/shield/auth/password', { method: 'POST', body: { tenant_id: this.tenantId, email, current_password: currentPassword, new_password: newPassword }, tenant: false }) }
  health() { return this.request('/api/shield/health', { tenant: false }) }
  dashboard() { return this.request('/api/shield/dashboard-summary') }
  devices() { return this.request('/api/shield/devices') }
  device(id) { return this.request(`/api/shield/devices/${encodeURIComponent(id)}`) }
  exporterStatus() { return this.request('/api/shield/exporter-status') }
  exporterRemediation(deviceId, action = 'retry', reason = '') { return this.request('/api/shield/exporter-remediation', { method: 'POST', body: { tenant_id: this.tenantId, device_id: deviceId, action, reason }, tenant: false }) }
  integrations() { return this.request('/api/shield/integrations') }
  detectionQuality() { return this.request('/api/shield/detection-quality') }
  testEvents(agentId = '') { return this.request(`/api/shield/test-events${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ''}`) }
  enforcementOutcomes(deviceId = '') { return this.request(`/api/shield/enforcement-outcomes${deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : ''}`) }
  deployPolicy(deviceId, policy) { return this.request(`/api/shield/policies/${encodeURIComponent(this.tenantId)}/${encodeURIComponent(deviceId)}`, { method: 'POST', body: policy, tenant: false }) }
  policyHistory(deviceId) { return this.request(`/api/shield/policy-history?device_id=${encodeURIComponent(deviceId)}`) }
  rollbackPolicy(deviceId, historyId) { return this.request('/api/shield/policy-history/rollback', { method: 'POST', body: { tenant_id: this.tenantId, device_id: deviceId, history_id: historyId }, tenant: false }) }
  enrollDevice(deviceId, deviceRole = 'workstation') { return this.request('/api/shield/enroll', { method: 'POST', body: { tenant_id: this.tenantId, device_id: deviceId, device_role: deviceRole }, tenant: false }) }
  createIntegration(integrationId, kind, config) { return this.request('/api/shield/integrations', { method: 'POST', body: { tenant_id: this.tenantId, integration_id: integrationId, kind, config }, tenant: false }) }
  issueApproval(body) { return this.request('/api/shield/transaction-approvals', { method: 'POST', body: { ...body, tenant_id: this.tenantId }, tenant: false }) }

  // Backwards-compatible names used by the initial UI.
  getDashboardSummary() { return this.dashboard() }
  getDevices() { return this.devices() }
  getEnforcementOutcomes(deviceId = '') { return this.enforcementOutcomes(deviceId) }
}
