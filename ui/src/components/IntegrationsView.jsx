import { useState } from 'react'
import {
  Activity,
  Check,
  CheckCircle2,
  Copy,
  Database,
  Flame,
  Globe,
  Layers,
  Plus,
  Radio,
  Send,
  Shield,
  Terminal,
  X
} from 'lucide-react'

const CATALOG_PROVIDERS = [
  {
    kind: 'splunk',
    name: 'Splunk Enterprise & Cloud',
    badge: 'HEC JSON',
    desc: 'Stream decision logs and containment proofs directly into Splunk HTTP Event Collector with sourcetype xibalba_shield_decision.',
    defaultConfig: {
      hec_url: 'https://splunk.corp.internal:8088/services/collector',
      index: 'security_xibalba',
      sourcetype: 'xibalba_shield_decision',
      severity_filter: 'all',
    },
    samplePayload: {
      time: 1788879500,
      host: 'xibalba-desktop',
      source: 'xibalba:shield:decision',
      sourcetype: 'xibalba_shield_decision',
      event: {
        action: 'contain',
        rule_id: 'process-contain-suspicious',
        severity: 'high',
        process: '/usr/bin/unverified-agent',
        reason: 'Real-time containment: process execution flagged',
        governance_tier: 'tier1',
      },
    },
  },
  {
    kind: 'elastic',
    name: 'Elasticsearch & Elastic Security',
    badge: 'ECS 8.0.0',
    desc: 'Compliant with Elastic Common Schema 8.0.0 for SIEM rule correlation, Kibana dashboards, and fleet alerting.',
    defaultConfig: {
      endpoint: 'https://elastic.corp.internal:9200',
      dataset: 'xibalba_shield.decision',
      index_prefix: 'shield-decisions-',
      severity_filter: 'alerts_only',
    },
    samplePayload: {
      '@timestamp': '2026-09-08T13:52:53.000Z',
      'ecs.version': '8.0.0',
      'event.module': 'xibalba-shield',
      'event.dataset': 'xibalba_shield.decision',
      'event.kind': 'alert',
      'host.name': 'xibalba-desktop',
      'rule.id': 'process-contain-suspicious',
      'process.name': 'unverified-agent',
    },
  },
  {
    kind: 'webhook',
    name: 'Generic SOAR Webhook',
    badge: 'RAW JSON / REST',
    desc: 'Forward raw cryptographic decision objects and receipt hashes to custom SOAR receivers, Cortex, or Torq playbooks.',
    defaultConfig: {
      url: 'https://soar.corp.internal/api/v1/alerts/xibalba-shield',
      secret_header: 'Bearer secops-token-live',
      events: ['contain', 'deny', 'escalate'],
    },
    samplePayload: {
      specversion: '1.0',
      type: 'sh.xibalba.shield.decision',
      source: '/tenant/tenant-a/device/xibalba-desktop',
      data: {
        action: 'contain',
        reason: 'Real-time containment: process execution flagged',
        receipt_hash: 'sha256:d82e4a...',
        governance_tier: 'tier1',
      },
    },
  },
  {
    kind: 'slack',
    name: 'Slack & Teams SecOps Channel',
    badge: 'RICH ALERTS',
    desc: 'Broadcast high-priority process containments, policy blocks, and sensor drops to dedicated incident response channels.',
    defaultConfig: {
      webhook_url: 'https://example.invalid/slack-webhook',
      channel: '#security-containments',
      notify_on: ['contain', 'escalate'],
    },
    samplePayload: {
      text: '🛡️ [SHIELD CONTAINMENT] Autonomous quarantine executed on xibalba-desktop',
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: '*Shield Intercepted High-Risk Workload*\n*Device:* xibalba-desktop\n*Action:* `CONTAIN`\n*Rule:* `process-contain-suspicious`',
          },
        },
      ],
    },
  },
  {
    kind: 'syslog',
    name: 'Syslog / RFC 5424 (CEF)',
    badge: 'TLS STREAM',
    desc: 'Pipe RFC 5424 formatted audit events over encrypted TLS directly to central syslog daemons or air-gapped collectors.',
    defaultConfig: {
      host: 'syslog.corp.internal',
      port: 6514,
      transport: 'tls',
      facility: 'local4',
      format: 'cef',
    },
    samplePayload: {
      cef: 'CEF:0|Xibalba|Shield|1.0|CONTAIN|Autonomous process quarantine|8|src=xibalba-desktop rule=process-contain-suspicious',
    },
  },
]

export function IntegrationsView({ data, api, refresh }) {
  const integrations = data.integrations || []
  const [inspectPayload, setInspectPayload] = useState(null)
  const [copiedId, setCopiedId] = useState(null)
  const [pingStatus, setPingStatus] = useState({})
  const [formOpen, setFormOpen] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [formMessage, setFormMessage] = useState(null)

  // Form states
  const [formId, setFormId] = useState('')
  const [formKind, setFormKind] = useState('splunk')
  const [formUrl, setFormUrl] = useState('https://splunk.corp.internal:8088/services/collector')
  const [formFilter, setFormFilter] = useState('all')

  const copyText = (txt, id) => {
    navigator.clipboard?.writeText?.(txt)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleCatalogConnect = (provider) => {
    setFormKind(provider.kind)
    setFormId(`${provider.kind}-pipeline-${Date.now().toString(36).slice(-4)}`)
    setFormUrl(provider.defaultConfig.hec_url || provider.defaultConfig.endpoint || provider.defaultConfig.url || provider.defaultConfig.webhook_url || `${provider.defaultConfig.host}:${provider.defaultConfig.port}`)
    setFormOpen(true)
    setFormMessage(null)
  }

  const handlePing = async (integrationId) => {
    setPingStatus((prev) => ({ ...prev, [integrationId]: { state: 'sending' } }))
    try {
      const result = await api.testIntegration(integrationId)
      setPingStatus((prev) => ({ ...prev, [integrationId]: { state: result.ok ? 'success' : 'error', status: result.status } }))
    } catch (error) {
      setPingStatus((prev) => ({ ...prev, [integrationId]: { state: 'error', message: error instanceof Error ? error.message : String(error) } }))
    }
  }

  const handleCreate = async (e) => {
    e.preventDefault()
    if (!formId.trim()) return
    setSubmitting(true)
    setFormMessage(null)

    try {
      const config = {
        endpoint_url: formUrl.trim(),
        severity_filter: formFilter,
        created_by: 'operator-console',
      }
      if (formKind === 'splunk') {
        config.sourcetype = 'xibalba_shield_decision'
        config.index = 'security_xibalba'
      } else if (formKind === 'elastic') {
        config.dataset = 'xibalba_shield.decision'
        config.ecs_version = '8.0.0'
      } else if (formKind === 'webhook') {
        config.events = ['contain', 'deny', 'escalate']
      }

      await api.createIntegration(formId.trim(), formKind, config)
      await refresh()
      setFormMessage({ type: 'success', text: `Integration "${formId}" connected successfully.` })
      setTimeout(() => {
        setFormOpen(false)
        setFormMessage(null)
      }, 1200)
    } catch (err) {
      setFormMessage({ type: 'error', text: err instanceof Error ? err.message : String(err) })
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="integrations-view">
      <header className="integrations-command-header">
        <div>
          <h2>SIEM, SOAR & Event Integrations</h2>
          <p>Route Shield telemetry to your security tools and verify delivery from one operational surface.</p>
        </div>
        <button type="button" className="primary-action-btn" onClick={() => handleCatalogConnect(CATALOG_PROVIDERS[0])}>
          <Plus size={15} /> Connect pipeline
        </button>
      </header>

      <section className="signal-routing-map" aria-label="Shield signal routing overview">
        <div className="signal-stack">
          <strong>Xibalba Shield</strong>
          <span><Shield size={15} /> Decisions</span>
          <span><Activity size={15} /> Sensor events</span>
          <span><CheckCircle2 size={15} /> Audit proofs</span>
        </div>
        <div className="signal-paths" aria-hidden="true"><i /><i /><i /></div>
        <div className="signal-center"><Radio size={17} /><strong>Secure event routing</strong><small>Filter · transform · deliver</small></div>
        <div className="signal-paths outbound" aria-hidden="true"><i /><i /><i /></div>
        <div className="signal-stack destinations">
          <strong>Your security tools</strong>
          <span><Database size={15} /> SIEM</span>
          <span><Layers size={15} /> SOAR</span>
          <span><Globe size={15} /> Custom endpoints</span>
        </div>
      </section>

      <div className="pipeline-health-rail" aria-label="Pipeline health">
        <div><Radio size={18} /><span><small>Active pipelines</small><strong>{integrations.length}</strong></span></div>
        <div><Activity size={18} /><span><small>Delivery health</small><strong>{integrations.length ? 'Awaiting test' : 'No data'}</strong></span></div>
        <div><Layers size={18} /><span><small>Queued events</small><strong>—</strong></span></div>
        <div><CheckCircle2 size={18} /><span><small>Last delivery</small><strong>{integrations.length ? 'Not reported' : 'Never'}</strong></span></div>
      </div>

      {/* Active Integrations Section */}
      <section className="integrations-section">
        <div className="section-title-bar">
          <div><h3>Connected pipelines</h3><p className="section-desc">Tenant-scoped destinations receiving authenticated Shield events.</p></div>
        </div>

        {integrations.length === 0 ? (
          <div className="pipeline-table empty">
            <div className="pipeline-table-head"><span>Pipeline</span><span>Destination</span><span>Scope</span><span>Last delivery</span><span>Status</span><span>Actions</span></div>
            <div className="empty-stream-state">
            <Radio size={36} />
            <h4>No pipelines connected</h4>
            <p>Connect a destination to begin routing authenticated Shield events.</p>
            <button
              type="button"
              className="primary-action-btn"
              onClick={() => handleCatalogConnect(CATALOG_PROVIDERS[0])}
            >
              <Plus size={14} />
              <span>Connect pipeline</span>
            </button>
            </div>
          </div>
        ) : (
          <div className="pipeline-table">
            <div className="pipeline-table-head"><span>Pipeline</span><span>Destination</span><span>Scope</span><span>Last delivery</span><span>Status</span><span>Actions</span></div>
            {integrations.map((item) => {
              const kind = item.kind || 'generic'
              const config = item.config || {}
              const endpoint = config.hec_url || config.endpoint || config.url || config.endpoint_url || config.webhook_url || 'Configured via agent daemon'
              const provider = CATALOG_PROVIDERS.find((p) => p.kind === kind)
              const ping = pingStatus[item.integration_id] || {}

              return (
                <article className="pipeline-row" key={item.integration_id}>
                  <span className="pipeline-name"><b>{item.integration_id}</b><small>{kind.toUpperCase()}</small></span>
                  <code title={endpoint}>{endpoint}</code>
                  <span>{config.severity_filter || 'all events'}</span>
                  <span>{item.last_delivery_at || 'Not reported'}</span>
                  <span className="pipeline-status"><i /> Active</span>
                  <div className="pipeline-actions">
                    <button
                      type="button"
                      className="inspect-btn"
                      onClick={() => setInspectPayload(provider?.samplePayload || config)}
                    >
                      <Terminal size={13} />
                      <span>Schema</span>
                    </button>

                    <button
                      type="button"
                      className={`ping-btn ${ping.state === 'success' ? 'success' : ping.state === 'error' ? 'error' : ''}`}
                      onClick={() => handlePing(item.integration_id)}
                      disabled={ping.state === 'sending'}
                      title={ping.message || undefined}
                    >
                      {ping.state === 'sending' ? <><Activity size={13} className="spinning" /><span>Testing…</span></> : ping.state === 'success' ? <><CheckCircle2 size={13} /><span>Delivered ({ping.status})</span></> : ping.state === 'error' ? <><X size={13} /><span>Delivery failed</span></> : <><Send size={13} /><span>Test delivery</span></>}
                    </button>
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>

      {/* Catalog / Quick Connect Section */}
      <section className="integrations-section">
        <div className="section-title-bar">
          <div>
            <h3>Connector catalog</h3>
            <p className="section-desc">Choose a destination, inspect its event shape, then connect it to this tenant.</p>
          </div>
        </div>

        <div className="catalog-grid">
          {CATALOG_PROVIDERS.map((provider) => (
            <article className="catalog-card" key={provider.kind}>
              <div className="catalog-card-header">
                <div className="catalog-title-group">
                  <div className={`catalog-icon-box ${provider.kind}`}>
                    {provider.kind === 'splunk' && <Flame size={20} />}
                    {provider.kind === 'elastic' && <Database size={20} />}
                    {provider.kind === 'webhook' && <Globe size={20} />}
                    {provider.kind === 'slack' && <Radio size={20} />}
                    {provider.kind === 'syslog' && <Terminal size={20} />}
                  </div>
                  <div>
                    <h4>{provider.name}</h4>
                    <span className="protocol-badge">{provider.badge}</span>
                  </div>
                </div>
              </div>

              <p className="catalog-desc">{provider.desc.split('.')[0]}.</p>

              <div className="catalog-actions">
                <button
                  type="button"
                  className="preview-schema-btn"
                  onClick={() => setInspectPayload(provider.samplePayload)}
                >
                  <Terminal size={13} />
                  <span>Sample Payload</span>
                </button>

                <button
                  type="button"
                  className="connect-btn"
                  onClick={() => handleCatalogConnect(provider)}
                >
                  <Plus size={13} />
                  <span>Connect</span>
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* Add / Connect Modal */}
      {formOpen && (
        <div className="modal-backdrop" onClick={() => setFormOpen(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-wrap">
                <Radio size={18} className="pulse-icon" />
                <h3>Connect SIEM / SOAR Pipeline</h3>
              </div>
              <button
                type="button"
                className="close-modal-btn"
                onClick={() => setFormOpen(false)}
                aria-label="Close modal"
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreate} className="integration-form">
              <div className="form-group">
                <label>Integration Identifier</label>
                <input
                  type="text"
                  required
                  value={formId}
                  onChange={(e) => setFormId(e.target.value)}
                  placeholder="e.g. splunk-hec-prod or soar-webhook-primary"
                />
                <span className="field-hint">Unique pipeline name scoped to this tenant.</span>
              </div>

              <div className="form-group">
                <label>Target Ecosystem</label>
                <select
                  value={formKind}
                  onChange={(e) => {
                    const nextKind = e.target.value
                    setFormKind(nextKind)
                    const found = CATALOG_PROVIDERS.find((p) => p.kind === nextKind)
                    if (found) {
                      setFormUrl(found.defaultConfig.hec_url || found.defaultConfig.endpoint || found.defaultConfig.url || found.defaultConfig.webhook_url || '')
                    }
                  }}
                  className="form-select"
                >
                  <option value="splunk">Splunk Enterprise & Cloud (HEC)</option>
                  <option value="elastic">Elasticsearch & Elastic Security (ECS 8.0)</option>
                  <option value="webhook">Generic SOAR Webhook (POST)</option>
                  <option value="slack">Slack / Teams Incident Alerts</option>
                  <option value="syslog">Syslog / RFC 5424 (TLS)</option>
                </select>
              </div>

              <div className="form-group">
                <label>Destination Endpoint / URL</label>
                <input
                  type="text"
                  required
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  placeholder="https://siem-collector.corp:8088/services/collector"
                />
              </div>

              <div className="form-group">
                <label>Event Filter Scope</label>
                <select
                  value={formFilter}
                  onChange={(e) => setFormFilter(e.target.value)}
                  className="form-select"
                >
                  <option value="all">All Events (Telemetry, Benign & Interceptions)</option>
                  <option value="alerts_only">Security Alerts Only (Containment, Denials & Escalations)</option>
                  <option value="contain_only">Containments Only (Autonomous Quarantines)</option>
                </select>
              </div>

              {formMessage && (
                <div className={`form-feedback-alert ${formMessage.type}`}>
                  {formMessage.type === 'success' ? <CheckCircle2 size={16} /> : <X size={16} />}
                  <span>{formMessage.text}</span>
                </div>
              )}

              <div className="modal-actions">
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => setFormOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-btn"
                  disabled={submitting}
                >
                  {submitting ? 'Connecting pipeline…' : 'Connect pipeline'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Payload Schema Inspection Drawer */}
      {inspectPayload && (
        <div className="drawer-backdrop" onClick={() => setInspectPayload(null)}>
          <aside className="evidence-drawer" onClick={(e) => e.stopPropagation()}>
            <header className="evidence-drawer-header">
              <div className="drawer-title-group">
                <Terminal size={18} />
                <h3>SIEM Event Payload Specification</h3>
              </div>
              <button
                type="button"
                className="drawer-close-btn"
                onClick={() => setInspectPayload(null)}
                aria-label="Close schema drawer"
              >
                <X size={18} />
              </button>
            </header>

            <div className="evidence-drawer-content">
              <p className="drawer-subtext">
                Real-time output stream structure forwarded over authenticated TLS for SIEM correlation:
              </p>

              <div className="json-inspector">
                <div className="json-inspector-toolbar">
                  <span>FORMATTED JSON</span>
                  <button
                    type="button"
                    className="copy-chip"
                    onClick={() => copyText(JSON.stringify(inspectPayload, null, 2), 'schema-copy')}
                  >
                    {copiedId === 'schema-copy' ? <Check size={12} /> : <Copy size={12} />}
                    <span>{copiedId === 'schema-copy' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre>{JSON.stringify(inspectPayload, null, 2)}</pre>
              </div>
            </div>
          </aside>
        </div>
      )}
    </div>
  )
}
