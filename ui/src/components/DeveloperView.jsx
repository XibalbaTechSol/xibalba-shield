import { useState, useMemo } from 'react'
import {
  Activity,
  Check,
  Code2,
  Copy,
  Cpu,
  Eye,
  EyeOff,
  FileCode,
  Key,
  Play,
  Shield,
} from 'lucide-react'

const API_ENDPOINTS = [
  {
    id: 'dashboard-summary',
    method: 'GET',
    path: '/api/shield/dashboard-summary',
    category: 'Telemetry',
    description: 'Fetch aggregate telemetry metrics, device counts, event rates, and containment statistics.',
    defaultBody: null,
  },
  {
    id: 'devices',
    method: 'GET',
    path: '/api/shield/devices',
    category: 'Fleet',
    description: 'List enrolled devices, active policy hashes, and last-seen timestamps.',
    defaultBody: null,
  },
  {
    id: 'exporter-status',
    method: 'GET',
    path: '/api/shield/exporter-status',
    category: 'Evidence',
    description: 'Query DID preflight status, sensor connectivity, and export queue depths.',
    defaultBody: null,
  },
  {
    id: 'enforcement-outcomes',
    method: 'GET',
    path: '/api/shield/enforcement-outcomes',
    category: 'Telemetry',
    description: 'Query historical containment attempts, OPA policy denials, and benign verifications.',
    defaultBody: null,
  },
  {
    id: 'integrations',
    method: 'GET',
    path: '/api/shield/integrations',
    category: 'Pipelines',
    description: 'Retrieve configured SIEM/SOAR export adapters and webhook targets.',
    defaultBody: null,
  },
  {
    id: 'policy-history',
    method: 'GET',
    path: '/api/shield/policy-history?device_id=xibalba-desktop',
    category: 'Governance',
    description: 'Query cryptographic policy history and version lineage for a given device.',
    defaultBody: null,
  },
  {
    id: 'detection-quality',
    method: 'GET',
    path: '/api/shield/detection-quality',
    category: 'Telemetry',
    description: 'Retrieve detection quality metrics, precision/recall benchmarks, and sensor loss counts.',
    defaultBody: null,
  },
  {
    id: 'enroll',
    method: 'POST',
    path: '/api/shield/enroll',
    category: 'Fleet',
    description: 'Enroll an endpoint device and provision a tenant-scoped credential bundle.',
    defaultBody: {
      tenant_id: 'tenant-a',
      device_id: 'workstation-dev-02',
      device_role: 'workstation',
    },
  },
  {
    id: 'create-integration',
    method: 'POST',
    path: '/api/shield/integrations',
    category: 'Pipelines',
    description: 'Register a new SIEM HEC, Elasticsearch, or webhook forwarder destination.',
    defaultBody: {
      tenant_id: 'tenant-a',
      integration_id: 'soar-alert-receiver',
      kind: 'webhook',
      config: {
        url: 'https://soar.corp.internal/alerts',
        events: ['contain', 'deny'],
      },
    },
  },
  {
    id: 'mint-admin-token',
    method: 'POST',
    path: '/api/shield/admin-tokens',
    category: 'Auth',
    description: 'Mint a new tenant-scoped cryptographic administrative token.',
    defaultBody: {
      tenant_id: 'tenant-a',
    },
  },
  {
    id: 'exporter-remediation',
    method: 'POST',
    path: '/api/shield/exporter-remediation',
    category: 'Evidence',
    description: 'Dispatch an auditable exporter retry, reconnect, or spool flush task.',
    defaultBody: {
      tenant_id: 'tenant-a',
      device_id: 'xibalba-desktop',
      action: 'retry',
      reason: 'Manual diagnostic verification from Developer Console',
    },
  },
]

export function DeveloperView({ connection }) {
  const [selectedEndpointId, setSelectedEndpointId] = useState('dashboard-summary')
  const [requestBodyText, setRequestBodyText] = useState('')
  const [copiedKey, setCopiedKey] = useState(null)
  const [showToken, setShowToken] = useState(false)
  const [executing, setExecuting] = useState(false)
  const [responseResult, setResponseResult] = useState(null)
  const [activeSnippetTab, setActiveSnippetTab] = useState('curl')

  const selectedEndpoint = useMemo(() => {
    return API_ENDPOINTS.find((ep) => ep.id === selectedEndpointId) || API_ENDPOINTS[0]
  }, [selectedEndpointId])

  // Initialize or update body text when endpoint changes
  const handleSelectEndpoint = (endpointId) => {
    setSelectedEndpointId(endpointId)
    const ep = API_ENDPOINTS.find((x) => x.id === endpointId)
    if (ep?.defaultBody) {
      setRequestBodyText(JSON.stringify(ep.defaultBody, null, 2))
    } else {
      setRequestBodyText('')
    }
    setResponseResult(null)
  }

  const copyToClipboard = (text, key) => {
    navigator.clipboard?.writeText?.(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const handleExecute = async () => {
    setExecuting(true)
    setResponseResult(null)
    const startTime = performance.now()

    try {
      const fullUrl = new URL(`${connection.baseUrl}${selectedEndpoint.path}`)
      if (selectedEndpoint.method === 'GET' && !fullUrl.searchParams.has('tenant_id')) {
        fullUrl.searchParams.set('tenant_id', connection.tenant)
      }

      const headers = {
        Accept: 'application/json',
      }
      if (connection.token) {
        headers.Authorization = `Bearer ${connection.token}`
      }

      let body = undefined
      if (selectedEndpoint.method === 'POST') {
        headers['Content-Type'] = 'application/json'
        body = requestBodyText ? requestBodyText : JSON.stringify(selectedEndpoint.defaultBody || {})
      }

      const res = await fetch(fullUrl.toString(), {
        method: selectedEndpoint.method,
        headers,
        body,
      })

      const latencyMs = Math.round(performance.now() - startTime)
      const data = await res.json().catch(() => ({}))

      setResponseResult({
        status: res.status,
        statusText: res.statusText || (res.ok ? 'OK' : 'Error'),
        ok: res.ok,
        latencyMs,
        data,
      })
    } catch (err) {
      const latencyMs = Math.round(performance.now() - startTime)
      setResponseResult({
        status: 0,
        statusText: 'Network / Fetch Error',
        ok: false,
        latencyMs,
        data: { error: err instanceof Error ? err.message : String(err) },
      })
    } finally {
      setExecuting(false)
    }
  }

  // Generate Snippets
  const snippets = useMemo(() => {
    const isPost = selectedEndpoint.method === 'POST'
    const fullPath = selectedEndpoint.path.includes('?')
      ? `${selectedEndpoint.path}&tenant_id=${connection.tenant}`
      : `${selectedEndpoint.path}?tenant_id=${connection.tenant}`
    const targetUrl = `${connection.baseUrl}${isPost ? selectedEndpoint.path : fullPath}`
    const bodyStr = requestBodyText || JSON.stringify(selectedEndpoint.defaultBody || {}, null, 2)

    return {
      curl: isPost
        ? `curl -X POST "${targetUrl}" \\
  -H "Authorization: Bearer ${connection.token}" \\
  -H "Content-Type: application/json" \\
  -d '${bodyStr.replace(/\n/g, '\n  ')}'`
        : `curl -s -X GET "${targetUrl}" \\
  -H "Authorization: Bearer ${connection.token}" \\
  -H "Accept: application/json"`,

      python: isPost
        ? `import httpx

headers = {
    "Authorization": "Bearer ${connection.token}",
    "Content-Type": "application/json",
}
payload = ${bodyStr}

response = httpx.post("${targetUrl}", headers=headers, json=payload)
print(response.status_code, response.json())`
        : `import httpx

headers = {
    "Authorization": "Bearer ${connection.token}",
    "Accept": "application/json",
}

response = httpx.get("${targetUrl}", headers=headers)
print(response.status_code, response.json())`,

      javascript: isPost
        ? `const response = await fetch("${targetUrl}", {
  method: "POST",
  headers: {
    "Authorization": "Bearer ${connection.token}",
    "Content-Type": "application/json",
  },
  body: JSON.stringify(${bodyStr}),
});
const data = await response.json();
console.log(response.status, data);`
        : `const response = await fetch("${targetUrl}", {
  method: "GET",
  headers: {
    "Authorization": "Bearer ${connection.token}",
    "Accept": "application/json",
  },
});
const data = await response.json();
console.log(response.status, data);`,

      golang: isPost
        ? `package main

import (
    "bytes"
    "fmt"
    "net/http"
    "io"
)

func main() {
    body := []byte(\`${bodyStr}\`)
    req, _ := http.NewRequest("POST", "${targetUrl}", bytes.NewBuffer(body))
    req.Header.Set("Authorization", "Bearer ${connection.token}")
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil { panic(err) }
    defer resp.Body.Close()
    respBody, _ := io.ReadAll(resp.Body)
    fmt.Println(resp.Status, string(respBody))
}`
        : `package main

import (
    "fmt"
    "net/http"
    "io"
)

func main() {
    req, _ := http.NewRequest("GET", "${targetUrl}", nil)
    req.Header.Set("Authorization", "Bearer ${connection.token}")
    req.Header.Set("Accept", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil { panic(err) }
    defer resp.Body.Close()
    respBody, _ := io.ReadAll(resp.Body)
    fmt.Println(resp.Status, string(respBody))
}`,
    }
  }, [selectedEndpoint, connection, requestBodyText])

  return (
    <div className="developer-view">
      {/* Header */}
      <header className="view-header">
        <div className="eyebrow-badge">
          <Code2 size={13} className="pulse-icon" />
          <span>AUTHENTICATED API SURFACE</span>
        </div>
        <h2>Developer Contract & API Explorer</h2>
        <span>
          Test live control plane endpoints, inspect schemas, generate client code, and review cryptographic contracts.
        </span>
        <small className="evidence-label">
          Evidence class: authenticated local control-plane data; synthetic/demo records are labeled explicitly.
        </small>
      </header>

      {/* Connection & Auth Banner */}
      <div className="dev-auth-card">
        <div className="dev-auth-header">
          <div className="dev-auth-title">
            <Key size={16} />
            <h4>Active Client Session</h4>
          </div>
          <span className="auth-badge authenticated">Authenticated</span>
        </div>

        <div className="dev-auth-grid">
          <div className="auth-prop">
            <span className="auth-prop-label">CONTROL PLANE ENDPOINT</span>
            <code>{connection.baseUrl}</code>
          </div>

          <div className="auth-prop">
            <span className="auth-prop-label">ACTIVE TENANT</span>
            <code>{connection.tenant}</code>
          </div>

          <div className="auth-prop token-prop">
            <span className="auth-prop-label">AUTHORIZATION HEADER</span>
            <div className="token-field">
              <code>
                Bearer {showToken ? connection.token : '••••••••••••••••••••••••••••••••'}
              </code>
              <button
                type="button"
                className="icon-chip-btn"
                onClick={() => setShowToken(!showToken)}
                title={showToken ? 'Hide token' : 'Show token'}
              >
                {showToken ? <EyeOff size={13} /> : <Eye size={13} />}
              </button>
              <button
                type="button"
                className="icon-chip-btn"
                onClick={() => copyToClipboard(connection.token, 'token-copy')}
                title="Copy token"
              >
                {copiedKey === 'token-copy' ? <Check size={13} /> : <Copy size={13} />}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive API Explorer */}
      <div className="api-explorer-layout">
        {/* Endpoint Selector Sidebar */}
        <aside className="api-endpoints-nav">
          <div className="nav-group-title">REST ENDPOINTS</div>
          {API_ENDPOINTS.map((ep) => {
            const isSelected = ep.id === selectedEndpointId
            return (
              <button
                key={ep.id}
                type="button"
                className={`endpoint-nav-item ${isSelected ? 'active' : ''}`}
                onClick={() => handleSelectEndpoint(ep.id)}
              >
                <span className={`method-badge ${ep.method.toLowerCase()}`}>{ep.method}</span>
                <span className="endpoint-name">{ep.path.split('?')[0].replace('/api/shield/', '')}</span>
              </button>
            )
          })}
        </aside>

        {/* Console / Request Executor */}
        <div className="api-console-main">
          <div className="api-endpoint-header">
            <div className="endpoint-route-bar">
              <span className={`method-badge large ${selectedEndpoint.method.toLowerCase()}`}>
                {selectedEndpoint.method}
              </span>
              <code className="endpoint-path">{selectedEndpoint.path}</code>
            </div>

            <button
              type="button"
              className="execute-btn"
              onClick={handleExecute}
              disabled={executing}
            >
              {executing ? (
                <>
                  <Activity size={14} className="spinning" />
                  <span>Executing…</span>
                </>
              ) : (
                <>
                  <Play size={14} />
                  <span>Execute Request</span>
                </>
              )}
            </button>
          </div>

          <p className="endpoint-description">{selectedEndpoint.description}</p>

          {/* Request Body (For POST) */}
          {selectedEndpoint.method === 'POST' && (
            <div className="request-body-section">
              <div className="body-header">
                <span>REQUEST PAYLOAD (JSON)</span>
                <button
                  type="button"
                  className="copy-chip"
                  onClick={() => copyToClipboard(requestBodyText, 'body-copy')}
                >
                  {copiedKey === 'body-copy' ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copiedKey === 'body-copy' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <textarea
                className="body-editor"
                rows={6}
                value={requestBodyText}
                onChange={(e) => setRequestBodyText(e.target.value)}
                placeholder="JSON request body..."
              />
            </div>
          )}

          {/* Response Inspector */}
          {responseResult && (
            <div className="response-pane">
              <div className="response-status-bar">
                <div className="status-indicator">
                  <span className={`status-code-pill ${responseResult.ok ? 'ok' : 'error'}`}>
                    {responseResult.status} {responseResult.statusText}
                  </span>
                  <span className="latency-pill">{responseResult.latencyMs} ms</span>
                </div>
                <button
                  type="button"
                  className="copy-chip"
                  onClick={() =>
                    copyToClipboard(JSON.stringify(responseResult.data, null, 2), 'response-copy')
                  }
                >
                  {copiedKey === 'response-copy' ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copiedKey === 'response-copy' ? 'Copied' : 'Copy Response'}</span>
                </button>
              </div>

              <div className="response-json-box">
                <pre>{JSON.stringify(responseResult.data, null, 2)}</pre>
              </div>
            </div>
          )}

          {/* Code Snippets Section */}
          <div className="code-snippets-section">
            <div className="snippet-tabs">
              {['curl', 'python', 'javascript', 'golang'].map((tab) => (
                <button
                  key={tab}
                  type="button"
                  className={`snippet-tab-btn ${activeSnippetTab === tab ? 'active' : ''}`}
                  onClick={() => setActiveSnippetTab(tab)}
                >
                  {tab === 'curl' && 'cURL'}
                  {tab === 'python' && 'Python (httpx)'}
                  {tab === 'javascript' && 'JavaScript'}
                  {tab === 'golang' && 'Go'}
                </button>
              ))}

              <button
                type="button"
                className="copy-snippet-btn"
                onClick={() => copyToClipboard(snippets[activeSnippetTab], 'snippet-copy')}
              >
                {copiedKey === 'snippet-copy' ? <Check size={12} /> : <Copy size={12} />}
                <span>{copiedKey === 'snippet-copy' ? 'Copied' : 'Copy Code'}</span>
              </button>
            </div>

            <div className="snippet-body">
              <pre>{snippets[activeSnippetTab]}</pre>
            </div>
          </div>
        </div>
      </div>

      {/* Architectural Security Contracts */}
      <section className="contracts-section">
        <h3>Shield Security Architecture & Verification Contracts</h3>
        <p className="section-desc">
          Core primitives underpinning our zero-trust endpoint interceptor and autonomous reasoning engine.
        </p>

        <div className="contracts-grid">
          <article className="contract-card">
            <div className="contract-icon-box blue">
              <Shield size={20} />
            </div>
            <h4>Cryptographic Policy Bundles</h4>
            <p>
              Signed OPA Rego policies compiled into immutable SHA-256 hash chains. Every decision is cryptographically evaluated against a published hash, ensuring zero unauthorized policy drift.
            </p>
            <code>Bundle Header: sha256:b5a83d0c...</code>
          </article>

          <article className="contract-card">
            <div className="contract-icon-box green">
              <Cpu size={20} />
            </div>
            <h4>Kernel-Level eBPF Telemetry</h4>
            <p>
              Ring-buffer monitored kernel probes attached to <code>sys_enter_execve</code>, process clones, and raw socket creation. Autonomous containment executes via SIGKILL before unauthorized socket binds occur.
            </p>
            <code>Probe: tracepoint/syscalls/sys_enter_execve</code>
          </article>

          <article className="contract-card">
            <div className="contract-icon-box purple">
              <FileCode size={20} />
            </div>
            <h4>W3C DID Audit Receipts</h4>
            <p>
              Decentralized Identifier (DID:key) cryptographic attestations generated for each intercepted event. Receipts are written to append-only tamper-evident logs and forwarded to enterprise SIEMs.
            </p>
            <code>DID Proof: did:key:z6Mkq5...</code>
          </article>
        </div>
      </section>
    </div>
  )
}
