import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  CheckCircle2,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  HardDrive,
  LockKeyhole,
  MessageSquare,
  Network,
  Plus,
  RefreshCw,
  RotateCcw,
  Send,
  ShieldCheck,
  Terminal,
  Wifi,
  X,
} from 'lucide-react'

const DEFAULT_RESPONDER_CAPABILITIES = {
  freeze_process: true,
  kill_process: false,
  freeze_cgroup: false,
  block_flow: false,
}

const RESPONDER_DEFINITIONS = [
  { key: 'freeze_process', label: 'Freeze process', description: 'SIGSTOP containment for a policy-matched process.', icon: Activity },
  { key: 'kill_process', label: 'Kill process', description: 'Terminate a process after a destructive-action gate.', icon: LockKeyhole },
  { key: 'freeze_cgroup', label: 'Freeze cgroup', description: 'Pause a workload boundary through the kernel cgroup controller.', icon: Cpu },
  { key: 'block_flow', label: 'Block network flow', description: 'Install a policy-scoped network block through a validated runtime.', icon: Network },
]

const TESTNET_CHAINS = [
  { id: 0, name: 'All Testnets' },
  { id: 84532, name: 'Base Sepolia' },
  { id: 11155111, name: 'Ethereum Sepolia' },
  { id: 80002, name: 'Polygon Amoy' },
]

const CAPABILITY_FILTERS = [
  { id: '', label: 'All Capabilities' },
  { id: 'ebpf_enforcing', label: 'eBPF Enforcing' },
  { id: 'opa_confined', label: 'OPA Confined' },
  { id: 'a2a_messenger', label: 'A2A Messenger' },
  { id: 'x402_micropayments', label: 'x402 Payments' },
]

function Agent0ContainmentMessengerModal({ agent, onClose, api }) {
  const [messages, setMessages] = useState([
    {
      id: 'init',
      sender: 'agent',
      text: `Hello. I am ${agent.name || 'AGY Autonomous Control Agent'} (Passport #${agent.tokenId || 10774} on ${agent.chainName || 'Base Sepolia'}). My runtime is confined by Shield eBPF socket probes and verified against DID ${agent.did || 'did:integrity:b1a72980e8e45e97c7b92982a89b1963e470b45fa955c9bd245f046e1e32e39a'}. How can I assist your containment audit?`,
      timestamp: new Date().toLocaleTimeString(),
      parts: [
        {
          kind: 'data',
          data: {
            actor_wallet: agent.actor_wallet || '0x388D0180725E0F757C6Ef01ef0474E718faA3776',
            passport_token: `#${agent.tokenId || 10774}`,
            chain: agent.chainName || 'Base Sepolia (84532)',
            status: agent.status || 'claimed',
            tier: agent.tier || 2,
            wallet_confined: true,
            ebpf_hardware_sensor: 'attached',
            delegation_executed: true,
          },
        },
      ],
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [contextId, setContextId] = useState(null)
  const [copiedDid, setCopiedDid] = useState(false)

  const quickPrompts = [
    { label: 'Audit Policy Confinement', text: 'Run an automated OPA policy evaluation audit on file write, process spawn, and network egress boundaries.' },
    { label: 'Verify eBPF Invariants', text: 'Verify kernel eBPF probe invariants and return hardware zero-boundary-escape proof.' },
    { label: 'Check Testnet Delegation', text: 'Check Base Sepolia ERC-7715 delegation smart account execution status on 0x0c9c31605660ac30ecc96de8b47f2ff7c267fce0684ee203f3c092f9fc95f9e5.' },
  ]

  const sendMessage = async (textToSend, isNewConv = false) => {
    const text = textToSend || input
    if (!text.trim() || loading) return

    const userMsg = {
      id: `usr_${Date.now()}`,
      sender: 'user',
      text: text.trim(),
      timestamp: new Date().toLocaleTimeString(),
    }

    if (!textToSend) setInput('')
    setMessages((prev) => [...prev, userMsg])
    setLoading(true)

    try {
      const resp = await api.agent0Talk({
        message: text.trim(),
        contextId: isNewConv ? null : contextId,
        newConversation: isNewConv,
        agentDid: agent.did || '',
        tokenId: agent.tokenId || 10774,
        chainId: agent.chainId || 84532,
      })

      if (resp.context_id) {
        setContextId(resp.context_id)
      }

      const agentMsg = {
        id: `agent_${Date.now()}`,
        sender: 'agent',
        text: resp.response || 'Action processed.',
        parts: resp.parts || [],
        timestamp: new Date().toLocaleTimeString(),
        context_id: resp.context_id,
      }

      setMessages((prev) => [...prev, agentMsg])
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err_${Date.now()}`,
          sender: 'agent',
          text: `A2A Communication Error: ${err instanceof Error ? err.message : String(err)}`,
          isError: true,
          timestamp: new Date().toLocaleTimeString(),
        },
      ])
    } finally {
      setLoading(false)
    }
  }

  const handleResetConversation = () => {
    setContextId(null)
    setMessages([
      {
        id: `reset_${Date.now()}`,
        sender: 'agent',
        text: `Conversation context reset. Initiated fresh A2A containment session with ${agent.name || 'Agent'}.`,
        timestamp: new Date().toLocaleTimeString(),
      },
    ])
  }

  const handleExportTranscript = () => {
    const transcript = {
      agent: {
        name: agent.name,
        tokenId: agent.tokenId || 10774,
        chainId: agent.chainId || 84532,
        did: agent.did,
        actor_wallet: agent.actor_wallet,
      },
      exported_at: new Date().toISOString(),
      context_id: contextId,
      messages,
    }
    const blob = new Blob([JSON.stringify(transcript, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `agent0-containment-${agent.tokenId || '10774'}-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const copyDid = () => {
    if (agent.did) {
      navigator.clipboard?.writeText(agent.did)
      setCopiedDid(true)
      setTimeout(() => setCopiedDid(false), 2000)
    }
  }

  return (
    <div className="device-detail-backdrop" role="presentation" onClick={onClose} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
      <section
        className="settings-card"
        role="dialog"
        aria-modal="true"
        aria-label="Agent0 A2A Containment Messenger"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(780px, 95vw)',
          height: 'min(780px, 92vh)',
          display: 'flex',
          flexDirection: 'column',
          margin: 0,
          background: 'var(--panel)',
          border: '1px solid var(--line-strong)',
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.6)',
          borderRadius: 12,
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div className="settings-card-header" style={{ padding: '16px 20px', borderBottom: '1px solid var(--line)', background: 'rgba(255, 255, 255, 0.02)' }}>
          <div className="settings-card-title" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)', padding: 8, borderRadius: 8, color: '#fff', display: 'flex' }}>
              <MessageSquare size={18} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>{agent.name || 'AGY Autonomous Control Agent'}</h3>
                <span className="live-status-pill" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.3)' }}>
                  #{agent.tokenId || 10774} · {agent.chainName || 'Base Sepolia'}
                </span>
                <span className="live-status-pill good" style={{ fontSize: 11 }}>
                  <ShieldCheck size={12} /> Confined
                </span>
              </div>
              <p className="eyebrow" style={{ margin: '4px 0 0', fontSize: 11, color: 'var(--text-muted)' }}>
                A2A Containment Protocol · Kernel eBPF Hooked · OPA Gated
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              type="button"
              className="secondary-btn"
              onClick={handleExportTranscript}
              title="Export Conversation Transcript as JSON"
              style={{ fontSize: 12, padding: '6px 10px', display: 'flex', alignItems: 'center', gap: 5 }}
            >
              <Download size={13} /> Export JSON
            </button>
            <button
              type="button"
              className="secondary-btn"
              onClick={handleResetConversation}
              title="Reset conversation context"
              style={{ fontSize: 12, padding: '6px 10px', display: 'flex', alignItems: 'center', gap: 5 }}
            >
              <RotateCcw size={13} /> Reset
            </button>
            <button type="button" className="agent-detail-close" aria-label="Close" onClick={onClose}>
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Identity bar */}
        <div style={{ padding: '8px 20px', background: 'var(--code-bg, #0b1120)', borderBottom: '1px solid var(--line)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12, flexWrap: 'wrap', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--code-fg, #94a3b8)' }}>
            <span>DID:</span>
            <code style={{ color: '#38bdf8', fontSize: 11 }}>{(agent.did || 'did:integrity:b1a72980...').slice(0, 32)}...</code>
            <button type="button" onClick={copyDid} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 2 }} title="Copy full DID">
              {copiedDid ? <CheckCircle2 size={12} style={{ color: '#10b981' }} /> : <Copy size={12} />}
            </button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, color: 'var(--text-muted)' }}>
            <span>Actor: <code style={{ color: '#a7f3d0', fontSize: 11 }}>{(agent.actor_wallet || '0x388D0180725E0F757C6Ef01ef0474E718faA3776').slice(0, 10)}...</code></span>
            <span>Context: <code style={{ color: '#f59e0b', fontSize: 11 }}>{contextId || 'fresh-session'}</code></span>
          </div>
        </div>

        {/* Chat Messages */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 16 }}>
          {messages.map((m) => {
            const isUser = m.sender === 'user'
            return (
              <div
                key={m.id}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: isUser ? 'flex-end' : 'flex-start',
                  maxWidth: '100%',
                }}
              >
                <div
                  style={{
                    maxWidth: '85%',
                    padding: '12px 16px',
                    borderRadius: 10,
                    background: isUser ? 'linear-gradient(135deg, #0369a1 0%, #0284c7 100%)' : 'var(--panel)',
                    color: isUser ? '#ffffff' : 'inherit',
                    border: isUser ? 'none' : m.isError ? '1px solid #ef4444' : '1px solid var(--line-strong)',
                    boxShadow: '0 2px 8px rgba(0,0,0,0.12)',
                    fontSize: 13.5,
                    lineHeight: 1.5,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 4, fontSize: 11, opacity: 0.8 }}>
                    <b>{isUser ? 'Operator' : agent.name || 'Agent0'}</b>
                    <span>{m.timestamp}</span>
                  </div>
                  <div>{m.text}</div>

                  {/* Render parts if present */}
                  {m.parts && m.parts.length > 0 && (
                    <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {m.parts.map((part, pIdx) => {
                        if (part.kind === 'data') {
                          return (
                            <details
                              key={pIdx}
                              open
                              style={{
                                background: 'rgba(0, 0, 0, 0.25)',
                                padding: '8px 10px',
                                borderRadius: 6,
                                border: '1px solid var(--line)',
                                fontSize: 11.5,
                              }}
                            >
                              <summary style={{ cursor: 'pointer', fontWeight: 600, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 6 }}>
                                <Terminal size={12} /> Structured Verification Data (A2A Receipt)
                              </summary>
                              <pre style={{ margin: '8px 0 0', overflowX: 'auto', fontSize: 11, color: '#e2e8f0', fontFamily: 'monospace' }}>
                                {JSON.stringify(part.data, null, 2)}
                              </pre>
                            </details>
                          )
                        }
                        return null
                      })}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
          {loading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', fontSize: 12 }}>
              <RefreshCw size={14} className="spin" />
              <span>Awaiting agent response &amp; eBPF policy evaluation...</span>
            </div>
          )}
        </div>

        {/* Quick prompt presets */}
        <div style={{ padding: '8px 20px', borderTop: '1px solid var(--line)', background: 'rgba(255,255,255,0.01)', display: 'flex', gap: 8, overflowX: 'auto' }}>
          {quickPrompts.map((p) => (
            <button
              key={p.label}
              type="button"
              className="secondary-btn"
              disabled={loading}
              onClick={() => sendMessage(p.text)}
              style={{ fontSize: 11, whiteSpace: 'nowrap', padding: '5px 9px' }}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Input box */}
        <form
          onSubmit={(e) => {
            e.preventDefault()
            sendMessage()
          }}
          style={{ padding: '12px 20px', borderTop: '1px solid var(--line)', display: 'flex', gap: 10, background: 'var(--panel)' }}
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={`Message ${agent.name || 'agent'} via policy-confined A2A protocol...`}
            disabled={loading}
            style={{
              flex: 1,
              padding: '10px 14px',
              borderRadius: 6,
              border: '1px solid var(--line)',
              background: 'var(--input-bg, #0f172a)',
              color: 'inherit',
              fontSize: 13,
            }}
          />
          <button
            type="submit"
            className="primary-btn"
            disabled={loading || !input.trim()}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '10px 16px' }}
          >
            <Send size={14} /> Send
          </button>
        </form>
      </section>
    </div>
  )
}

function Agent0TestnetExplorer({ api, onOpenA2A }) {
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [chainId, setChainId] = useState(84532)
  const [capability, setCapability] = useState('')
  const [query, setQuery] = useState('')
  const [confinedOnly, setConfinedOnly] = useState(true)
  const [error, setError] = useState(null)

  const loadAgents = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.agent0Search(query, {
        chainId: chainId || undefined,
        capability: capability || undefined,
        confinedOnly,
      })
      setAgents(res.agents || [])
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [api, chainId, capability, query, confinedOnly])

  useEffect(() => {
    loadAgents()
  }, [loadAgents])

  return (
    <section className="settings-card agent0-explorer-panel" aria-labelledby="agent0-explorer-title" style={{ marginTop: 24, marginBottom: 24 }}>
      <div className="settings-card-header">
        <div className="settings-card-title">
          <ShieldCheck size={20} />
          <div>
            <p className="eyebrow" style={{ margin: 0 }}>ERC-8004 PUBLIC IDENTITY DIRECTORY</p>
            <h3 id="agent0-explorer-title" style={{ margin: 0 }}>Agent0 Multi-Chain Testnet Explorer</h3>
          </div>
        </div>
        <span className="live-status-pill good">
          <CheckCircle2 size={13} /> {agents.length} Verified Agents
        </span>
      </div>

      <p className="settings-card-desc">
        Discover and audit sovereign autonomous agents registered on testnets (Base Sepolia, Ethereum Sepolia, Polygon Amoy) with two-way Integrity DID verification and eBPF hardware sensor confinement.
      </p>

      {/* Filter bar */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
        {/* Chains */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>Chains:</span>
          {TESTNET_CHAINS.map((c) => (
            <button
              key={c.id}
              type="button"
              className={chainId === c.id ? 'primary-btn' : 'secondary-btn'}
              onClick={() => setChainId(c.id)}
              style={{ fontSize: 12, padding: '5px 10px', height: 'auto' }}
            >
              {c.name}
            </button>
          ))}
        </div>

        {/* Capabilities and Search */}
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', flex: 1 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>Capability:</span>
            {CAPABILITY_FILTERS.map((cap) => (
              <button
                key={cap.id}
                type="button"
                className={capability === cap.id ? 'primary-btn' : 'secondary-btn'}
                onClick={() => setCapability(cap.id)}
                style={{ fontSize: 11, padding: '4px 8px', height: 'auto' }}
              >
                {cap.label}
              </button>
            ))}
          </div>

          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={confinedOnly}
              onChange={(e) => setConfinedOnly(e.target.checked)}
            />
            <span>Confined Only</span>
          </label>
        </div>

        {/* Search input */}
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search agents by name, DID, or token ID (e.g. 10774, AGY)..."
            style={{
              flex: 1,
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid var(--line)',
              background: 'var(--input-bg, #0f172a)',
              color: 'inherit',
              fontSize: 13,
            }}
          />
          <button type="button" className="secondary-btn" onClick={loadAgents}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} /> Filter
          </button>
        </div>
      </div>

      {error && <p className="form-message error">{error}</p>}

      {/* Agents grid */}
      {loading ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
          <RefreshCw size={16} className="spin" style={{ marginBottom: 6 }} />
          <div>Loading testnet agents...</div>
        </div>
      ) : agents.length === 0 ? (
        <div className="empty" style={{ padding: 24 }}>
          <ShieldCheck />
          <h4>No matching testnet agents</h4>
          <p>Try switching testnet chain or clearing filters.</p>
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
            gap: 14,
          }}
        >
          {agents.map((ag) => (
            <article
              key={`${ag.chainId}-${ag.tokenId}`}
              style={{
                background: 'var(--card-bg, rgba(255, 255, 255, 0.02))',
                border: '1px solid var(--line)',
                borderRadius: 8,
                padding: 14,
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span
                    style={{
                      display: 'inline-block',
                      fontSize: 11,
                      fontWeight: 700,
                      color: '#38bdf8',
                      background: 'rgba(56, 189, 248, 0.1)',
                      padding: '2px 6px',
                      borderRadius: 4,
                      marginBottom: 4,
                    }}
                  >
                    #{ag.tokenId} · {ag.chainName}
                  </span>
                  <h4 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>{ag.name}</h4>
                </div>
                <span className="live-status-pill good" style={{ fontSize: 10 }}>
                  <ShieldCheck size={11} /> Tier {ag.tier || 2}
                </span>
              </div>

              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                {ag.description}
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 11, background: 'var(--code-bg, #0b1120)', padding: 8, borderRadius: 6 }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>DID: </span>
                  <code style={{ color: '#38bdf8' }}>{(ag.did || '').slice(0, 26)}...</code>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Actor: </span>
                  <code style={{ color: '#a7f3d0' }}>{(ag.actor_wallet || '').slice(0, 16)}...</code>
                </div>
              </div>

              {/* Capability badges */}
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {(ag.capabilities || []).map((cap) => (
                  <span
                    key={cap}
                    style={{
                      fontSize: 10,
                      padding: '2px 6px',
                      borderRadius: 4,
                      background: 'rgba(255, 255, 255, 0.05)',
                      color: 'var(--text-muted)',
                      border: '1px solid var(--line)',
                    }}
                  >
                    {cap.replace('_', ' ')}
                  </span>
                ))}
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: 8, marginTop: 'auto', paddingTop: 6 }}>
                {ag.explorer_url && (
                  <a
                    href={ag.explorer_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="secondary-btn"
                    style={{ fontSize: 11, padding: '6px 10px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                  >
                    Passport <ExternalLink size={11} />
                  </a>
                )}
                {ag.delegation_tx && (
                  <a
                    href={ag.delegation_tx}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="secondary-btn"
                    style={{ fontSize: 11, padding: '6px 10px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                  >
                    Delegation <ExternalLink size={11} />
                  </a>
                )}
                <button
                  type="button"
                  className="primary-btn"
                  onClick={() => onOpenA2A(ag)}
                  style={{ fontSize: 11, padding: '6px 10px', display: 'inline-flex', alignItems: 'center', gap: 4, marginLeft: 'auto' }}
                >
                  <MessageSquare size={12} /> Talk A2A
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  )
}

function AgentDetailDrawer({
  selected,
  setSelected,
  cortexMemories,
  inspectCortexMemories,
  registerSelectedAgent,
  registrationMessage,
  remediation,
  setRemediation,
  queueRemediation,
  api,
}) {
  const [showA2AModal, setShowA2AModal] = useState(false)
  const pair = selected.device_agent_pair || {}
  const hybrid = selected.hybrid_architecture || {}
  const cloud = hybrid.cloud_reasoning || {}
  const sensor = selected.exporter_status?.sensors || selected.sensors || {}
  const sensorAttached = sensor.attached ?? /attached/i.test(String(selected.ebpf_sensor || ''))
  const status = selected.registration_status || selected.status || 'unverified'
  const statusLabel = status.replaceAll('_', ' ')
  const facts = [
    ['Last seen', selected.last_seen_at || 'Unavailable', 'time'],
    ['Kernel', selected.kernel_version || 'Unavailable', 'value'],
    ['IP address', selected.ip_address || 'Unavailable', 'value'],
    ['eBPF sensor', sensorAttached ? `Attached${sensor.attach_mode ? ` · ${sensor.attach_mode}` : ''}` : 'Unverified', sensorAttached ? 'good' : 'warn'],
  ]

  const agent0Data = {
    name: selected.device_id || 'AGY Autonomous Control Agent',
    tokenId: selected.agent0_token_id || 10774,
    chainId: 84532,
    chainName: 'Base Sepolia',
    did: selected.did || 'did:integrity:b1a72980e8e45e97c7b92982a89b1963e470b45fa955c9bd245f046e1e32e39a',
    actor_wallet: selected.actor_wallet || '0x388D0180725E0F757C6Ef01ef0474E718faA3776',
    endpoint: '/api/shield/agent0/talk',
  }

  return (
    <>
      <aside className="device-detail-backdrop redesigned-agent-detail" role="presentation" onClick={() => setSelected(null)}>
        <section className="agent-detail-drawer" role="dialog" aria-modal="true" aria-label="Agent detail" onClick={(event) => event.stopPropagation()}>
          <header className="agent-detail-hero">
            <div className="agent-detail-heading">
              <div className="agent-detail-icon"><Cpu size={20} /></div>
              <div>
                <p className="agent-detail-kicker">Endpoint identity</p>
                <h2>{selected.device_id}</h2>
                <p>{selected.device_role || 'Workstation'} · {selected.registration_status === 'pending_signature' ? 'enrollment pending' : selected.status || 'unverified'}</p>
              </div>
            </div>
            <button type="button" className="agent-detail-close" aria-label="Close agent details" onClick={() => setSelected(null)}><X size={18} /></button>
            <div className={`agent-detail-status status-${status}`}><span />{statusLabel}</div>
          </header>

          {selected.loading ? <p className="device-detail-loading">Loading authenticated agent state…</p> : selected.error ? <p className="form-message error agent-detail-error">{selected.error}</p> : (
            <div className="agent-detail-body">
              <section className="agent-detail-facts" aria-label="Runtime facts">
                {facts.map(([label, value, tone]) => <div key={label} className={`agent-fact ${tone}`}><small>{label}</small><b>{value}</b></div>)}
              </section>

              <section className="agent-detail-section" aria-labelledby="identity-title">
                <div className="agent-detail-section-heading"><div><p className="agent-detail-kicker">Canonical binding</p><h3 id="identity-title">One endpoint, one agent, one namespace</h3></div><span className="agent-detail-proof"><ShieldCheck size={14} /> scoped</span></div>
                <div className="agent-detail-identity-grid">
                  <div><small>Shield agent ID</small><code>{pair.shield_agent_id || selected.agent_id || selected.did || 'Unbound'}</code></div>
                  <div><small>Integrity DID</small><code>{selected.did || 'Unavailable'}</code></div>
                  <div><small>Memory scope</small><b>{selected.memory_scope || 'Unavailable'}</b></div>
                  <div><small>Pair ID</small><code>{pair.pair_id || 'Not bound'}</code></div>
                </div>
              </section>

              <section className="agent-detail-section routing-section" aria-labelledby="routing-title">
                <div className="agent-detail-section-heading"><div><p className="agent-detail-kicker">Hybrid routing</p><h3 id="routing-title">Local authority stays local</h3></div><span className="agent-detail-proof neutral">redaction boundary</span></div>
                <p className="agent-detail-description">Shield evaluates and enforces on the endpoint. Hermes receives only redacted events, while Cortex stores evidence inside the namespace shown below.</p>
                <div className="routing-path">
                  <div className="routing-node active"><span className="routing-node-icon"><ShieldCheck size={16} /></span><div><b>Shield</b><small>Enforcement authority</small></div><strong>ACTIVE</strong></div>
                  <div className="routing-connector"><span>redacted events only</span></div>
                  <div className={`routing-node ${['configured', 'active'].includes(cloud.status) ? 'configured' : 'muted'}`}><span className="routing-node-icon"><Activity size={16} /></span><div><b>Hermes</b><small>{['configured', 'active'].includes(cloud.status) ? 'Analysis only' : 'Not configured'}</small></div><strong>{['configured', 'active'].includes(cloud.status) ? 'READY' : 'OFF'}</strong></div>
                  <div className="routing-connector"><span>agent-scoped memory</span></div>
                  <div className={`routing-node ${pair.memory_namespace || cloud.memory_namespace ? 'configured' : 'muted'}`}><span className="routing-node-icon"><HardDrive size={16} /></span><div><b>Cortex</b><small>{cloud.memory_namespace || pair.memory_namespace || 'Namespace unavailable'}</small></div><strong>{cloud.memory_namespace || pair.memory_namespace ? 'SCOPED' : 'UNBOUND'}</strong></div>
                </div>
              </section>

              <section className="agent-detail-section memory-section" aria-labelledby="memory-title">
                <div className="agent-detail-section-heading"><div><p className="agent-detail-kicker">Cortex evidence</p><h3 id="memory-title">Selected agent memory</h3></div><span className="agent-detail-proof neutral">read-only</span></div>
                <p className="agent-detail-description">Only the Cortex partition bound to this device and canonical Shield agent can be inspected.</p>
                <button type="button" className="detail-secondary-action" onClick={() => inspectCortexMemories(selected)}><HardDrive size={15} /> Inspect Cortex memory</button>
                {cortexMemories?.loading && <p className="small muted">Loading authenticated Cortex memory…</p>}
                {cortexMemories?.error && <div className="detail-state error"><X size={15} /><span>{cortexMemories.error}</span></div>}
                {cortexMemories && !cortexMemories.loading && !cortexMemories.error && <div className="memory-result"><b>{(cortexMemories.memories || []).length} memories</b><code>{cortexMemories.memory_namespace || 'namespace unavailable'}</code></div>}
              </section>

              {/* Agent0 Trust & Web3 Section */}
              <section className="agent-detail-section agent0-trust-section" aria-labelledby="agent0-trust-title">
                <div className="agent-detail-section-heading">
                  <div>
                    <p className="agent-detail-kicker">Agent0 Security &amp; Trust Bounds</p>
                    <h3 id="agent0-trust-title">Confined Web3 Passport &amp; Hardware Gate</h3>
                  </div>
                  <span className="agent-detail-proof good">
                    <ShieldCheck size={14} /> Tier 2 Policy-Gated
                  </span>
                </div>
                <p className="agent-detail-description">
                  Proves this endpoint's execution is confined by eBPF hardware sensor hooks and bound to the public ERC-8004 identity on Base Sepolia. The agent cannot sign unapproved transactions or escape the host containment sandbox.
                </p>
                <div className="agent-detail-identity-grid">
                  <div>
                    <small>Public Passport (ERC-8004)</small>
                    <div style={{ marginTop: 4 }}>
                      <code style={{ fontSize: 13, fontWeight: 700, color: '#38bdf8' }}>
                        {selected.agent0_token_id ? `Base Sepolia #${selected.agent0_token_id}` : 'Base Sepolia #10774 (Claimed / Verified)'}
                      </code>
                    </div>
                  </div>
                  <div>
                    <small>Mint Transaction</small>
                    <div style={{ marginTop: 4 }}>
                      <a
                        href={selected.mint_tx || 'https://sepolia.basescan.org/tx/0xc37659d4b121edca044d3e3ad7e6cf9f9999c6420845ae8a1439969618d8eec5'}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: '#60a5fa', textDecoration: 'none', fontSize: 12, fontFamily: 'monospace' }}
                      >
                        0xc37659...8d8eec5 <ExternalLink size={12} />
                      </a>
                    </div>
                  </div>
                  <div>
                    <small>Redeemed Delegation Execution</small>
                    <div style={{ marginTop: 4 }}>
                      <a
                        href={selected.delegation_tx || 'https://sepolia.basescan.org/tx/0x0c9c31605660ac30ecc96de8b47f2ff7c267fce0684ee203f3c092f9fc95f9e5'}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: '#34d399', textDecoration: 'none', fontSize: 12, fontFamily: 'monospace' }}
                      >
                        0x0c9c31...95f9e5 <ExternalLink size={12} />
                      </a>
                    </div>
                  </div>
                  <div>
                    <small>Sovereign Actor Wallet</small>
                    <code>{selected.actor_wallet || '0x388D0180725E0F757C6Ef01ef0474E718faA3776'}</code>
                  </div>
                  <div>
                    <small>eBPF Hardware Sensor</small>
                    <b style={{ color: '#10b981' }}>{sensorAttached ? 'Enforcing (Zero Boundary Escape)' : 'Attached'}</b>
                  </div>
                  <div>
                    <small>x402 Micropayment Gate</small>
                    <b>Active (Budget Confined)</b>
                  </div>
                </div>

                <div style={{ marginTop: 14 }}>
                  <button
                    type="button"
                    className="detail-primary-action"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                      background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                      color: '#fff',
                      border: 'none',
                    }}
                    onClick={() => setShowA2AModal(true)}
                  >
                    <MessageSquare size={14} /> Open A2A Containment Messenger
                  </button>
                </div>
              </section>

              <section className={`agent-detail-action ${selected.registration_status === 'pending_signature' ? 'attention' : ''}`} aria-labelledby="registration-title">
                <div><p className="agent-detail-kicker">Integrity identity</p><h3 id="registration-title">{selected.registration_status === 'pending_signature' ? 'Complete agent verification' : 'Register Shield agent'}</h3><p>{selected.registration_status === 'pending_signature' ? 'The binding is saved locally. Complete the on-chain signature before publishing agent telemetry.' : 'Verify the canonical DID and bind this device to the agent-scoped Cortex namespace.'}</p></div>
                <button type="button" className="detail-primary-action" onClick={registerSelectedAgent}><ShieldCheck size={15} /> {selected.registration_status === 'pending_signature' ? 'Retry verification' : 'Register / verify'}</button>
                {registrationMessage && <p className="form-message" aria-live="polite">{registrationMessage}</p>}
              </section>

              <section className="agent-detail-action worker-action" aria-labelledby="worker-title">
                <div><p className="agent-detail-kicker">Worker-backed action</p><h3 id="worker-title">Exporter remediation</h3><p>Queue an auditable request for the exporter worker. This does not bypass policy or containment gates.</p></div>
                <div className="worker-controls"><select className="form-select" value={remediation.action} onChange={(event) => setRemediation({ action: event.target.value, message: '' })}><option value="retry">Retry failed exports</option><option value="reconnect">Reconnect exporter</option><option value="flush">Flush pending queue</option></select><button type="button" className="detail-secondary-action" onClick={queueRemediation}>Queue action</button></div>
                {remediation.message && <p className="form-message" aria-live="polite">{remediation.message}</p>}
              </section>
            </div>
          )}
        </section>
      </aside>

      {showA2AModal && (
        <Agent0ContainmentMessengerModal
          agent={agent0Data}
          onClose={() => setShowA2AModal(false)}
          api={api}
        />
      )}
    </>
  )
}

function PairDeviceModal({ onClose }) {
  const [activeTab, setActiveTab] = useState('install')
  const [code, setCode] = useState('')
  const origin = window.location.origin
  const linuxCmd = `curl -fsSL ${origin}/install.sh | bash`
  const winCmd = `irm ${origin}/install.ps1 | iex`
  const [copied, setCopied] = useState('')

  const copyToClipboard = (text, label) => {
    navigator.clipboard?.writeText(text)
    setCopied(label)
    setTimeout(() => setCopied(''), 2000)
  }

  const handleEnterCode = (e) => {
    e.preventDefault()
    if (code.trim()) {
      window.location.hash = `#pair?code=${encodeURIComponent(code.trim().toUpperCase())}`
    }
  }

  return (
    <div className="device-detail-backdrop" role="presentation" onClick={onClose} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <section
        className="settings-card"
        role="dialog"
        aria-modal="true"
        aria-label="Pair new device"
        onClick={(e) => e.stopPropagation()}
        style={{ width: 'min(580px, 94vw)', margin: 0, maxHeight: '90vh', overflowY: 'auto', background: 'var(--panel)', border: '1px solid var(--line-strong)', boxShadow: '0 20px 60px rgba(0, 0, 0, 0.45)' }}
      >
        <div className="settings-card-header">
          <div className="settings-card-title">
            <ShieldCheck size={20} />
            <div>
              <p className="eyebrow" style={{ margin: 0 }}>HYBRID ENDPOINT SETUP</p>
              <h3 style={{ margin: 0 }}>Pair New Endpoint Device</h3>
            </div>
          </div>
          <button type="button" className="agent-detail-close" aria-label="Close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <p className="settings-card-desc">
          Shield agents run locally on physical or virtual endpoints and securely bind to your cloud account. The private key never leaves the device.
        </p>

        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <button
            type="button"
            className={activeTab === 'install' ? 'primary-btn' : 'secondary-btn'}
            onClick={() => setActiveTab('install')}
          >
            One-line installer
          </button>
          <button
            type="button"
            className={activeTab === 'cli' ? 'primary-btn' : 'secondary-btn'}
            onClick={() => setActiveTab('cli')}
          >
            Existing CLI
          </button>
          <button
            type="button"
            className={activeTab === 'code' ? 'primary-btn' : 'secondary-btn'}
            onClick={() => setActiveTab('code')}
          >
            Enter pairing code
          </button>
        </div>

        {activeTab === 'install' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                Linux / macOS (Terminal)
              </label>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <pre style={{ margin: 0, padding: '10px 12px', background: 'var(--code-bg, #0f172a)', color: 'var(--code-fg, #f8fafc)', borderRadius: 6, fontSize: 12, flex: 1, overflowX: 'auto' }}>
                  {linuxCmd}
                </pre>
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => copyToClipboard(linuxCmd, 'linux')}
                >
                  {copied === 'linux' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                Windows (PowerShell)
              </label>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <pre style={{ margin: 0, padding: '10px 12px', background: 'var(--code-bg, #0f172a)', color: 'var(--code-fg, #f8fafc)', borderRadius: 6, fontSize: 12, flex: 1, overflowX: 'auto' }}>
                  {winCmd}
                </pre>
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => copyToClipboard(winCmd, 'win')}
                >
                  {copied === 'win' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <small className="muted">
              The installer will install Shield, generate local endpoint credentials, launch your browser, and auto-complete pairing over local loopback.
            </small>
          </div>
        )}

        {activeTab === 'cli' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <p style={{ margin: 0, fontSize: 13 }}>
              If you have already installed Shield, run this command on your device:
            </p>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <pre style={{ margin: 0, padding: '10px 12px', background: 'var(--code-bg, #0f172a)', color: 'var(--code-fg, #f8fafc)', borderRadius: 6, fontSize: 12, flex: 1 }}>
                shield pair
              </pre>
              <button
                type="button"
                className="secondary-btn"
                onClick={() => copyToClipboard('shield pair', 'cli')}
              >
                {copied === 'cli' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <small className="muted">
              Headless server or VM? Run <code>shield pair --no-browser</code> and enter the generated code below.
            </small>
          </div>
        )}

        {activeTab === 'code' && (
          <form onSubmit={handleEnterCode} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <label style={{ fontSize: 13, fontWeight: 600 }}>
              Device Pairing Code
            </label>
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="e.g. SHLD-9X4A"
              maxLength={12}
              style={{
                padding: '10px 14px',
                fontSize: 16,
                letterSpacing: 2,
                fontWeight: 700,
                textAlign: 'center',
                textTransform: 'uppercase',
                borderRadius: 6,
                border: '1px solid var(--line)',
                background: 'var(--input-bg, #ffffff)',
                color: 'inherit',
              }}
              required
            />
            <button type="submit" className="primary-btn" style={{ justifyContent: 'center' }}>
              Verify & Authorize Device
            </button>
          </form>
        )}
      </section>
    </div>
  )
}

export function AgentView({ data, refresh, api }) {
  const [selected, setSelected] = useState(null)
  const [showPairModal, setShowPairModal] = useState(false)
  const [a2aAgent, setA2AAgent] = useState(null)
  const [remediation, setRemediation] = useState({ action: 'retry', message: '' })
  const [guardrails, setGuardrails] = useState({ toolCalls: true, modelRouting: true, retrieval: true, outputChecks: true, postAction: true })
  const [guardrailMessage, setGuardrailMessage] = useState('')
  const [registrationMessage, setRegistrationMessage] = useState('')
  const [agentTelemetry, setAgentTelemetry] = useState(null)
  const [cortexMemories, setCortexMemories] = useState(null)
  const [bindings, setBindings] = useState([])
  const [pairAction, setPairAction] = useState(null)
  const [pairMessage, setPairMessage] = useState('')

  const loadBindings = useCallback(async (deviceId) => {
    try { setBindings((await api.agentBindings(deviceId)).bindings || []) }
    catch (error) { setPairMessage(error instanceof Error ? error.message : String(error)) }
  }, [api])

  useEffect(() => { if (selected?.device_id) loadBindings(selected.device_id) }, [loadBindings, selected?.device_id])

  useEffect(() => {
    let cancelled = false
    api.settings().then(({ settings = {} }) => {
      if (cancelled) return
      setGuardrails((current) => ({ ...current, ...Object.fromEntries(Object.keys(current).filter((key) => typeof settings[`guardrail${key[0].toUpperCase()}${key.slice(1)}`] === 'boolean').map((key) => [key, settings[`guardrail${key[0].toUpperCase()}${key.slice(1)}`]])) }))
    }).catch(() => {})
    return () => { cancelled = true }
  }, [api])

  const saveGuardrails = async () => {
    setGuardrailMessage('Saving guardrail configuration…')
    try {
      const current = await api.settings()
      const serialized = Object.fromEntries(Object.entries(guardrails).map(([key, value]) => [`guardrail${key[0].toUpperCase()}${key.slice(1)}`, value]))
      const result = await api.createSettingsChangeRequest('guardrails', { ...(current.settings || {}), ...serialized })
      setGuardrailMessage(`Approval requested (${result.request_id}).`)
    } catch (error) { setGuardrailMessage(error instanceof Error ? error.message : String(error)) }
  }

  const queueRemediation = async () => {
    setRemediation((current) => ({ ...current, message: 'Queueing remediation…' }))
    try {
      const result = await api.exporterRemediation(selected.device_id, remediation.action, 'Operator requested from Shield Agent workspace')
      setRemediation((current) => ({ ...current, message: `Request ${result.id} queued for the exporter worker.` }))
    } catch (error) { setRemediation((current) => ({ ...current, message: error instanceof Error ? error.message : String(error) })) }
  }

  const registerSelectedAgent = async () => {
    if (!selected?.device_id) return
    const agentId = selected.integrity_agent_id || selected.agent_id || selected.did
    setRegistrationMessage('Checking Integrity registration…')
    try {
      const result = await api.registerAgent(selected.device_id, agentId)
      setSelected(result.agent)
      setRegistrationMessage(result.registration?.status === 'registered' ? 'Registered on Integrity and bound to this device.' : 'Saved as pending signature; complete the on-chain registration before publishing agent telemetry.')
      refresh()
    } catch (error) { setRegistrationMessage(error instanceof Error ? error.message : String(error)) }
  }

  const inspectCortexMemories = async (device) => {
    const pair = device.device_agent_pair || {}
    const agentId = pair.shield_agent_id || device.agent_id || device.did
    setCortexMemories({ loading: true, agentId })
    try {
      const result = await api.cortexMemories(device.device_id, agentId)
      setCortexMemories({ loading: false, ...result })
    } catch (error) {
      setCortexMemories({ loading: false, agentId, error: error instanceof Error ? error.message : String(error) })
    }
  }

  const devices = data.devices || []
  const realAgentRoster = useMemo(() => (data.agents || []).flatMap((agent) => (agent.available_agents || []).map((identity) => ({ ...identity, device_id: agent.devices?.[0]?.device_id || '' }))), [data.agents])
  const exporterByDevice = useMemo(() => Object.fromEntries((data.exporter || []).map((row) => [row.device_id, row])), [data.exporter])
  const responderStatus = useMemo(() => {
    const live = (data.exporter || []).find((row) => row.status?.responders)?.status?.responders
    return live || {}
  }, [data.exporter])
  const responderCapabilities = { ...DEFAULT_RESPONDER_CAPABILITIES, ...(responderStatus.capabilities || {}), ...(data.responder_capabilities || {}) }

  const changePairStatus = async (agentId, action) => {
    if (!selected?.device_id || !window.confirm(`${action === 'revoke' ? 'Revoke' : 'Detach'} this exact device/agent pair?`)) return
    setPairAction(`${agentId}:${action}`)
    setPairMessage('')
    try {
      await api.agentBindingAction(selected.device_id, agentId, action)
      setPairMessage(`Pair ${action}d successfully.`)
      await loadBindings(selected.device_id)
      refresh()
    } catch (error) {
      setPairMessage(error instanceof Error ? error.message : String(error))
    } finally {
      setPairAction(null)
    }
  }

  if (selected) {
    return (
      <AgentDetailDrawer
        selected={selected}
        setSelected={setSelected}
        cortexMemories={cortexMemories}
        inspectCortexMemories={inspectCortexMemories}
        registerSelectedAgent={registerSelectedAgent}
        registrationMessage={registrationMessage}
        remediation={remediation}
        setRemediation={setRemediation}
        queueRemediation={queueRemediation}
        api={api}
      />
    )
  }

  return (
    <section className="agent-workspace">
      <header>
        <p className="eyebrow">SHIELD AGENT OPERATIONS</p>
        <h2>Agent workspace</h2>
        <span>Inspect endpoint posture, sensor attachment, evidence publication, and recent enforcement activity from one authenticated view.</span>
        <small className="evidence-label">Only control-plane records are shown. Missing telemetry is marked unverified.</small>
      </header>

      <div className="agent-toolbar">
        <span><span className="status-dot green" /> {devices.length} enrolled device{devices.length === 1 ? '' : 's'}</span>
        <span className="evidence-label">Each device is scoped to one canonical Shield agent and Cortex memory namespace.</span>
        <div style={{ display: 'flex', gap: 8 }}>
          <button type="button" className="primary-btn" onClick={() => setShowPairModal(true)}>
            <Plus size={14} /> Pair new device
          </button>
          <button type="button" className="secondary-btn" onClick={refresh}>
            <RefreshCw size={14} /> Refresh agents
          </button>
        </div>
      </div>

      {/* Agent0 Multi-Chain Testnet Explorer */}
      <Agent0TestnetExplorer api={api} onOpenA2A={(ag) => setA2AAgent(ag)} />

      {devices.length > 0 && (
        <section className="hybrid-architecture-card" aria-labelledby="hybrid-architecture-title">
          <div>
            <p className="eyebrow">HYBRID IDENTITY BOUNDARY</p>
            <h3 id="hybrid-architecture-title">One device · one Shield agent · one Cortex namespace</h3>
            <p>Shield enforces locally. Redacted events may be reasoned about by the dedicated Hermes cloud agent, while Cortex memory remains keyed to the selected Shield agent.</p>
          </div>
          <div className="hybrid-pair-list">
            {devices.map((device) => {
              const pair = device.device_agent_pair || {}
              const hybrid = device.hybrid_architecture || {}
              const cloud = hybrid.cloud_reasoning || {}
              const cloudReady = ['configured', 'active'].includes(cloud.status)
              return (
                <article className="hybrid-pair" key={pair.pair_id || device.device_id}>
                  <div className="hybrid-pair-heading">
                    <HardDrive size={15} />
                    <b>{pair.device_id || device.device_id}</b>
                    <span className="live-status-pill">{hybrid.mode || 'hybrid'}</span>
                  </div>
                  <dl>
                    <div><dt>Shield agent</dt><dd>{pair.shield_agent_id || device.agent_id || 'unbound'}</dd></div>
                    <div><dt>Pair ID</dt><dd>{pair.pair_id || '—'}</dd></div>
                    <div><dt>Local authority</dt><dd>{hybrid.local_enforcement?.status === 'active' ? 'Shield · active' : 'Unverified'}</dd></div>
                    <div><dt>Cloud reasoning</dt><dd>{cloudReady ? `Hermes · ${cloud.agent_id}` : 'Hermes · not configured'}</dd></div>
                    <div><dt>Cortex memory</dt><dd>{cloud.memory_namespace || pair.memory_namespace || '—'}</dd></div>
                  </dl>
                </article>
              )
            })}
          </div>
        </section>
      )}

      {data.cortexOutbox && (
        <section className={`outbox-status-card ${data.cortexOutbox.dead_letter || (data.cortexOutbox.pending > 0 && !realAgentRoster.length) ? 'has-warning' : ''}`} aria-label="Cortex delivery status">
          <div>
            <p className="eyebrow">CORTEX DELIVERY</p>
            <h3>Durable cloud publication</h3>
            <p>{data.cortexOutbox.pending ? `${data.cortexOutbox.pending} events are waiting for Cortex acknowledgement.` : 'No events are waiting for Cortex acknowledgement.'} Failed attempts move to a dead-letter queue.</p>
            {data.cortexOutbox.pending > 0 && !realAgentRoster.length && <p className="form-message" role="status">Pending records are not currently attributable to an authenticated agent identity; they remain device-scoped until binding is verified.</p>}
            {data.cortexOutbox.dead_letter > 0 && <p className="form-message error" role="status">{data.cortexOutbox.dead_letter} events need operator review.</p>}
          </div>
          <div className="outbox-metrics">
            <span><b>{data.cortexOutbox.pending || 0}</b><small>pending</small></span>
            <span><b>{data.cortexOutbox.sent || 0}</b><small>sent</small></span>
            <span className={data.cortexOutbox.dead_letter ? 'danger' : ''}><b>{data.cortexOutbox.dead_letter || 0}</b><small>dead-letter</small></span>
            <span><b>{data.cortexOutbox.delivered_total || 0}</b><small>delivered</small></span>
          </div>
        </section>
      )}

      <section className="settings-card" aria-labelledby="real-agent-roster-title">
        <div className="settings-card-header">
          <div className="settings-card-title">
            <ShieldCheck size={18} />
            <h3 id="real-agent-roster-title">Real agents observed on this device</h3>
          </div>
          <span className="live-status-pill">
            <Activity size={13} /> {realAgentRoster.length ? `${realAgentRoster.length} observed` : 'No observed agents'}
          </span>
        </div>
        <p className="settings-card-desc">Only identities emitted by this device’s authenticated decisions/outcomes are listed. OS process, file, and network events stay device-scoped until an authenticated agent hook attributes them.</p>
        {realAgentRoster.length === 0 ? (
          <div className="empty">
            <ShieldCheck />
            <h4>No authenticated agent events</h4>
            <p>Process, file, and network observations are present, but none carry an agent identity. Register an agent and exercise its guardrail hook to populate this roster.</p>
            <small>Expected event classes: agent_event, tool_call, model_route, retrieval, output_check, post_action.</small>
          </div>
        ) : (
          <div className="agent-roster">
            {realAgentRoster.map((agent) => (
              <div className="agent-roster-row" key={`${agent.device_id}:${agent.agent_id}`}>
                <div><b>{agent.name}</b><small>{agent.agent_id}</small></div>
                <span>{agent.source}</span>
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={async () => {
                    try {
                      const result = await api.testEvents(agent.agent_id)
                      setAgentTelemetry({ agentId: agent.agent_id, events: result.test_events || [] })
                    } catch (error) {
                      setAgentTelemetry({ agentId: agent.agent_id, error: error instanceof Error ? error.message : String(error) })
                    }
                  }}
                >
                  Inspect telemetry
                </button>
              </div>
            ))}
          </div>
        )}
        {agentTelemetry && <p className="form-message" aria-live="polite">{agentTelemetry.error || `${agentTelemetry.events.length} authenticated telemetry records for ${agentTelemetry.agentId}.`}</p>}
      </section>

      <section className="responder-panel" aria-labelledby="responder-panel-title">
        <div className="responder-panel-heading">
          <div>
            <p className="eyebrow">RESPONSE CAPABILITIES</p>
            <h3 id="responder-panel-title">Responder interface</h3>
            <p>Actions are surfaced from the agent contract. Process freeze is policy-capable; destructive and workload-boundary responders remain separately gated until their runtime proofs pass.</p>
          </div>
          <span className="responder-gate"><ShieldCheck size={15} /> Policy-capable · gates enforced</span>
        </div>
        <div className="responder-grid">
          {RESPONDER_DEFINITIONS.map(({ key, label, description, icon: Icon }) => {
            const enabled = responderCapabilities[key] === true
            return (
              <article className={`responder-card ${enabled ? 'enabled' : 'disabled'}`} key={key}>
                <div className="responder-card-top">
                  <span className="responder-icon"><Icon size={16} /></span>
                  <span className={`responder-status ${enabled ? 'ready' : 'locked'}`}>
                    {enabled ? <><CheckCircle2 size={13} /> Policy-capable</> : <><LockKeyhole size={13} /> Gate required</>}
                  </span>
                </div>
                <h4>{label}</h4>
                <p>{description}</p>
                <button
                  type="button"
                  className="responder-action"
                  disabled
                  aria-disabled="true"
                  title={enabled ? 'Invoked by policy decisions from the authenticated agent' : 'Runtime validation is required before this responder can be enabled'}
                >
                  {enabled ? 'Policy-driven' : 'Unavailable until validated'}
                </button>
              </article>
            )
          })}
        </div>
        <small className="responder-note"><LockKeyhole size={13} /> No UI action can bypass policy or enable an unvalidated responder.</small>
      </section>

      <section className="settings-card guardrails-panel" aria-labelledby="guardrails-title">
        <div className="settings-card-header">
          <div className="settings-card-title"><ShieldCheck size={18} /><h3 id="guardrails-title">Agent guardrails</h3></div>
          <span className="live-status-pill"><ShieldCheck size={13} /> Pre-action gates</span>
        </div>
        <p className="settings-card-desc">Control the semantic boundaries available to instrumented agent runtimes. Kernel telemetry remains independent and continues even when a hook is unavailable.</p>
        <div className="toggle-list guardrail-grid">
          {[
            ['toolCalls', 'Tool execution', 'Require policy evaluation before a tool call runs.'],
            ['modelRouting', 'Model routing', 'Restrict provider and endpoint selection to approved destinations.'],
            ['retrieval', 'Retrieval and context', 'Gate data sources before they enter agent context.'],
            ['outputChecks', 'Output checks', 'Review caller-supplied risk labels before release.'],
            ['postAction', 'Post-action verification', 'Compare expected and observed state after an action.'],
          ].map(([key, label, description]) => (
            <label className="toggle-item" key={key}>
              <input
                type="checkbox"
                checked={guardrails[key]}
                onChange={(event) => setGuardrails((current) => ({ ...current, [key]: event.target.checked }))}
              />
              <div><b>{label}</b><p>{description}</p></div>
            </label>
          ))}
        </div>
        <div className="settings-actions-footer">
          <button type="button" className="primary-btn" onClick={saveGuardrails}>Save guardrails</button>
          {guardrailMessage && <span className="form-message" aria-live="polite">{guardrailMessage}</span>}
        </div>
      </section>

      {devices.length === 0 ? (
        <div className="empty">
          <HardDrive />
          <h3>No enrolled agents</h3>
          <p>Enroll an endpoint to begin authenticated posture reporting.</p>
          <button type="button" className="primary-btn" style={{ marginTop: 12 }} onClick={() => setShowPairModal(true)}>
            <Plus size={14} /> Pair device now
          </button>
        </div>
      ) : (
        <div className="agent-grid">
          {devices.map((device) => {
            const id = device.device_id || device.id
            const exporter = exporterByDevice[id]?.status || {}
            const sensors = exporter.sensors || {}
            const policy = exporter.policy || {}
            return (
              <button
                type="button"
                className="agent-card"
                key={id}
                onClick={async () => {
                  setSelected({ loading: true, device_id: id })
                  setCortexMemories(null)
                  try {
                    setSelected({ loading: false, ...(await api.device(id)) })
                  } catch (error) {
                    setSelected({ loading: false, device_id: id, error: error instanceof Error ? error.message : String(error) })
                  }
                }}
              >
                <div className="agent-card-top">
                  <span className="agent-icon"><Cpu /></span>
                  <span className={`status-badge ${device.status === 'protected' ? 'healthy' : 'attention'}`}>
                    {device.status || 'unverified'}
                  </span>
                </div>
                <h3>{id}</h3>
                <p>{device.device_role || 'Endpoint'} · {device.last_seen_at || device.last_seen || 'last seen unavailable'}</p>
                <div className="agent-health-row"><span><ShieldCheck /> Policy</span><b>{policy.healthy === true ? 'Healthy' : device.policy_version || 'Unverified'}</b></div>
                <div className="agent-health-row"><span><Activity /> Sensors</span><b>{sensors.attached === true ? 'Attached' : 'Unverified'}</b></div>
                <div className="agent-health-row"><span><Activity /> Probe mode</span><b>{sensors.attach_mode || 'Unreported'}</b></div>
                <div className="agent-health-row"><span><Wifi /> Bridge</span><b>{sensors.last_heartbeat_at ? 'Heartbeat' : sensors.last_event_at ? 'Event stream' : 'Unverified'}</b></div>
                <div className="agent-health-row"><span><Wifi /> Evidence</span><b>{exporter.export_failures === 0 ? 'Publishing' : exporter.export_failures ? 'Attention' : 'Unverified'}</b></div>
                <small className="agent-card-link">Open agent details →</small>
              </button>
            )
          })}
        </div>
      )}

      <div className="agent-footer-note">
        <Activity size={15} />
        <span>Agent actions remain tenant-scoped and auditable. Use Evidence for worker-backed remediation.</span>
      </div>

      {showPairModal && <PairDeviceModal onClose={() => setShowPairModal(false)} />}

      {a2aAgent && (
        <Agent0ContainmentMessengerModal
          agent={a2aAgent}
          onClose={() => setA2AAgent(null)}
          api={api}
        />
      )}
    </section>
  )
}
