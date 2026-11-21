import { useState } from 'react'
import {
  Activity,
  ArrowRight,
  Check,
  Copy,
  Cpu,
  Crosshair,
  Download,
  ExternalLink,
  FileCheck2,
  Fingerprint,
  Globe,
  Layers,
  LockKeyhole,
  Mail,
  MapPin,
  Phone,
  Radar,
  RotateCcw,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  Sliders,
  SquareTerminal,
  Terminal,
  Workflow,
} from 'lucide-react'
import { Brand } from './Brand'
import { MermaidDiagram } from './MermaidDiagram'

const CONTROL_LOOP_FLOW = `flowchart LR
  SP["Signed pack<br/>setpoint · constraint vector C"] --> SUM(("Σ"))
  SUM --> HK["Hook<br/>evaluates C on post-state"]
  HK -->|admit / revert<br/>fail-closed| AG["Agent & Workload<br/>the plant"]
  AG -->|"what actually happened"| SH["🛡️ Shield Endpoint Defense<br/><b>The Plant Sensor & Enforcer</b><br/>kernel procfs · eBPF · EDR · nftables"]
  SH -->|"evidence spans"| OR["Oracle<br/>verify · epoch · anchor"]
  OR -->|"verified state estimate"| SUM
  OR -->|"verified"| AIS["AIS<br/>bounded gain"]
  AIS -.->|"widen finite bound"| SP
  AG -->|"settle"| CH["Chain<br/>anchors · settlement"]
  SH -.->|"anchorRoot"| CH`

const DECISION_FLOW = `flowchart LR
  A["Kernel & EDR Telemetry<br/>procfs · eBPF · Falcon"] --> B["Normalize & Enrich<br/>correlation tags · hash binding"]
  B --> C{"Response Gateway<br/>deterministic gate"}
  C -->|allow| D["Endpoint Execution<br/>SIGSTOP · cgroup · nftables"]
  C -->|escalate| G["Operator Queue<br/>two-person sign-off"]
  G -->|approved| D
  C -->|deny| H["Terminal Block<br/>fail-closed drop"]
  D --> F["Integrity Receipt<br/>Ed25519 hash-chained ledger"]
  F -.->|"evidence anchor"| P["Integrity Protocol"]`

const RESPONSE_FLOW = `flowchart LR
  A["Response Intent"] --> E{"Cryptographic Gate<br/>RFC 8628 DID & policy"}
  B["Actor DID & Role"] --> E
  C["Policy Hash Bundle"] --> E
  D["Two-Person Sign-off"] --> E
  E -->|allow / approved| F["Atomic Consume"]
  E -->|deny / expired| G["Fail Closed"]
  F --> H["EDR: Contain Host"]
  F --> I["EDR: Kill Process"]
  F --> J["OS: cgroup freeze & nftables"]`

const AGENT_FLOW = `flowchart LR
  A["Agent Intent<br/>tool call / model action"] --> B["Cryptographic Boundary<br/>DID verification"]
  B --> C["Deterministic Policy<br/>geometric traversal checks"]
  C --> D["Response Intent Gateway"]
  D --> E["EDR & Kernel Execution<br/>procfs · eBPF · host"]
  E --> F["Post-Action Verification<br/>state differential audit"]
  F --> G["Attested Evidence Chain<br/>hash-linked ledger"]
  H["Signed Tenant Policy"] -.->|"governs"| B
  H -.->|"governs"| D
  I["Sensors & EDR Connectors"] -.->|"observes"| E`

const INSTALL_OPTIONS = [
  {
    id: 'daemon',
    label: 'Linux Daemon',
    icon: Server,
    desc: 'Deploy the hardened systemd service with automatic service account isolation, capability bounding (CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN), and local Ed25519 identity generation.',
    cmd: 'curl -sSL https://raw.githubusercontent.com/XibalbaTechSol/xibalba-shield/main/scripts/install_linux_agent.sh | sudo bash',
    verify: 'sudo systemctl status xibalba-shield --no-pager',
    details: 'Installs binary to /opt/xibalba-shield, configs to /etc/xibalba-shield, and loads local OPA policy bundles.'
  },
  {
    id: 'cli',
    label: 'Python Package / CLI',
    icon: Terminal,
    desc: 'Install directly into your Python 3.12+ environment or uv virtualenv. Ideal for local developer workstations, AI agent host sandboxes, and offline testing.',
    cmd: 'pip install xibalba-shield\nshield run --sensor process-exec --local',
    verify: 'shield status',
    details: 'Runs procfs & socket monitoring loop, evaluates deterministic policies, and writes hash-chained logs to ~/.xibalba-shield/.'
  },
  {
    id: 'pair',
    label: 'Zero-Trust Device Pairing',
    icon: Cpu,
    desc: 'Pair an endpoint device with your Shield console using RFC 8628 Device Authorization. Binds local host hardware keys and Ed25519 DID to tenant policy.',
    cmd: 'shield pair --tenant <tenant-id>',
    verify: 'shield verify-log',
    details: 'Generates user code & URL, binds device DID, and synchronizes signed OPA Rego policy bundles.'
  },
  {
    id: 'docker',
    label: 'Container / Edge Node',
    icon: Layers,
    desc: 'Deploy as an isolated containerized agent mounting host procfs and network namespaces for continuous container and host monitoring.',
    cmd: 'docker run -d --name xibalba-shield \\\n  --privileged \\\n  --net=host \\\n  -v /proc:/host/proc:ro \\\n  -v /etc/xibalba-shield:/etc/xibalba-shield:ro \\\n  ghcr.io/xibalbatechsol/xibalba-shield:latest',
    verify: 'docker logs xibalba-shield --tail 20',
    details: 'Inspects host TCP sockets and process trees without requiring kernel headers or custom driver compilation.'
  }
]

export function Landing({ next }) {
  const [activeInstallTab, setActiveInstallTab] = useState('daemon')
  const [copied, setCopied] = useState(false)

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const activeInstall = INSTALL_OPTIONS.find((opt) => opt.id === activeInstallTab) || INSTALL_OPTIONS[0]

  return (
    <main className="landing">
      <header className="site-header">
        <nav className="site-nav" aria-label="Main Navigation">
          <a className="brand-link" href="#top" aria-label="Xibalba Shield home"><Brand /></a>
          <div className="nav-links">
            <a href="#platform">Platform</a>
            <a href="#loop">Control loop</a>
            <a href="#install">Install</a>
            <a href="#architecture">Architecture</a>
            <a href="#agent-security">Agent security</a>
          </div>
          <div className="nav-actions">
            <button className="quiet" onClick={next}>Sign in</button>
            <button className="primary" onClick={next}>Open console <ArrowRight aria-hidden="true" /></button>
          </div>
        </nav>
      </header>

      <section className="hero" id="top">
        <div className="hero-content">
          <div className="hero-badge">
            <span className="hero-badge-dot" aria-hidden="true" />
            <span>INDEPENDENT LINUX ENDPOINT DEFENSE &amp; RESPONSE GOVERNANCE</span>
          </div>

          <div className="hero-brand-wrap">
            <img
              className="hero-logo"
              src="/shield-logo-large.webp"
              alt="Xibalba Shield logo"
              width="640"
              height="691"
            />
          </div>

          <h1>
            The EDR detects and acts.<br />
            <em>Shield proves who authorized it.</em>
          </h1>

          <p className="lede">
            Deterministic Linux endpoint defense, kernel telemetry, zero-probability boundary gating, and fail-closed host containment. Built as an autonomous endpoint security platform that operates completely standalone or serves as the ground-truth physical plant sensor and runtime enforcer in closed control loops.
          </p>

          <div className="hero-actions">
            <a href="#install" className="primary big" style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
              <Download size={18} aria-hidden="true" /> Install Shield
            </a>
            <button className="quiet big" onClick={next}>
              Explore console <ArrowRight aria-hidden="true" />
            </button>
            <a href="#loop" className="hero-secondary-link">
              <Activity size={15} aria-hidden="true" /> Control loop spec
            </a>
          </div>

          <div className="hero-metrics-bar" role="region" aria-label="Key system invariants">
            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <ShieldCheck size={18} aria-hidden="true" />
                <h3>Host-Authoritative</h3>
              </div>
              <p>Reversible SIGSTOP, cgroup freeze, and nftables destination drop executed directly on the physical host.</p>
              <div className="hero-metric-footer">
                <code>FAIL-CLOSED · LOCAL ENFORCER</code>
              </div>
            </div>

            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <Cpu size={18} aria-hidden="true" />
                <h3>Zero Kernel Modules</h3>
              </div>
              <p>Native Linux procfs, eBPF CO-RE, and socket tables without kernel panics or out-of-tree drivers.</p>
              <div className="hero-metric-footer">
                <code>LINUX 4.18+ / 5.x / 6.x</code>
              </div>
            </div>

            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <LockKeyhole size={18} aria-hidden="true" />
                <h3>Cryptographic Gateways</h3>
              </div>
              <p>EDR containment, process termination, and policy actions gated by actor DID and OPA hash bundles.</p>
              <div className="hero-metric-footer">
                <code>RFC 8628 · BOUNDARY VERIFIED</code>
              </div>
            </div>

            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <FileCheck2 size={18} aria-hidden="true" />
                <h3>Ed25519 Hash Ledger</h3>
              </div>
              <p>Every sensor event, gate evaluation, and responder outcome written to an append-only cryptographic chain.</p>
              <div className="hero-metric-footer">
                <code>100% OFFLINE · IMMUTABLE EVIDENCE</code>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="proof" id="proof" aria-label="Key architectural properties">
        <div>
          <b>Kernel-level</b>
          <span>procfs &amp; eBPF coverage</span>
        </div>
        <div>
          <b>Default deny</b>
          <span>policy enforcement</span>
        </div>
        <div>
          <b>Append-only</b>
          <span>decision evidence</span>
        </div>
        <div>
          <b>Local first</b>
          <span>works without cloud</span>
        </div>
      </section>

      <section className="features" id="platform" aria-labelledby="platform-heading">
        <header>
          <p className="eyebrow">THE SHIELD PLATFORM</p>
          <h2 id="platform-heading">Security that moves at agent speed.</h2>
          <p>One operational surface for fleet posture, policy decisions, and containment evidence.</p>
        </header>
        <div className="feature-grid">
          {[
            [Radar, 'See every action', 'Process, file, and network telemetry in one live event stream.'],
            [Fingerprint, 'Enforce identity', 'Bind decisions to verified agents, devices, and identities.'],
            [FileCheck2, 'Prove the outcome', 'Every action produces durable, reviewable evidence.']
          ].map(([Icon, title, copy]) => (
            <article key={title} className="feature-card">
              <span className="feature-icon"><Icon aria-hidden="true" /></span>
              <h3>{title}</h3>
              <p>{copy}</p>
              <button onClick={next} className="link-button">
                View in console <ArrowRight aria-hidden="true" />
              </button>
            </article>
          ))}
        </div>
      </section>

      <section className="landing-loop" id="loop" aria-labelledby="loop-heading">
        <div className="landing-section-copy">
          <p className="eyebrow"><span aria-hidden="true" /> CONTROL THEORY &amp; CLOSED-LOOP INTEGRITY</p>
          <h2 id="loop-heading">Where Shield works in the <em>control loop.</em></h2>
          <p>
            A feedback controller cannot stabilize a system without accurate plant measurements. Prompt guardrails fail because reinforcement learning agents treat them as thermodynamic friction and optimize around them. Shield is the physical plant sensor and fail-closed enforcer: observing what actually happened at the OS and network layer, executing containment when bounds revert, and publishing signed evidence spans to close the control loop.
          </p>
        </div>
        <MermaidDiagram chart={CONTROL_LOOP_FLOW} label="Closed control loop: Signed pack, Hook, Agent plant, Shield sensor, Oracle, AIS, and Settlement chain" />
        <p className="diagram-caption">
          <LockKeyhole size={14} /> Shield is the physical plant sensor and runtime enforcer ($y = Cx + v$). It measures ground truth on the host and executes fail-closed physical containment if the hook reverts.
        </p>
        <div className="loop-callout-grid">
          <article className="loop-callout-card">
            <h3><Radar size={16} /> 1. The Plant Sensor (Observation)</h3>
            <p>
              Shield sits alongside the agent workload, monitoring raw Linux telemetry: /proc/net/tcp socket tables, process exec events, file writes, and network flows. It captures ground truth regardless of what the LLM claims it did.
            </p>
          </article>
          <article className="loop-callout-card">
            <h3><Sliders size={16} /> 2. Fail-Closed Enforcer (Containment)</h3>
            <p>
              When a policy gate or boundary hook evaluates constraint vector C and reverts, Shield enforces physical containment on the host: dropping egress via nftables, issuing SIGSTOP, freezing cgroups, or terminating rogue processes.
            </p>
          </article>
          <article className="loop-callout-card">
            <h3><ShieldCheck size={16} /> 3. Evidence Spans to Oracle (Feedback)</h3>
            <p>
              Shield emits signed, tamper-evident evidence spans to the Oracle. The Oracle verifies state estimates, updates the Autonomous Integrity Score (AIS), and anchors Merkle roots to the settlement chain—preventing reward hacking.
            </p>
          </article>
        </div>
      </section>

      <section className="landing-install" id="install" aria-labelledby="install-heading">
        <div className="landing-section-copy">
          <p className="eyebrow"><span aria-hidden="true" /> DEPLOYMENT &amp; QUICKSTART</p>
          <h2 id="install-heading">Install Shield on any <em>Linux host or cluster.</em></h2>
          <p>
            Shield operates as a self-contained endpoint defense agent. Whether deployed as a hardened systemd daemon on bare-metal servers, containerized on Kubernetes edge nodes, or run via CLI on developer workstations, Shield brings kernel-level visibility and fail-closed containment to your infrastructure.
          </p>
        </div>

        <div className="install-container">
          <div className="install-tabs" role="tablist" aria-label="Installation methods">
            {INSTALL_OPTIONS.map((opt) => {
              const Icon = opt.icon
              const isActive = activeInstallTab === opt.id
              return (
                <button
                  key={opt.id}
                  role="tab"
                  aria-selected={isActive}
                  className={`install-tab-btn ${isActive ? 'active' : ''}`}
                  onClick={() => setActiveInstallTab(opt.id)}
                >
                  <Icon size={15} aria-hidden="true" />
                  {opt.label}
                </button>
              )
            })}
          </div>

          <div className="install-terminal">
            <div className="terminal-header">
              <div className="terminal-dots">
                <span className="terminal-dot red" />
                <span className="terminal-dot yellow" />
                <span className="terminal-dot green" />
                <span style={{ marginLeft: '8px', opacity: 0.8 }}>shield@{activeInstall.id}:~</span>
              </div>
              <button
                className="copy-snippet-btn"
                onClick={() => handleCopy(activeInstall.cmd)}
                aria-label="Copy installation command"
              >
                {copied ? <Check size={13} /> : <Copy size={13} />}
                {copied ? 'Copied' : 'Copy command'}
              </button>
            </div>
            <div className="terminal-content">
              <p className="terminal-description">{activeInstall.desc}</p>
              <pre className="terminal-code-block"><code>{activeInstall.cmd}</code></pre>
              <div className="terminal-verify-block">
                <span className="terminal-verify-label">Verification Command</span>
                <code className="terminal-verify-code">{activeInstall.verify}</code>
                <small style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '2px' }}>{activeInstall.details}</small>
              </div>
            </div>
          </div>

          <div className="install-features-grid">
            <div className="install-feature-item">
              <Cpu size={16} aria-hidden="true" />
              <div>
                <b>No Kernel Modules Required</b>
                <span>Runs cleanly via native Linux procfs, eBPF CO-RE, or socket helpers without kernel patching.</span>
              </div>
            </div>
            <div className="install-feature-item">
              <LockKeyhole size={16} aria-hidden="true" />
              <div>
                <b>Fail-Closed Local Containment</b>
                <span>Reversible SIGSTOP, cgroup freeze, and nftables rules execute locally without cloud roundtrips.</span>
              </div>
            </div>
            <div className="install-feature-item">
              <Fingerprint size={16} aria-hidden="true" />
              <div>
                <b>Cryptographic Hash Chains</b>
                <span>Every decision and outcome is signed with a local Ed25519 node keypair in tamper-evident logs.</span>
              </div>
            </div>
            <div className="install-feature-item">
              <ShieldCheck size={16} aria-hidden="true" />
              <div>
                <b>Air-Gap &amp; Standalone Ready</b>
                <span>Full OPA policy execution, sensor loops, and local containment function without external internet.</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="landing-architecture" id="architecture" aria-labelledby="architecture-heading">
        <div className="landing-section-copy">
          <p className="eyebrow"><span aria-hidden="true" /> HOST DEFENSE &amp; TELEMETRY</p>
          <h2 id="architecture-heading">From kernel telemetry to <em>provable action.</em></h2>
          <p>
            Shield turns low-level Linux signals into high-confidence decisions on the host. The local policy path remains independent of cloud availability; evidence export happens after the decision.
          </p>
        </div>
        <MermaidDiagram chart={DECISION_FLOW} label="Shield telemetry, local policy, containment, and evidence flow" />
      </section>

      <section className="landing-response" id="responders" aria-labelledby="response-heading">
        <div className="landing-section-copy">
          <p className="eyebrow"><span aria-hidden="true" /> ENFORCEMENT GATING</p>
          <h2 id="response-heading">A <em>proof-gated</em> response lifecycle.</h2>
          <p>
            Powerful responders are never enabled by a UI switch or configuration flag alone. Runtime evidence, identity, policy integrity, rollback validation, audit delivery, and approval must all be current.
          </p>
        </div>
        <MermaidDiagram chart={RESPONSE_FLOW} label="Proof-gated responder readiness flow" />
        <p className="diagram-caption"><LockKeyhole size={14} /> Any missing, stale, or device-mismatched proof keeps the responder unavailable.</p>
      </section>

      <section className="landing-assurance" id="assurance" aria-labelledby="assurance-heading">
        <div className="landing-section-copy">
          <p className="eyebrow"><span aria-hidden="true" /> OPERATIONAL ASSURANCE</p>
          <h2 id="assurance-heading">Operational assurance by design.</h2>
          <p>
            Security that stays close to the workload, records what happened, and limits every response to the smallest justified boundary.
          </p>
        </div>
        <div className="assurance-rows">
          {[[SquareTerminal, 'Local-first', 'Sensing, policy evaluation, and containment run on the host.'], [FileCheck2, 'Auditable', 'Decisions and outcomes carry durable evidence and correlation.'], [Crosshair, 'Scoped', 'Responses target a process, cgroup, or exact destination flow.'], [RotateCcw, 'Reversible', 'Safe actions support rollback; destructive actions require approval.']].map(([Icon, title, text]) => <div key={title}><Icon /><b>{title}</b><span>{text}</span></div>)}
        </div>
      </section>

      <section className="landing-agent-security" id="agent-security" aria-labelledby="agent-security-heading">
        <div className="agent-security-intro">
          <p className="eyebrow"><span aria-hidden="true" /> DUAL-LAYER PROTECTION</p>
          <h2 id="agent-security-heading">One security boundary across agent intent and host execution.</h2>
          <p>
            Shield protects autonomous systems at two layers. Semantic guardrails inspect what an agent is attempting to do, while Linux sensors observe what actually reaches the operating system. A local deterministic policy engine connects both views without putting cloud inference in the enforcement path.
          </p>
        </div>
        <MermaidDiagram chart={AGENT_FLOW} label="Shield agent request, guardrail, kernel execution, and evidence correlation flow" />
        <div className="metadata-rail" aria-label="Shield security coverage"><span>Security coverage</span>{['Ingress', 'Retrieval', 'Model routing', 'Tool calls', 'Process execution', 'File writes', 'Network flows', 'Post-action checks'].map((item) => <b key={item}>{item}</b>)}</div>
        <div className="agent-security-details">
          <article><Workflow /><h3>Correlate intent with execution</h3><p>Shield carries stable identifiers from an agent request through policy evaluation, attempted action, kernel telemetry, containment, and evidence publication. Operators can reconstruct what was requested, what policy decided, what the host observed, and whether the outcome matched expectations.</p><ul><li>Agent, tenant, device, session, and invocation scope.</li><li>Policy version and deterministic decision reason.</li><li>Requested, attempted, completed, and verified outcomes.</li><li>Explicit gaps when telemetry or evidence is unavailable.</li></ul></article>
          <article><Settings2 /><h3>Configure enforcement deliberately</h3><p>Teams select sensor cadence, evidence behavior, guardrail coverage, containment mode, and cooldowns through versioned tenant settings. Sensitive containment and guardrail changes enter an approval queue and can be rejected or rolled back with a complete audit trail.</p><ul><li>Audit-only, approval, or policy-authorized response modes.</li><li>Independent guardrails for retrieval, routing, output, tools, and post-action state.</li><li>Signed policy distribution with downgrade protection.</li><li>Responder capability stays locked until runtime proof passes.</li></ul></article>
        </div>
        <div className="shield-capabilities">
          <article><span>01</span><div><h3>Live event timeline</h3><p>Filter process, file, network, and agent events by severity and decision. Expand each record to inspect normalized context, policy rationale, evidence state, and correlation identifiers.</p></div></article>
          <article><span>02</span><div><h3>Pre-action guardrails</h3><p>Evaluate ingress, retrieved context, model destinations, generated output, and tool requests before execution. Unavailable policy dependencies fail closed instead of silently allowing work.</p></div></article>
          <article><span>03</span><div><h3>Kernel-level observation</h3><p>Use eBPF process, file-write, and TCP-connect sensors—or a split privileged helper—to observe real host activity independently of the agent framework.</p></div></article>
          <article><span>04</span><div><h3>Bounded containment</h3><p>Start with reversible SIGSTOP. Promote cgroup freeze, explicit kill, or destination-scoped nftables blocking only after device-bound runtime evidence and operator approval.</p></div></article>
          <article><span>05</span><div><h3>Post-action verification</h3><p>Compare the expected state transition with observed results. A mismatch becomes an enforcement anomaly rather than an unqualified success.</p></div></article>
          <article><span>06</span><div><h3>Evidence and integrations</h3><p>Publish durable decision and outcome records, monitor exporter queues, and route normalized events into SIEM, webhooks, and incident-response systems.</p></div></article>
        </div>
        <p className="agent-security-boundary"><LockKeyhole size={14} /> Shield is the enforcement authority shown here. External intelligence can inform policy design, but it cannot bypass local policy, approval, or responder-readiness gates.</p>
      </section>

      <section className="cta" id="control">
        <div>
          <p className="eyebrow">BUILT FOR REAL OPERATIONS</p>
          <h2>Put your agent fleet behind a verifiable boundary.</h2>
          <p>Start with visibility. Promote responders only when their evidence is complete.</p>
          <div style={{ marginTop: '1.25rem', display: 'flex', gap: '1.5rem', flexWrap: 'wrap', fontSize: '13px', alignItems: 'center' }}>
            <a href="mailto:jacob@xibalbasolutions.com" style={{ color: 'var(--text)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 500 }}>
              <Mail size={14} style={{ color: 'var(--accent-text)' }} /> jacob@xibalbasolutions.com
            </a>
            <a href="tel:+12628641589" style={{ color: 'var(--text)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 500 }}>
              <Phone size={14} style={{ color: 'var(--accent-text)' }} /> 1 (262) 864-1589
            </a>
            <a href="https://xibalbasolutions.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-text)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
              <Globe size={14} /> xibalbasolutions.com
            </a>
          </div>
        </div>
        <button onClick={next} className="cta-btn">
          Open Shield <ArrowRight aria-hidden="true" />
        </button>
      </section>

      <footer className="site-footer">
        <div className="footer-main">
          <div className="footer-brand">
            <Brand />
            <p>
              Deterministic Linux endpoint defense, response governance, and fail-closed host containment for autonomous agent systems.
            </p>
            <div className="footer-brand-meta">
              <a
                href="https://xibalbasolutions.com"
                target="_blank"
                rel="noopener noreferrer"
                className="footer-brand-parent"
              >
                <Globe size={13} aria-hidden="true" />
                <span>Commercial vertical of Xibalba Solutions LLC</span>
              </a>
              <div className="footer-brand-badge">
                <span className="status-dot green" aria-hidden="true" />
                <span>Local-first · Zero cloud runtime dependency</span>
              </div>
            </div>
          </div>

          <div className="footer-links">
            <h3>Platform</h3>
            <a href="#install">Install &amp; Quickstart</a>
            <a href="#loop">Control Loop Spec</a>
            <a href="#platform">Endpoint Capabilities</a>
            <a href="#architecture">Kernel Telemetry</a>
            <a href="#responders">Proof-Gated Responders</a>
          </div>

          <div className="footer-links">
            <h3>Ecosystem</h3>
            <a href="https://xibalbasolutions.com" target="_blank" rel="noopener noreferrer">
              Xibalba Solutions LLC
            </a>
            <a href="#loop">Integrity Protocol</a>
            <a href="#loop">Super-Cortex AIS Memory</a>
            <a href="#agent-security">Agent0 ERC-8004 Identity</a>
            <a href="#install">Zero-Trust Device Pairing</a>
          </div>

          <div className="footer-links">
            <h3>Governance</h3>
            <a href="#proof">Default-Deny Invariants</a>
            <a href="#responders">Two-Person Sign-off</a>
            <a href="#assurance">Host Containment Bounds</a>
            <a href="#proof">Ed25519 Hash Ledger</a>
            <button onClick={next} className="footer-console-btn">
              Operator Console <ArrowRight size={12} aria-hidden="true" />
            </button>
          </div>

          <div className="footer-contact">
            <h3>Executive Inquiries</h3>
            <p className="footer-contact-desc">
              Direct engineering access for enterprise deployments, custom eBPF telemetry, and closed control loop integrations.
            </p>
            <div className="footer-contact-list">
              <a href="mailto:jacob@xibalbasolutions.com" className="footer-contact-item">
                <Mail size={13} aria-hidden="true" />
                <span>jacob@xibalbasolutions.com</span>
              </a>
              <a href="tel:+12628641589" className="footer-contact-item">
                <Phone size={13} aria-hidden="true" />
                <span>+1 (262) 864-1589</span>
              </a>
              <a
                href="https://xibalbasolutions.com"
                target="_blank"
                rel="noopener noreferrer"
                className="footer-contact-item"
              >
                <Globe size={13} aria-hidden="true" />
                <span>xibalbasolutions.com</span>
              </a>
              <div className="footer-contact-item footer-location">
                <MapPin size={13} aria-hidden="true" />
                <span>Wisconsin, United States</span>
              </div>
            </div>
          </div>
        </div>

        <div className="footer-bottom">
          <div className="footer-bottom-copy">
            <small>
              © {new Date().getFullYear()} <a href="https://xibalbasolutions.com" target="_blank" rel="noopener noreferrer">Xibalba Solutions LLC</a>. All rights reserved. Registered in Wisconsin, USA.
            </small>
          </div>
          <div className="footer-bottom-specs">
            <span className="spec-tag">LINUX 4.18+ / 5.x / 6.x</span>
            <span className="spec-tag">RFC 8628 DID &amp; OPA REGO</span>
            <span className="spec-tag">ED25519 HASH CHAIN</span>
            <span className="spec-tag">FAIL-CLOSED ENFORCER</span>
          </div>
        </div>
      </footer>
    </main>
  )
}
