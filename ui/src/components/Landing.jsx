import { useState } from 'react'
import {
  Activity,
  ArrowRight,
  Check,
  CheckCircle2,
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
  Send,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  Sliders,
  Sparkles,
  SquareTerminal,
  Terminal,
  Workflow,
} from 'lucide-react'
import { Brand } from './Brand'
import { MermaidDiagram } from './MermaidDiagram'

const CONTROL_LOOP_FLOW = `flowchart LR
  SP["Signed Setpoint Pack<br/>constraint vector C"] --> SUM(("Σ"))
  SUM --> HK["Pre/Post Hook<br/>evaluates C on state"]
  HK -->|admit or revert| AG["Autonomous Workload<br/>the physical plant"]
  AG -->|"actual execution"| SH["Shield Host Defense<br/>sensor & enforcer"]
  SH -->|"evidence spans"| OR["Integrity Oracle<br/>verify & epoch anchor"]
  OR -->|"state estimate"| SUM
  OR -->|"verified proof"| AIS["AIS Engine<br/>bounded adaptive gain"]
  AIS -.->|"adapt bound"| SP
  AG -->|"settlement"| CH["Settlement Chain<br/>anchored state root"]
  SH -.->|"anchor root"| CH`

const HYBRID_A2A_FLOW = `flowchart LR
  subgraph EDGE["Edge Host · shield.local (Fast Classifier)"]
    direction TB
    K["Kernel Telemetry<br/>procfs · eBPF · sockets"] --> C{"Fast Classifier<br/>OPA gate (&lt; 2ms)"}
    C -->|benign / admit| OK["Admit Workload<br/>unhindered execution"]
    C -->|breach / halt| CONT["Host Containment<br/>SIGSTOP · nftables"]
    CONT --> EV["Evidence Ledger<br/>Ed25519 hash chain"]
  end

  subgraph MESH["Secure A2A Protocol (RFC 8785)"]
    direction TB
    DID["Mutual DID Auth<br/>ERC-8004 Passports"]
    ENV["Canonical Envelopes<br/>RFC 8785 · SHA-256"]
    DID --- ENV
  end

  subgraph CLOUD["Cloud Defense · shield.cloud (Production LLM)"]
    direction TB
    LLM["Production LLM<br/>Hermes-3 70B reasoning"]
    CORR["Fleet Correlation<br/>multi-agent threat graph"]
    POL["Policy Synthesis<br/>signed OPA distribution"]
    LLM --> CORR --> POL
  end

  C -->|"flagged detection"| MESH
  MESH -->|"verified envelope"| LLM
  POL -.->|"signed policy push"| EDGE`

const RESPONSE_FLOW = `flowchart LR
  A["Response Intent<br/>remediation proposal"] --> E{"Cryptographic Gate<br/>deterministic verify"}
  B["Actor DID & Role<br/>verified Ed25519 key"] --> E
  C["Policy Bundle<br/>signed OPA hash lock"] --> E
  D["Operator Sign-off<br/>two-person quorum"] --> E
  E -->|allow / approved| F["Atomic Consume<br/>single-use execution"]
  E -->|deny / expired| G["Fail Closed<br/>terminal drop & log"]
  F --> H["Contain Host<br/>isolated interface"]
  F --> I["Kill Process<br/>targeted SIGKILL"]
  F --> J["OS Freeze<br/>cgroups & nftables"]`

const AGENT_FLOW = `flowchart LR
  A["Agent Intent<br/>tool call or model action"] --> B["Cryptographic Boundary<br/>mutual DID verification"]
  B --> C["Deterministic Policy<br/>geometric traversal checks"]
  C --> D["Response Gateway<br/>execution intent triage"]
  D --> E["Kernel Execution<br/>procfs · eBPF telemetry"]
  E --> F["State Verification<br/>differential audit check"]
  F --> G["Evidence Chain<br/>hash-linked receipt log"]
  H["Signed Tenant Policy<br/>immutable OPA bundle"] -.->|"governs"| B
  H -.->|"governs"| D
  I["Sensors & Connectors<br/>kernel telemetry feeds"] -.->|"observes"| E`

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
  const [contactForm, setContactForm] = useState({
    name: '',
    email: '',
    organization: '',
    scope: 'Endpoint Agent Deployment',
    message: '',
  })
  const [contactSubmitted, setContactSubmitted] = useState(false)

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleContactSubmit = (e) => {
    e.preventDefault()
    setContactSubmitted(true)
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
            <a href="#contact">Contact</a>
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
            A hybrid endpoint defense architecture combining sub-millisecond local classification on the host with deep production LLM reasoning in the cloud—communicating securely over the cryptographic A2A protocol. Shield enforces fail-closed containment at the kernel boundary while correlating fleet-wide threats across autonomous agent workloads.
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
                <h3>Local Fast Classifier</h3>
              </div>
              <p>Sub-millisecond classification and OPA evaluation on the edge daemon for wire-speed containment without cloud latency.</p>
              <div className="hero-metric-footer">
                <code>&lt; 2MS LATENCY · SHIELD.LOCAL</code>
              </div>
            </div>

            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <Workflow size={18} aria-hidden="true" />
                <h3>Secure A2A Protocol</h3>
              </div>
              <p>Flagged detections escalate to cloud fleet models over mutual Ed25519 DIDs and canonical RFC 8785 envelopes.</p>
              <div className="hero-metric-footer">
                <code>RFC 8785 · ERC-8004 PASSPORTS</code>
              </div>
            </div>

            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <Sparkles size={18} aria-hidden="true" />
                <h3>Cloud LLM Reasoning</h3>
              </div>
              <p>Production frontier LLMs perform deep chain-of-thought analysis and fleet correlation over flagged edge detections.</p>
              <div className="hero-metric-footer">
                <code>HERMES-3 70B · SHIELD.CLOUD</code>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="proof" id="proof" aria-label="Key architectural properties">
        <div>
          <b>Local classifier</b>
          <span>&lt; 2ms edge speed</span>
        </div>
        <div>
          <b>Cloud LLM reasoning</b>
          <span>deep anomaly analysis</span>
        </div>
        <div>
          <b>Secure A2A mesh</b>
          <span>mutual DID authentication</span>
        </div>
        <div>
          <b>Fail-closed</b>
          <span>kernel-level containment</span>
        </div>
      </section>

      <section className="features" id="platform" aria-labelledby="platform-heading">
        <header>
          <p className="eyebrow">THE SHIELD PLATFORM</p>
          <h2 id="platform-heading">Security that moves at agent speed.</h2>
          <p>A hybrid defense mesh uniting deterministic edge classification and deep cloud reasoning.</p>
        </header>
        <div className="feature-grid">
          {[
            [Cpu, 'Fast Edge Classifier', 'Sub-2ms local classification and deterministic OPA bounding right on the host—no cloud round-trip required for containment.'],
            [Workflow, 'Secure A2A Mesh', 'Mutual Ed25519 DID authentication and RFC 8785 canonical envelopes connect edge daemons to the defense fleet with zero trust.'],
            [Sparkles, 'Production LLM Reasoning', 'Cloud reasoning coordinator (Hermes-3 70B) runs deep contextual analysis on detections flagged by edge nodes.']
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
          <LockKeyhole size={14} /> Shield is the physical plant sensor and runtime enforcer (y = C x + v). It measures ground truth on the host and executes fail-closed physical containment if the hook reverts.
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
                <span className="terminal-title">shield@{activeInstall.id}:~</span>
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
          <p className="eyebrow"><span aria-hidden="true" /> HYBRID EDGE-TO-CLOUD ARCHITECTURE</p>
          <h2 id="architecture-heading">Local classification speed. <em>Cloud LLM reasoning.</em></h2>
          <p>
            Endpoint containment cannot tolerate cloud round-trips when a rogue process executes unauthorized actions. Conversely, a lightweight edge daemon cannot maintain full fleet threat graphs or run multi-step reasoning. Shield solves this with a two-tier hybrid architecture: an ultra-fast classification agent (<code>shield.local</code>) operating directly on the Linux host for immediate fail-closed containment, paired with a cloud defense coordinator (<code>shield.cloud</code>) running large production LLMs for deep reasoning over flagged detections—exchanged securely over the cryptographic Agent-to-Agent (A2A) protocol.
          </p>
        </div>
        <MermaidDiagram chart={HYBRID_A2A_FLOW} label="Shield hybrid architecture: Local classification on edge, secure A2A protocol, and cloud LLM deep reasoning" />
        <div className="hybrid-tier-grid">
          <article className="hybrid-tier-card">
            <div className="hybrid-tier-header">
              <span className="hybrid-tier-badge local">EDGE DAEMON · #4</span>
              <h3>shield.local (Fast Classifier)</h3>
            </div>
            <p className="hybrid-tier-desc">Runs directly on the host alongside workloads, evaluating kernel events in microseconds without cloud dependencies.</p>
            <ul className="hybrid-tier-list">
              <li><b>Classification model:</b> Specialized low-latency classifier (<code>jev-fast-classifier</code>) &amp; deterministic OPA engine.</li>
              <li><b>Execution latency:</b> &lt; 2ms decision time; admits benign actions and immediately halts policy breaches.</li>
              <li><b>Physical containment:</b> Executes reversible SIGSTOP, cgroup freezing, and nftables destination drops.</li>
              <li><b>Autonomous fallback:</b> 100% offline-capable; fails closed if network connectivity is severed.</li>
            </ul>
          </article>

          <article className="hybrid-tier-card">
            <div className="hybrid-tier-header">
              <span className="hybrid-tier-badge a2a">MESH PROTOCOL · RFC 8785</span>
              <h3>Secure A2A Mesh Bridge</h3>
            </div>
            <p className="hybrid-tier-desc">Cryptographic communication channel connecting edge hosts to cloud reasoning nodes with zero trust.</p>
            <ul className="hybrid-tier-list">
              <li><b>Mutual DID handshake:</b> Ed25519 identity verification and on-chain ERC-8004 passport tokens.</li>
              <li><b>Canonical payloads:</b> Envelopes serialized via RFC 8785 canonical JSON with SHA-256 integrity digests.</li>
              <li><b>Escalation queue:</b> Transmits flagged anomalies, ambient socket traces, and telemetry context for deep inspection.</li>
              <li><b>Attested feedback:</b> Ingested into Super-Cortex memory with strict <code>agent:*</code> cryptographic boundaries.</li>
            </ul>
          </article>

          <article className="hybrid-tier-card">
            <div className="hybrid-tier-header">
              <span className="hybrid-tier-badge cloud">CLOUD FLEET · #5</span>
              <h3>shield.cloud (Production LLM)</h3>
            </div>
            <p className="hybrid-tier-desc">Scalable cloud defense intelligence analyzing escalated incidents across all fleet nodes.</p>
            <ul className="hybrid-tier-list">
              <li><b>Production models:</b> Frontier open-weights reasoning LLMs (<code>hermes-3-70b</code> / cloud frontier reasoning models).</li>
              <li><b>Deep incident reasoning:</b> Evaluates intent vs telemetry context, reconstructs attack trees, and detects evasion.</li>
              <li><b>Fleet correlation:</b> Correlates coordinated multi-host anomalies and novel zero-day attack vectors.</li>
              <li><b>Policy distribution:</b> Synthesizes hardened OPA constraint rules and pushes signed updates to edge daemons.</li>
            </ul>
          </article>
        </div>
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
            Shield protects autonomous systems across two distinct layers: an ultra-fast classification agent running on the Linux host (<code>shield.local</code>) that evaluates kernel events in microseconds, and an asynchronous cloud defense coordinator (<code>shield.cloud</code>) that evaluates flagged telemetry using production LLMs over an authenticated Agent-to-Agent (A2A) mesh. A local deterministic policy engine connects both views without putting cloud inference in the blocking enforcement path.
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

      {/* Contact Section mirroring Cortex #xc-contact */}
      <section className="landing-contact" id="contact" aria-labelledby="contact-heading">
        <div className="contact-grid">
          <div className="contact-info">
            <div>
              <p className="eyebrow"><span aria-hidden="true" /> CONTACT LEADERSHIP</p>
              <h2 id="contact-heading">Direct Inquiries &amp; Dedicated Deployments</h2>
            </div>
            <p>
              Reach out for dedicated enterprise Xibalba Shield deployments, high-throughput autonomous agent fleet protection, custom eBPF / OPA policy bundles, or confidential security assessments.
            </p>

            <div className="contact-channels">
              <a href="mailto:jacob@xibalbasolutions.com" className="contact-channel-card">
                <span className="contact-channel-icon" aria-hidden="true">
                  <Mail size={18} />
                </span>
                <div className="contact-channel-meta">
                  <span className="contact-channel-label">Executive Email</span>
                  <span className="contact-channel-value">jacob@xibalbasolutions.com</span>
                </div>
              </a>

              <a href="tel:+12628641589" className="contact-channel-card">
                <span className="contact-channel-icon" aria-hidden="true">
                  <Phone size={18} />
                </span>
                <div className="contact-channel-meta">
                  <span className="contact-channel-label">Direct Telephone</span>
                  <span className="contact-channel-value">1 (262) 864-1589</span>
                </div>
              </a>

              <a href="https://xibalbasolutions.com" target="_blank" rel="noopener noreferrer" className="contact-channel-card">
                <span className="contact-channel-icon" aria-hidden="true">
                  <Globe size={18} />
                </span>
                <div className="contact-channel-meta">
                  <span className="contact-channel-label">Parent Company</span>
                  <span className="contact-channel-value">
                    xibalbasolutions.com <ExternalLink size={12} aria-hidden="true" />
                  </span>
                </div>
              </a>
            </div>

            <div className="contact-location">
              <MapPin size={14} aria-hidden="true" />
              <span>Xibalba Solutions LLC · Operations based in Wisconsin, USA</span>
            </div>
          </div>

          <form onSubmit={handleContactSubmit} className="contact-form-wrap">
            <input name="website" type="text" tabIndex="-1" autoComplete="off" style={{ display: 'none' }} />

            <div className="contact-form-row">
              <div className="contact-field">
                <label htmlFor="contact-name">Your Name *</label>
                <input
                  id="contact-name"
                  name="name"
                  required
                  placeholder="Dr. Elena Rostova"
                  value={contactForm.name}
                  onChange={(e) => setContactForm({ ...contactForm, name: e.target.value })}
                />
              </div>
              <div className="contact-field">
                <label htmlFor="contact-email">Email Address *</label>
                <input
                  id="contact-email"
                  name="email"
                  type="email"
                  required
                  placeholder="elena@organization.com"
                  value={contactForm.email}
                  onChange={(e) => setContactForm({ ...contactForm, email: e.target.value })}
                />
              </div>
            </div>

            <div className="contact-form-row">
              <div className="contact-field">
                <label htmlFor="contact-org">Organization</label>
                <input
                  id="contact-org"
                  name="organization"
                  placeholder="Autonomous Systems Lab"
                  value={contactForm.organization}
                  onChange={(e) => setContactForm({ ...contactForm, organization: e.target.value })}
                />
              </div>
              <div className="contact-field">
                <label htmlFor="contact-scope">Inquiry Scope</label>
                <select
                  id="contact-scope"
                  name="scope"
                  value={contactForm.scope}
                  onChange={(e) => setContactForm({ ...contactForm, scope: e.target.value })}
                >
                  <option value="Endpoint Agent Deployment">Dedicated Endpoint Daemon Deployment</option>
                  <option value="Agent Fleet Security Audit">Agent Fleet Security Audit</option>
                  <option value="Custom OPA / eBPF Rule Authoring">Custom OPA / eBPF Rule Authoring</option>
                  <option value="Enterprise / Partnership Inquiry">Enterprise / Partnership Inquiry</option>
                </select>
              </div>
            </div>

            <div className="contact-field">
              <label htmlFor="contact-message">Message or Deployment Inquiry *</label>
              <textarea
                id="contact-message"
                name="message"
                required
                rows={4}
                placeholder="Describe your host environment, agent frameworks, containment requirements, or custom Linux telemetry needs..."
                value={contactForm.message}
                onChange={(e) => setContactForm({ ...contactForm, message: e.target.value })}
              />
            </div>

            <div className="contact-form-footer">
              <span className="contact-reassurance">Direct executive transmission · Zero tracking</span>
              <button type="submit" className="contact-submit-btn">
                <Send size={14} aria-hidden="true" />
                <span>Send Message</span>
              </button>
            </div>

            {contactSubmitted && (
              <div className="contact-feedback-banner" role="status">
                <CheckCircle2 size={16} aria-hidden="true" />
                <span>Your inquiry has been received. Jacob from Xibalba Solutions will follow up promptly.</span>
              </div>
            )}
          </form>
        </div>
      </section>

      {/* Footer mirroring Cortex */}
      <footer className="site-footer">
        <div className="footer-main">
          {/* Brand & Mission Column */}
          <div className="footer-brand">
            <div className="footer-brand-header">
              <Brand />
              <span className="footer-badge">HOST DEFENSE</span>
            </div>
            <p>
              Deterministic Linux host defense, kernel telemetry observation, and fail-closed containment for autonomous agent fleets.
            </p>
            <div className="footer-brand-meta">
              <div className="footer-meta-line">Deterministic Hash Chains · RFC 8628 DIDs</div>
              <a
                href="https://xibalbasolutions.com"
                target="_blank"
                rel="noopener noreferrer"
                className="footer-brand-parent"
              >
                <Globe size={12} aria-hidden="true" />
                <span>Commercial pillar of Xibalba Solutions LLC</span>
                <ExternalLink size={10} aria-hidden="true" />
              </a>
            </div>
          </div>

          {/* Platform Navigation */}
          <div className="footer-links">
            <p className="footer-col-title">Platform</p>
            <a href="#platform">Endpoint Capabilities</a>
            <a href="#architecture">Hybrid Architecture</a>
            <a href="#responders">Proof Responders</a>
            <a href="#agent-security">Dual-Layer Security</a>
            <a href="#install">Quick Install</a>
            <button onClick={next} className="footer-console-btn">
              Operator Console <ArrowRight size={11} aria-hidden="true" />
            </button>
          </div>

          {/* Ecosystem Links */}
          <div className="footer-links">
            <p className="footer-col-title">Xibalba Ecosystem</p>
            <a href="https://xibalbasolutions.com" target="_blank" rel="noopener noreferrer">
              Xibalba Solutions LLC <ExternalLink size={10} aria-hidden="true" />
            </a>
            <a href="https://cortex-managed-pilot.onrender.com" target="_blank" rel="noopener noreferrer">
              Super-Cortex (AIS Memory) <ExternalLink size={10} aria-hidden="true" />
            </a>
            <a href="https://github.com/xibalbatechsol/integrity-core" target="_blank" rel="noopener noreferrer">
              Integrity Protocol <ExternalLink size={10} aria-hidden="true" />
            </a>
            <a href="https://github.com/xibalbatechsol/xibalba-shield" target="_blank" rel="noopener noreferrer">
              Xibalba Shield (EDR) <ExternalLink size={10} aria-hidden="true" />
            </a>
            <a href="https://github.com/xibalbatechsol" target="_blank" rel="noopener noreferrer">
              GitHub Organization <ExternalLink size={10} aria-hidden="true" />
            </a>
          </div>

          {/* Direct Contact Column */}
          <div className="footer-contact">
            <p className="footer-col-title">Direct Contact</p>
            <div className="footer-contact-list">
              <a href="mailto:jacob@xibalbasolutions.com" className="footer-contact-item">
                <Mail size={12} aria-hidden="true" />
                <span>jacob@xibalbasolutions.com</span>
              </a>
              <a href="tel:+12628641589" className="footer-contact-item">
                <Phone size={12} aria-hidden="true" />
                <span>1 (262) 864-1589</span>
              </a>
              <div className="footer-contact-item footer-location">
                <MapPin size={12} aria-hidden="true" />
                <span>Wisconsin, United States</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="footer-bottom">
          <div className="footer-bottom-copy">
            &copy; {new Date().getFullYear()} <a href="https://xibalbasolutions.com" target="_blank" rel="noopener noreferrer">Xibalba Solutions LLC</a>. All rights reserved. Registered in Wisconsin, USA.
          </div>
          <div className="footer-bottom-specs">
            <span className="spec-tag">Local-First · Host-Authoritative · RFC 8628 DIDs</span>
          </div>
        </div>
      </footer>
    </main>
  )
}
