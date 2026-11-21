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
  subgraph PROTOCOL["Integrity Protocol (Closed-Loop Governance)"]
    direction TB
    SP["Signed Setpoint Pack<br/>boundary vector C"] --> HK["Boundary Gate Hook<br/>evaluates C on state"]
    OR["Integrity Oracle<br/>verify & epoch anchor"] --> AIS["AIS Engine<br/>adaptive gain (K, L)"]
    AIS -.->|"adapt bounds"| SP
  end

  subgraph WORKLOAD["Physical Host (Plant)"]
    direction TB
    AG["Autonomous Agent<br/>workload plant (x)"]
  end

  subgraph SHIELD["Xibalba Shield (Host Sensor & Enforcer)"]
    direction TB
    SEN["Kernel Sensor (y = Cx + v)<br/>procfs · eBPF · sockets"] --> GATE{"Local OPA Engine<br/>fail-closed triage"}
    GATE -->|breach| CONT["Physical Actuator (u)<br/>SIGSTOP · nftables"]
    GATE -->|admit| LOG["Signed Evidence Log<br/>Ed25519 hash chain"]
  end

  HK -->|admit or revert| AG
  AG -->|"actual execution"| SEN
  LOG -->|"signed evidence spans"| OR`

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

const DUAL_LAYER_FLOW = `flowchart LR
  subgraph INTENT["Layer 1: Semantic Intent Gate (Pre-Action)"]
    direction TB
    A["Agent Reasoning<br/>model prompt & intent"] --> B["Tool Proposal<br/>invocation schema & target"]
    B --> C["Deterministic OPA Gate<br/>sub-2ms argument validation"]
  end

  subgraph BRIDGE["Cryptographic Nonce & Correlation Bridge"]
    direction TB
    NONCE["Invocation Nonce<br/>deterministic session token"]
    HASH["Signed Intent Hash<br/>immutable Ed25519 receipt"]
    NONCE --- HASH
  end

  subgraph KERNEL["Layer 2: Host Execution Enforcer (Post-Action)"]
    direction TB
    D["Kernel Execution<br/>procfs & eBPF CO-RE sensors"] --> E{"Ground-Truth Check<br/>boundary conformance"}
    E -->|conforming| F["Admit & Record<br/>append hash-chained span"]
    E -->|divergent| G["Fail-Closed Actuator<br/>cgroup freeze · SIGSTOP · nftables"]
  end

  C -->|"authorized intent"| NONCE
  NONCE -->|"correlate"| D
  C -.->|"policy deny"| G
  D -.->|"telemetry proof"| HASH`

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
            <span>SOVEREIGN LINUX HOST DEFENSE · INTEGRITY CLOSED-LOOP ENFORCER</span>
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
            Xibalba Shield is a standalone, host-authoritative EDR for Linux servers and autonomous agent fleets—delivering sub-2ms deterministic containment, kernel telemetry observation, and cryptographic authorization completely offline without external dependencies. When integrated with the Integrity Protocol, Shield becomes the physical plant sensor and fail-closed actuator that feeds verified evidence into the Oracle, mathematically closing the cybernetic control loop.
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
                <Shield size={18} aria-hidden="true" />
                <h3>100% Standalone Ready</h3>
              </div>
              <p>Operates completely offline with native procfs/eBPF sensors, local deterministic OPA rules, and Ed25519 hash-chained logs. Zero external dependencies required.</p>
              <div className="hero-metric-footer">
                <code>LOCAL-FIRST · SOVEREIGN EDR</code>
              </div>
            </div>

            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <ShieldCheck size={18} aria-hidden="true" />
                <h3>Host-Authoritative Enforcer</h3>
              </div>
              <p>Reversible SIGSTOP, cgroup v2 freeze, and nftables destination drops executed directly at the Linux kernel boundary without cloud roundtrips.</p>
              <div className="hero-metric-footer">
                <code>FAIL-CLOSED · LOCAL CONTAINMENT</code>
              </div>
            </div>

            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <Radar size={18} aria-hidden="true" />
                <h3>Integrity Closed Loop</h3>
              </div>
              <p>Feeds ground-truth socket and process execution evidence spans to the Integrity Oracle, closing the control loop and preventing model reward hacking.</p>
              <div className="hero-metric-footer">
                <code>y = C x + v · SENSOR FEEDBACK</code>
              </div>
            </div>

            <div className="hero-metric-card">
              <div className="hero-metric-header">
                <span className="hero-metric-status" aria-hidden="true" />
                <Workflow size={18} aria-hidden="true" />
                <h3>Hybrid A2A Intelligence</h3>
              </div>
              <p>Local sub-2ms fast classifier escalates flagged anomalies to cloud reasoning models (Hermes-3 70B) over mutual Ed25519 DIDs and canonical envelopes.</p>
              <div className="hero-metric-footer">
                <code>RFC 8785 · SHIELD.LOCAL &amp; CLOUD</code>
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
          <h2 id="loop-heading">Where Shield works in the control loop—<em>and why it stands alone.</em></h2>
          <p>
            In control theory, a feedback controller cannot stabilize a dynamic plant without accurate, independent measurements. In autonomous AI systems, prompt guardrails fail because reinforcement learning agents treat prompt text as thermodynamic friction and optimize around it—resulting in reward hacking and boundary evasion.
          </p>
          <p>
            Shield bridges sovereign host security and protocol governance. <b>Operating independently</b>, Shield is an offline, host-authoritative Linux EDR that halts rogue processes with sub-2ms local OPA rules. <b>Operating within the Integrity Protocol</b>, Shield acts as the indispensable physical plant sensor (<code>y = C x + v</code>) and runtime actuator (<code>u</code>): measuring ground-truth kernel telemetry, executing physical containment when boundary constraints revert, and publishing signed evidence spans to the Oracle to mathematically close the control loop.
          </p>
        </div>
        <MermaidDiagram chart={CONTROL_LOOP_FLOW} label="Closed control loop: Signed pack, Boundary Hook, Agent plant, Shield sensor & enforcer, Oracle, AIS, and Settlement chain" />
        <p className="diagram-caption">
          <LockKeyhole size={14} /> Shield is the physical plant sensor and runtime enforcer (y = C x + v). It operates standalone on the host and closes the feedback loop when connected to the Integrity Oracle.
        </p>
        <div className="loop-callout-grid">
          <article className="loop-callout-card">
            <h3><Shield size={16} /> 1. Sovereign Endpoint Defense</h3>
            <p>
              Shield operates 100% offline and standalone. It evaluates Linux kernel events, socket connections, and process spawns in microseconds, executes local containment, and writes tamper-evident Ed25519 hash-chained logs without requiring cloud infrastructure.
            </p>
          </article>
          <article className="loop-callout-card">
            <h3><Radar size={16} /> 2. Physical Plant Sensor (y = C x + v)</h3>
            <p>
              In an Integrity-governed fleet, Shield sits alongside the agent workload, observing ground truth via /proc/net/tcp and eBPF sensors. It captures physical execution state independently of what the agent or LLM claims it did.
            </p>
          </article>
          <article className="loop-callout-card">
            <h3><Sliders size={16} /> 3. Fail-Closed Actuator (Physical Containment)</h3>
            <p>
              When an Integrity boundary hook evaluates constraint vector C and reverts, software guardrails fail to stop executing threads. Shield enforces physical reality: dropping network egress via nftables, freezing cgroups, and halting rogue processes.
            </p>
          </article>
          <article className="loop-callout-card">
            <h3><ShieldCheck size={16} /> 4. Evidence Feedback to Oracle</h3>
            <p>
              Shield emits cryptographically signed evidence spans to the Integrity Oracle. The Oracle updates the Autonomous Integrity Score (AIS), adjusts adaptive gains, and anchors Merkle roots to the settlement chain—closing the control loop.
            </p>
          </article>
        </div>
      </section>

      <section className="landing-install" id="install" aria-labelledby="install-heading">
        <div className="landing-section-copy">
          <p className="eyebrow"><span aria-hidden="true" /> DEPLOYMENT &amp; QUICKSTART</p>
          <h2 id="install-heading">Install Shield on any <em>Linux host or cluster.</em></h2>
          <p>
            Shield operates as an independent, self-contained endpoint defense agent. Whether deployed as a hardened systemd daemon on bare-metal servers, containerized on Kubernetes edge nodes, or run via CLI on developer workstations, Shield brings kernel-level visibility and fail-closed containment to your infrastructure—operating standalone out of the box or feeding ground-truth evidence into the Integrity Protocol.
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
                <b>100% Standalone &amp; Protocol-Ready</b>
                <span>Full OPA policy execution and local containment operate offline, while evidence spans cleanly feed the Integrity Oracle.</span>
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

      <section className="landing-response" id="assurance" aria-labelledby="assurance-heading">
        <div className="landing-section-copy">
          <p className="eyebrow"><span aria-hidden="true" /> PROOF-GATED CONTAINMENT &amp; OPERATIONAL ASSURANCE</p>
          <h2 id="assurance-heading">Cryptographically gated response. <em>Operational assurance by design.</em></h2>
          <p>
            Powerful containment responders are never enabled by a configuration toggle alone. Every enforcement action requires valid runtime evidence, verified Ed25519 identity, signed policy locks, and quorum approval. In production, Shield restricts every mitigation to the smallest justified boundary with guaranteed rollback.
          </p>
        </div>
        <MermaidDiagram chart={RESPONSE_FLOW} label="Proof-gated responder readiness and containment execution lifecycle" />
        <p className="diagram-caption"><LockKeyhole size={14} /> Any missing, stale, or device-mismatched proof keeps the responder strictly unavailable.</p>

        <div className="assurance-grid">
          <div className="assurance-card">
            <SquareTerminal size={20} className="assurance-icon" aria-hidden="true" />
            <h3>Local-First Containment</h3>
            <p>Sensing, policy evaluation, and containment run directly on the host plant in microseconds with zero cloud latency.</p>
          </div>
          <div className="assurance-card">
            <FileCheck2 size={20} className="assurance-icon" aria-hidden="true" />
            <h3>Cryptographic Audit</h3>
            <p>Decisions and outcomes carry durable Ed25519 hash-chain evidence and correlation nonces for forensic playback.</p>
          </div>
          <div className="assurance-card">
            <Crosshair size={20} className="assurance-icon" aria-hidden="true" />
            <h3>Surgically Scoped</h3>
            <p>Mitigations target a specific PID, cgroup v2 controller, or destination network packet—never whole-node kill.</p>
          </div>
          <div className="assurance-card">
            <RotateCcw size={20} className="assurance-icon" aria-hidden="true" />
            <h3>Reversible Fail-Closed</h3>
            <p>Non-destructive actions (SIGSTOP, cgroup freeze, nftables block) support instant rollback; destructive steps require quorum.</p>
          </div>
        </div>
      </section>

      <section className="landing-agent-security" id="agent-security" aria-labelledby="agent-security-heading">
        <div className="agent-security-intro">
          <p className="eyebrow"><span aria-hidden="true" /> DUAL-LAYER PROTECTION</p>
          <h2 id="agent-security-heading">One security boundary across agent intent and host execution.</h2>
          <p>
            Autonomous reinforcement learning agents reason in software, but their consequences occur in the OS kernel. Traditional guardrails inspect prompts but cannot see process forks; traditional EDR monitors syscalls but lacks LLM intent context. Shield unifies both into a single, closed security boundary.
          </p>
        </div>

        <MermaidDiagram chart={DUAL_LAYER_FLOW} label="Shield dual-layer security boundary: Correlating semantic intent with kernel execution reality" />

        <div className="dual-layer-pillars">
          <article className="dual-pillar-card">
            <div className="dual-pillar-header">
              <span className="dual-pillar-badge">LAYER 1 · PRE-ACTION BOUNDARY</span>
              <Workflow size={20} aria-hidden="true" />
            </div>
            <h3>Semantic Intent Gate</h3>
            <p className="dual-pillar-desc">
              Intercepts tool proposals, prompt ingress, and model outputs before execution begins. Deterministic OPA policies verify arguments, model parameters, and access privileges in sub-2ms.
            </p>
            <ul className="dual-pillar-list">
              <li>
                <CheckCircle2 size={15} aria-hidden="true" />
                <span><b>Tool Argument Validation:</b> Enforces strict schemas on bash commands, file paths, and network URIs.</span>
              </li>
              <li>
                <CheckCircle2 size={15} aria-hidden="true" />
                <span><b>Context Taint Guard:</b> Intercepts adversarial prompt injections and untrusted context before model ingestion.</span>
              </li>
              <li>
                <CheckCircle2 size={15} aria-hidden="true" />
                <span><b>Fail-Closed Runtime Gate:</b> Rejects unauthorized intents at the agent wrapper before any OS syscall occurs.</span>
              </li>
            </ul>
          </article>

          <article className="dual-pillar-card">
            <div className="dual-pillar-header">
              <span className="dual-pillar-badge">LAYER 2 · POST-ACTION BOUNDARY</span>
              <Terminal size={20} aria-hidden="true" />
            </div>
            <h3>Kernel Execution Enforcer</h3>
            <p className="dual-pillar-desc">
              Observes physical execution state at the Linux kernel boundary via eBPF probes and procfs. If an executing thread escapes software sandboxes, Shield enforces boundary reality on the host plant.
            </p>
            <ul className="dual-pillar-list">
              <li>
                <CheckCircle2 size={15} aria-hidden="true" />
                <span><b>eBPF CO-RE Telemetry:</b> Captures process forks, file descriptor writes, and raw socket connections.</span>
              </li>
              <li>
                <CheckCircle2 size={15} aria-hidden="true" />
                <span><b>Reversible Host Containment:</b> Freezes cgroup v2 slices, sends SIGSTOP, and drops unauthorized egress via nftables.</span>
              </li>
              <li>
                <CheckCircle2 size={15} aria-hidden="true" />
                <span><b>Independent Plant Authority:</b> Operates with kernel capabilities (CAP_BPF, CAP_NET_ADMIN)—cannot be prompt-jailbroken.</span>
              </li>
            </ul>
          </article>
        </div>

        <div className="dual-layer-deck">
          <div className="dual-deck-card">
            <Fingerprint size={18} aria-hidden="true" />
            <h4>Invocation Correlation</h4>
            <p>Stable nonces cryptographically bind every eBPF syscall back to the specific agent session, prompt token, and tool call.</p>
          </div>
          <div className="dual-deck-card">
            <FileCheck2 size={18} aria-hidden="true" />
            <h4>Deterministic Policy Engine</h4>
            <p>Unified OPA bundles evaluate both semantic tool schemas and kernel-level network/process rules without drift.</p>
          </div>
          <div className="dual-deck-card">
            <LockKeyhole size={18} aria-hidden="true" />
            <h4>Ed25519 Hash-Chained Logs</h4>
            <p>Every intent proposal, policy verdict, and kernel containment event is signed locally into tamper-evident ledgers.</p>
          </div>
          <div className="dual-deck-card">
            <Cpu size={18} aria-hidden="true" />
            <h4>Closed-Loop Feedback</h4>
            <p>Signed execution evidence publishes to the Integrity Oracle to update trust scores and eliminate reward hacking.</p>
          </div>
        </div>
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
          </div>

          {/* Platform Navigation */}
          <div className="footer-links">
            <p className="footer-col-title">Platform</p>
            <a href="#architecture">Architecture</a>
            <a href="#agent-security">Agent Security</a>
            <a href="#install">Quickstart</a>
            <button onClick={next} className="footer-console-btn">
              Operator Console <ArrowRight size={11} aria-hidden="true" />
            </button>
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
            &copy; {new Date().getFullYear()} Xibalba Shield. All rights reserved.
          </div>
        </div>
      </footer>
    </main>
  )
}
