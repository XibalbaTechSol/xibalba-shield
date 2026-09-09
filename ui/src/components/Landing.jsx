import { Activity, ArrowRight, Check, Crosshair, FileCheck2, Fingerprint, Globe2, LockKeyhole, Radar, RotateCcw, Settings2, Shield, SquareTerminal, Workflow } from 'lucide-react'
import { Brand } from './Brand'
import { MermaidDiagram } from './MermaidDiagram'

const DECISION_FLOW = `flowchart LR
  A[Kernel telemetry<br/>process · file · network] --> B[Normalize<br/>deduplicate · enrich]
  B --> C{Local policy<br/>signed · deterministic}
  C -->|allow| D[Continue]
  C -->|contain| E[Bounded response]
  D --> F[Evidence receipt]
  E --> F
  F -. links to source .-> A`

const RESPONSE_FLOW = `flowchart LR
  A[Runtime probe] --> E{Every proof valid?}
  B[Device identity] --> E
  C[Policy signature] --> E
  D[Operator approval] --> E
  E -->|yes| F[Fresh readiness artifact]
  E -->|no| G[Fail closed]
  F --> H[Freeze cgroup]
  F --> I[Kill process]
  F --> J[Block network flow]`

const AGENT_FLOW = `flowchart LR
  A[Agent request] --> B[Ingress guardrail]
  B --> C[Model and retrieval checks]
  C --> D[Tool pre-action gate]
  D --> E[Kernel-observed execution]
  E --> F[Post-action verification]
  F --> G[Correlated evidence]
  H[Signed local policy] -. governs .-> B
  H -. governs .-> D
  I[Process · file · network sensors] -. observes .-> E`

export function Landing({ next }) {
  return (
    <main className="landing">
      <header className="site-header">
        <nav className="site-nav" aria-label="Main Navigation">
          <a className="brand-link" href="#top" aria-label="Xibalba Shield home"><Brand /></a>
          <div className="nav-links">
            <a href="#platform">Platform</a>
            <a href="#architecture">Architecture</a>
            <a href="#responders">Responders</a>
            <a href="#agent-security">Agent security</a>
            <a href="#assurance">Assurance</a>
          </div>
          <div className="nav-actions">
            <button className="quiet" onClick={next}>Sign in</button>
            <button className="primary" onClick={next}>Open console <ArrowRight aria-hidden="true" /></button>
          </div>
        </nav>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <img src="/shield-logo.png" alt="Shield Logo" className="hero-logo" />
          <p className="eyebrow">
            <span aria-hidden="true" /> LINUX-FIRST AGENT SECURITY
          </p>
          <h1>
            Trust every action.<br />
            <em>Contain every threat.</em>
          </h1>
          <p className="lede">
            Observe, evaluate, and enforce policy at the edge—a verifiable security boundary built for autonomous agents.
          </p>
          <div className="hero-actions">
            <button className="primary big" onClick={next}>
              Explore the console <ArrowRight aria-hidden="true" />
            </button>
            <a href="#platform" className="learn-more-link">See how it works</a>
          </div>
          <div className="checks">
            <span><Check aria-hidden="true" /> Kernel telemetry</span>
            <span><Check aria-hidden="true" /> Signed policies</span>
            <span><Check aria-hidden="true" /> Receipt-backed enforcement</span>
          </div>
        </div>

        <div className="hero-art" aria-hidden="true">
          <div className="ring r1" />
          <div className="ring r2" />
          <div className="core">
            <Shield />
            <b>Policy verified</b>
          </div>
          <div className="signal s1">
            <Activity />
            <span>Process event<b>Allowed</b></span>
          </div>
          <div className="signal s2">
            <LockKeyhole />
            <span>Write attempt<b>Contained</b></span>
          </div>
          <div className="signal s3">
            <Globe2 />
            <span>Network call<b>Verified</b></span>
          </div>
        </div>
      </section>

      <section className="proof" id="proof" aria-label="Key architectural properties">
        <div>
          <b>Kernel-level</b>
          <span>eBPF sensor coverage</span>
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

      <section className="landing-architecture" id="architecture" aria-labelledby="architecture-heading">
        <div className="landing-section-copy"><h2 id="architecture-heading">From kernel telemetry to <em>provable action.</em></h2><p>Shield turns low-level Linux signals into high-confidence decisions on the host. The local policy path remains independent of cloud availability; evidence export happens after the decision.</p></div>
        <MermaidDiagram chart={DECISION_FLOW} label="Shield telemetry, local policy, containment, and evidence flow" />
      </section>

      <section className="landing-response" id="responders" aria-labelledby="response-heading">
        <div className="landing-section-copy"><h2 id="response-heading">A <em>proof-gated</em> response lifecycle.</h2><p>Powerful responders are never enabled by a UI switch or configuration flag alone. Runtime evidence, identity, policy integrity, rollback validation, audit delivery, and approval must all be current.</p></div>
        <MermaidDiagram chart={RESPONSE_FLOW} label="Proof-gated responder readiness flow" />
        <p className="diagram-caption"><LockKeyhole size={14} /> Any missing, stale, or device-mismatched proof keeps the responder unavailable.</p>
      </section>

      <section className="landing-assurance" id="assurance" aria-labelledby="assurance-heading">
        <div><h2 id="assurance-heading">Operational assurance by design.</h2><p>Security that stays close to the workload, records what happened, and limits every response to the smallest justified boundary.</p></div>
        <div className="assurance-rows">
          {[[SquareTerminal, 'Local-first', 'Sensing, policy evaluation, and containment run on the host.'], [FileCheck2, 'Auditable', 'Decisions and outcomes carry durable evidence and correlation.'], [Crosshair, 'Scoped', 'Responses target a process, cgroup, or exact destination flow.'], [RotateCcw, 'Reversible', 'Safe actions support rollback; destructive actions require approval.']].map(([Icon, title, text]) => <div key={title}><Icon /><b>{title}</b><span>{text}</span></div>)}
        </div>
      </section>

      <section className="landing-agent-security" id="agent-security" aria-labelledby="agent-security-heading">
        <div className="agent-security-intro">
          <div><Shield aria-hidden="true" /><h2 id="agent-security-heading">One security boundary across agent intent and host execution.</h2></div>
          <p>Shield protects autonomous systems at two layers. Semantic guardrails inspect what an agent is attempting to do, while Linux sensors observe what actually reaches the operating system. A local deterministic policy engine connects both views without putting cloud inference in the enforcement path.</p>
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
          <h2>Put your agent fleet behind a verifiable boundary.</h2><p>Start with visibility. Promote responders only when their evidence is complete.</p>
        </div>
        <button onClick={next} className="cta-btn">
          Open Shield <ArrowRight aria-hidden="true" />
        </button>
      </section>

      <footer className="site-footer">
        <div className="footer-main">
          <div className="footer-brand"><Brand /><p>Deterministic endpoint security for autonomous systems—local decisions, bounded response, verifiable outcomes.</p><span><span className="status-dot green" /> Local-first by design</span></div>
          <div className="footer-links"><h3>Platform</h3><a href="#platform">Capabilities</a><a href="#architecture">Architecture</a><a href="#agent-security">Agent security</a></div>
          <div className="footer-links"><h3>Security</h3><a href="#proof">Trust model</a><a href="#assurance">Assurance</a><button onClick={next}>Operator console</button></div>
          <div className="footer-links"><h3>Operate</h3><a href="#architecture">Decision path</a><a href="#responders">Proof gates</a><button onClick={next}>Sign in</button></div>
        </div>
        <div className="footer-bottom"><small>© 2026 Xibalba Technology Solutions</small><span>Linux-first · Policy-driven · Evidence-backed</span></div>
      </footer>
    </main>
  )
}
