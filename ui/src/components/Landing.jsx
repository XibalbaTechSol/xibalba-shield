import { Activity, ArrowRight, Check, Crosshair, FileCheck2, Fingerprint, Globe2, LockKeyhole, Radar, RotateCcw, Shield, SquareTerminal } from 'lucide-react'
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
          <div className="footer-links"><h3>Platform</h3><a href="#platform">Capabilities</a><a href="#architecture">Architecture</a><a href="#responders">Responders</a></div>
          <div className="footer-links"><h3>Security</h3><a href="#proof">Trust model</a><a href="#assurance">Assurance</a><button onClick={next}>Operator console</button></div>
          <div className="footer-links"><h3>Operate</h3><a href="#architecture">Decision path</a><a href="#responders">Proof gates</a><button onClick={next}>Sign in</button></div>
        </div>
        <div className="footer-bottom"><small>© 2026 Xibalba Technology Solutions</small><span>Linux-first · Policy-driven · Evidence-backed</span></div>
      </footer>
    </main>
  )
}
