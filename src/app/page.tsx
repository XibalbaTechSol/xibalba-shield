'use client';
import { useState, useCallback } from 'react';
import Link from 'next/link';

interface UseCase {
  id: string;
  icon: string;
  title: string;
  category: 'clinics' | 'hospitals';
  scope: string;
  complianceMethod: string;
  description: string;
  uniqueId: string;
}

const useCasesData: UseCase[] = [
  {
    id: 'scribe',
    icon: '🎙️',
    title: 'Ambient Scribe Redaction',
    category: 'clinics',
    scope: 'Clinics & Startups',
    complianceMethod: 'Anonymized ✓',
    description: 'Ambient clinical scribes record doctor-patient room conversations. Xibalba Shield intercepts voice transcripts locally, securely isolates the Protected Health Information (PHI) in your private database, and anchors a cryptographically shielded verification hash to the blockchain.',
    uniqueId: 'uc-scribe'
  },
  {
    id: 'rpm',
    icon: '⌚',
    title: 'Outpatient Wearable RPM',
    category: 'clinics',
    scope: 'Rural & Community Clinics',
    complianceMethod: 'Continuous Telemetry ✓',
    description: 'Continuous streaming data from outpatient wearables (glucose monitors, ECGs, pacemakers) is securely ingested. Xibalba Shield processes raw events through a local micro-shield, logging epoch validity hashes to the chain while keeping patient health factors hidden.',
    uniqueId: 'uc-rpm'
  },
  {
    id: 'support',
    icon: '🤖',
    title: 'Conversational Support Intake',
    category: 'clinics',
    scope: 'Support Channels',
    complianceMethod: 'SBT Gated ✓',
    description: 'Prevents conversational care bots from inadvertently releasing medical summaries during patient chat loops. Verified Soulbound Reputation Tokens (ReputationSBT.sol) authorize access rights instantly prior to context window assembly.',
    uniqueId: 'uc-support'
  },
  {
    id: 'pharmacy',
    icon: '💊',
    title: 'Pharmacy Dispensing Checker',
    category: 'clinics',
    scope: 'Clinical Pharmacies',
    complianceMethod: 'Collateralized ✓',
    description: 'Real-time validation of AI prescription and dosage checkers. If the model hallucinates drug-drug interactions or overrides clinician warnings, a protocol exception is logged and model collateral is automatically slashed.',
    uniqueId: 'uc-pharmacy'
  },
  {
    id: 'telehealth',
    icon: '🌐',
    title: 'Cross-Border Telemedicine',
    category: 'clinics',
    scope: 'Telehealth Networks',
    complianceMethod: 'Multi-State Safe ✓',
    description: 'Multi-state outpatient networks must navigate varied state-level medical disclosure laws. Xibalba Shield evaluates smart contract compliance rules automatically during clinical sessions, dynamically adapting model parameters or blocking disclosure triggers according to local regulations.',
    uniqueId: 'uc-telehealth'
  },
  {
    id: 'ehr',
    icon: '🏢',
    title: 'Hospital-Wide EHR Audits',
    category: 'hospitals',
    scope: 'Hospital Networks',
    complianceMethod: 'Audit Ready ✓',
    description: 'Major hospital networks running clinical decision AI systems utilize our federated ledger. The system aggregates massive access histories from centralized Electronic Health Records (EHR) into unified compliance trees. Internal teams can run full audits on millions of patient file pointer queries within seconds.',
    uniqueId: 'uc-ehr'
  },
  {
    id: 'triage',
    icon: '🏥',
    title: 'Emergency Department Triage',
    category: 'hospitals',
    scope: 'Acute Care Clinics',
    complianceMethod: 'Real-time Alerts ✓',
    description: 'Emergency clinics leveraging automated intake AI require rigorous safety assurance. Our smart contracts record patient intake classification events on the blockchain. If triage recommendations fail severe case detection constraints, the system alerts the ED compliance staff and blocks deployment dynamically.',
    uniqueId: 'uc-triage'
  },
  {
    id: 'icu',
    icon: '🫁',
    title: 'ICU Predictive Safeguards',
    category: 'hospitals',
    scope: 'Tertiary Care Hospitals',
    complianceMethod: 'Decisional Guardrails ✓',
    description: 'Protects deep learning algorithms predicting sepsis, cardiac arrest, or lung ventilation settings in high-stress ICU environments. System monitors prediction thresholds on-chain, triggering automated clinician overrides and logging logs to prevent algorithmic drifts.',
    uniqueId: 'uc-icu'
  },
  {
    id: 'trials',
    icon: '🔬',
    title: 'Clinical Trial Cohort Selection',
    category: 'hospitals',
    scope: 'Research Clinics & Pharma',
    complianceMethod: 'ZK Cohorts ✓',
    description: 'AI oncology cohort selection screening strict clinical exclusion criteria against massive EHR datasets. Patient details are completely blinded via zero-knowledge proofs, enabling verification that selected cohorts match trial parameters without exposing individual patient records.',
    uniqueId: 'uc-trials'
  },
  {
    id: 'radiology',
    icon: '🩻',
    title: 'Radiology Metadata Shield',
    category: 'hospitals',
    scope: 'Imaging & Diagnostics',
    complianceMethod: 'Metadata Stripped ✓',
    description: 'Clinical imaging scans (MRI, CT, Pathology) are evaluated by diagnostic AI co-pilots. Xibalba Shield strips embedded Patient Names, birthdates, and internal IDs from DICOM metadata fields prior to external LLM analysis, replacing them with a secure hash anchor.',
    uniqueId: 'uc-radiology'
  },
  {
    id: 'billing',
    icon: '📊',
    title: 'Autonomous Coding & Billing',
    category: 'hospitals',
    scope: 'Hospital Billing Departments',
    complianceMethod: 'Collateralized ✓',
    description: 'High-volume ICD-10 medical coding models can hallucinate diagnostic protocols. StakingReputation.sol binds the billing model directly to an active ITK collateral pool. Validation failures immediately slash staked collateral to enforce model precision and combat billing fraud.',
    uniqueId: 'uc-billing'
  }
];

const contractExplanations = {
  sbt: {
    title: "Soulbound Credentials",
    subtitle: "ReputationSBT.sol — Gating Protocol",
    description: "Every clinical AI agent is represented on-chain by a non-transferable Soulbound Token (SBT) containing verified reputation vectors. If metrics fall below secure levels, the edge gateway blocks inference access instantly.",
    bullets: [
      {
        title: "Gas-Optimized Metric Packing",
        detail: "Packs accuracy, privacy, and reliability scores as uint8 with uint32 timestamps inside a single 256-bit EVM word, cutting L2 gas storage operations."
      },
      {
        title: "Pre-Inference Gating Check",
        detail: "The Edge SDK queries ReputationSBT vectors before allowing model inference. Out-of-bounds models are blocked from loading clinical patient summaries."
      },
      {
        title: "Transfer-Locked Identity",
        detail: "Overrides the ERC-721 token update pipeline to strictly prohibit transfers, preventing model credentials and compliance records from being traded."
      }
    ]
  },
  audit: {
    title: "Immutable Compliance",
    subtitle: "AuditShield.sol — Cryptographic Logs",
    description: "Traditional clinical logs are vulnerable to unauthorized revisions or deletion. AuditShield secures blinded patient note hashes directly to the block ledger, ensuring a tamper-proof HIPAA audit trail.",
    bullets: [
      {
        title: "Blinded Data Anchoring",
        detail: "Stores only SHA-256 hashes generated client-side with dynamic salting. Identifiable patient details never touch public networks or block records."
      },
      {
        title: "Anti-Forging Hash Mapping",
        detail: "Strict mappings prevent duplicate hashes from being registered, securing the audit ledger against transaction replays or historical modifications."
      },
      {
        title: "Zero-Disclosure Audits",
        detail: "Compliance officers can easily reconcile records offline by rehashing database charts and querying AuditShield to verify log timestamps."
      }
    ]
  },
  staking: {
    title: "Economic Alignment",
    subtitle: "StakingReputation.sol — SLA Escrow",
    description: "To ensure third-party AI models remain strictly aligned with hospital clinical safety guidelines, developers stake $ITK tokens as financial collateral. Hallucinations trigger automatic slashing.",
    bullets: [
      {
        title: "$ITK Token Escrow Pools",
        detail: "Model developers lock ERC-20 ITK tokens into the contract as financial collateral to authorize their SovereignAgent for hospital clinical use."
      },
      {
        title: "Dynamic Penalty Slashing",
        detail: "Safety exceptions, high-impact clinical overrides, or billing hallucinations trigger automated slash functions, executing prompt penalty payments."
      },
      {
        title: "Risk Insurance Model",
        detail: "Bridges blockchain mechanics with traditional hospital risk mitigation, allowing clinical systems to scale AI usage under safe, bound terms."
      }
    ]
  },
  sdk: {
    title: "Type-Safe Edge SDK",
    subtitle: "xibalba-shield-sdk.ts — Edge Firewall",
    description: "Our edge SDK intercepts model queries pre-inference. It isolates raw Patient Health Information (PHI) inside your local DB, blinds clinical notes, and gates model execution using live SBT scores.",
    bullets: [
      {
        title: "Local PHI Data Blinding",
        detail: "Computes cryptographic proof hashes locally inside the client's private server environment. Patient PHI never traverses the public network interface."
      },
      {
        title: "Pre-Inference SBT Gateway",
        detail: "Integrates directly with live smart contracts to query accuracy, privacy, and reliability. Throws immediate exceptions if scores fail custom thresholds."
      },
      {
        title: "Gasless Paymaster Logging",
        detail: "Supports seamless ERC-4337 paymaster gas abstraction on the ITK testnet, allowing clinical nodes to anchor compliance logs without wallet prompts."
      }
    ]
  }
};

export default function Home() {
  // Modal & Flow states
  const [authModal, setAuthModal] = useState<'signin' | 'signup' | null>(null);
  const [checkoutPlan, setCheckoutPlan] = useState<{ name: string; price: string } | null>(null);
  const [useCaseCategory, setUseCaseCategory] = useState<'all' | 'clinics' | 'hospitals'>('all');
  const [activeContract, setActiveContract] = useState<'sbt' | 'audit' | 'staking' | 'sdk'>('sbt');
  const [isSignedIn, setIsSignedIn] = useState(false);
  const [userEmail, setUserEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [cardNumber, setCardNumber] = useState('');
  const [cardExpiry, setCardExpiry] = useState('');
  const [cardCvc, setCardCvc] = useState('');
  const [checkoutSuccess, setCheckoutSuccess] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const [checkoutLoading, setCheckoutLoading] = useState(false);

  // Authentication simulator
  const handleAuth = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    setAuthLoading(true);
    setTimeout(() => {
      setAuthLoading(false);
      setIsSignedIn(true);
      setAuthModal(null);
    }, 1200);
  }, []);

  // Checkout simulator
  const handleCheckout = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    setCheckoutLoading(true);
    setTimeout(() => {
      setCheckoutLoading(false);
      setCheckoutSuccess(true);
      setTimeout(() => {
        setCheckoutPlan(null);
        setCheckoutSuccess(false);
        // Clear card details
        setCardNumber('');
        setCardExpiry('');
        setCardCvc('');
      }, 2000);
    }, 2000);
  }, []);

  const logout = useCallback(() => {
    setIsSignedIn(false);
    setUserEmail('');
    setUsername('');
    setPassword('');
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 font-sans relative selection:bg-teal-500 selection:text-white">
      {/* Premium Header */}
      <header className="sticky top-0 z-40 w-full bg-white/80 backdrop-blur-md border-b border-slate-200 px-6 py-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <span className="w-3.5 h-3.5 rounded-full bg-teal-500 animate-pulse" />
            <span className="text-xl font-bold tracking-tight text-slate-900">
              Xibalba <span className="text-teal-600">Shield</span>
            </span>
          </div>

          <nav className="hidden md:flex space-x-8 text-sm font-semibold text-slate-500">
            <a href="#how-it-works" className="hover:text-teal-600 transition-colors">How It Works</a>
            <a href="#use-cases" className="hover:text-teal-600 transition-colors">HIPAA Use Cases</a>
            <a href="#pricing" className="hover:text-teal-600 transition-colors">Pricing</a>
          </nav>

          <div className="flex items-center space-x-4">
            {isSignedIn ? (
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium text-slate-600">
                  Hi, <span className="text-teal-600 font-semibold">{username || userEmail || 'Operator'}</span>
                </span>
                <Link href="/dashboard" className="text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 px-4 py-2 rounded-lg shadow-sm transition-all">
                  Dashboard
                </Link>
                <button onClick={logout} className="text-sm font-semibold text-slate-500 hover:text-red-500 transition-colors">
                  Log Out
                </button>
              </div>
            ) : (
              <>
                <button onClick={() => setAuthModal('signin')} className="text-sm font-semibold text-slate-600 hover:text-teal-600 transition-colors">
                  Sign In
                </button>
                <button onClick={() => setAuthModal('signup')} className="text-sm font-semibold text-white bg-teal-600 hover:bg-teal-700 px-4 py-2 rounded-lg shadow-sm transition-all">
                  Sign Up
                </button>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden bg-white py-24 px-6 border-b border-slate-200">
        <div className="max-w-5xl mx-auto text-center relative z-10">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-teal-50 text-teal-700 border border-teal-200 mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-teal-500" />
            HIPAA Compliant & Fully Audited B2B SaaS
          </span>
          <h1 className="text-5xl md:text-6xl font-extrabold tracking-tight text-slate-900 mb-6 leading-tight">
            Compliance-as-a-Service for <br />
            <span className="bg-gradient-to-r from-teal-600 to-cyan-600 bg-clip-text text-transparent">AI Healthcare Startups</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-500 max-w-3xl mx-auto mb-10 leading-relaxed">
            Stochastic AI models fail traditional security boundaries. Xibalba Shield enforces hard mathematical guardrails on the blockchain, preventing Protected Health Information (PHI) leaks and agent hallucinations.
          </p>
          <div className="flex flex-col sm:flex-row justify-center items-center gap-4">
            <a href="#pricing" className="w-full sm:w-auto px-8 py-4 bg-teal-600 text-white rounded-lg font-bold shadow-md hover:bg-teal-700 transition-all text-center">
              Start Free Trial
            </a>
            <a href="#how-it-works" className="w-full sm:w-auto px-8 py-4 bg-slate-100 text-slate-700 rounded-lg font-bold hover:bg-slate-200 transition-all text-center">
              Explore Architecture
            </a>
          </div>
        </div>
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />
      </section>

      {/* HIPAA Use Cases Section */}
      <section id="use-cases" className="py-24 px-6 bg-slate-50 border-b border-slate-200">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-teal-50 text-teal-700 border border-teal-200 mb-4">
              <span className="w-1.5 h-1.5 rounded-full bg-teal-500 animate-pulse" />
              Versatile Regulatory Compliance
            </span>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight text-slate-900 mb-4">HIPAA & Clinical Safety Use Cases</h2>
            <p className="text-slate-500 max-w-2xl mx-auto text-sm md:text-base">
              A mathematically-proven framework designed to protect PHI and enforce model alignment across any healthcare organization.
            </p>
          </div>

          {/* Interactive Filtering Tabs */}
          <div className="flex justify-center mb-12">
            <div className="bg-slate-200/80 p-1.5 rounded-xl flex space-x-1.5 border border-slate-300/40">
              <button
                id="filter-all"
                onClick={() => setUseCaseCategory('all')}
                className={`px-5 py-2.5 rounded-lg text-xs md:text-sm font-semibold tracking-tight transition-all duration-200 cursor-pointer ${
                  useCaseCategory === 'all'
                    ? 'bg-teal-600 text-white shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                All Organizations
              </button>
              <button
                id="filter-clinics"
                onClick={() => setUseCaseCategory('clinics')}
                className={`px-5 py-2.5 rounded-lg text-xs md:text-sm font-semibold tracking-tight transition-all duration-200 cursor-pointer ${
                  useCaseCategory === 'clinics'
                    ? 'bg-teal-600 text-white shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Clinics & Outpatient Care
              </button>
              <button
                id="filter-hospitals"
                onClick={() => setUseCaseCategory('hospitals')}
                className={`px-5 py-2.5 rounded-lg text-xs md:text-sm font-semibold tracking-tight transition-all duration-200 cursor-pointer ${
                  useCaseCategory === 'hospitals'
                    ? 'bg-teal-600 text-white shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Hospitals & Enterprise Systems
              </button>
            </div>
          </div>

          {/* Dynamic Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 transition-all duration-300">
            {useCasesData
              .filter(uc => useCaseCategory === 'all' || uc.category === useCaseCategory)
              .map((uc) => (
                <div
                  key={uc.id}
                  id={uc.uniqueId}
                  className="bg-white p-8 rounded-xl shadow-sm border border-slate-200 flex flex-col justify-between hover:shadow-md hover:-translate-y-1 transition-all duration-300 group"
                >
                  <div>
                    <span className="text-4xl mb-5 block transform group-hover:scale-110 transition-transform duration-200">{uc.icon}</span>
                    <h3 className="text-lg font-bold text-slate-800 mb-3 group-hover:text-teal-600 transition-colors">{uc.title}</h3>
                    <p className="text-xs md:text-[13px] text-slate-500 leading-relaxed mb-6">
                      {uc.description}
                    </p>
                  </div>
                  <div className="text-xs font-bold text-teal-600 uppercase tracking-wider border-t border-slate-100 pt-4 flex justify-between items-center">
                    <span className="bg-teal-50 text-teal-700 px-2.5 py-1 rounded-md text-[10px] border border-teal-100">
                      {uc.scope}
                    </span>
                    <span className="text-[10px] bg-slate-100 text-slate-700 px-2 py-0.5 rounded font-mono">
                      {uc.complianceMethod}
                    </span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-24 px-6 bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight text-slate-900 mb-4">Zero-Knowledge Compliance Flow</h2>
            <p className="text-slate-500">From the moment your clinical scribe records an event to the final on-chain verification.</p>
          </div>

          <div className="space-y-12 relative before:absolute before:inset-0 before:left-4 md:before:left-1/2 before:w-0.5 before:bg-slate-200 before:h-full">
            {/* Step 1 */}
            <div className="relative flex flex-col md:flex-row items-center md:justify-between group">
              <div className="absolute left-4 md:left-1/2 w-8 h-8 rounded-full bg-teal-500 border-4 border-white transform -translate-x-1/2 flex items-center justify-center text-xs font-bold text-white shadow-sm">1</div>
              <div className="w-full md:w-[45%] pl-12 md:pl-0 md:text-right">
                <h4 className="text-lg font-bold text-slate-800 mb-2">On-Chain Identity Binding</h4>
                <p className="text-sm text-slate-500">
                  Deploy a unique `SovereignAgent` contract for your AI model. This converts your stochastic system into a firm, verifiable asset bound to a designated compliance reputation score on the ITK Testnet.
                </p>
              </div>
              <div className="hidden md:block w-[45%]" />
            </div>

            {/* Step 2 */}
            <div className="relative flex flex-col md:flex-row items-center md:justify-between group">
              <div className="absolute left-4 md:left-1/2 w-8 h-8 rounded-full bg-teal-500 border-4 border-white transform -translate-x-1/2 flex items-center justify-center text-xs font-bold text-white shadow-sm">2</div>
              <div className="hidden md:block w-[45%]" />
              <div className="w-full md:w-[45%] pl-12 md:pl-12">
                <h4 className="text-lg font-bold text-slate-800 mb-2">Blind Inference & Hashing</h4>
                <p className="text-sm text-slate-500">
                  The raw PHI notes are retained inside your local database. A secure backend utility generates a cryptographic SHA-256 hash containing only the transaction reference ID, prompt guidelines, and non-identifiable parameters.
                </p>
              </div>
            </div>

            {/* Step 3 */}
            <div className="relative flex flex-col md:flex-row items-center md:justify-between group">
              <div className="absolute left-4 md:left-1/2 w-8 h-8 rounded-full bg-teal-500 border-4 border-white transform -translate-x-1/2 flex items-center justify-center text-xs font-bold text-white shadow-sm">3</div>
              <div className="w-full md:w-[45%] pl-12 md:pl-0 md:text-right">
                <h4 className="text-lg font-bold text-slate-800 mb-2">SBT Reputation Check</h4>
                <p className="text-sm text-slate-500">
                  The Xibalba Shield gateway queries the local smart contract directory. If your agent's `ReputationSBT` contains an active status and score above 80, the request pipeline passes through the firewall instantly.
                </p>
              </div>
              <div className="hidden md:block w-[45%]" />
            </div>

            {/* Step 4 */}
            <div className="relative flex flex-col md:flex-row items-center md:justify-between group">
              <div className="absolute left-4 md:left-1/2 w-8 h-8 rounded-full bg-teal-500 border-4 border-white transform -translate-x-1/2 flex items-center justify-center text-xs font-bold text-white shadow-sm">4</div>
              <div className="hidden md:block w-[45%]" />
              <div className="w-full md:w-[45%] pl-12 md:pl-12">
                <h4 className="text-lg font-bold text-slate-800 mb-2">Immutable Audit Anchoring</h4>
                <p className="text-sm text-slate-500">
                  The L2 Paymaster contract automates gas payment using ITK tokens behind the scenes. `AuditShield.sol` locks the cryptographic hash onto the block ledger. Auditing teams can verify transactions offline at any point.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Smart Contracts & Cryptographic PHI Gating Section */}
      <section id="smart-contracts" className="py-24 px-6 bg-slate-900 text-white relative border-b border-slate-800">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            
            {/* Left Content Column (5 cols) */}
            <div className="lg:col-span-5 space-y-6">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-teal-500/10 text-teal-400 border border-teal-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse" />
                {contractExplanations[activeContract].subtitle}
              </span>
              <h2 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white leading-tight">
                {contractExplanations[activeContract].title} <br />
                <span className="bg-gradient-to-r from-teal-400 to-cyan-400 bg-clip-text text-transparent">PHI Access Gating</span>
              </h2>
              <p className="text-slate-400 text-sm md:text-base leading-relaxed">
                {contractExplanations[activeContract].description}
              </p>

              {/* Explanatory Steps (Dynamic) */}
              <div className="space-y-4 pt-4">
                {contractExplanations[activeContract].bullets.map((b, idx) => (
                  <div key={idx} className="flex gap-4 group">
                    <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-teal-500/15 border border-teal-500/30 flex items-center justify-center text-teal-400 font-mono font-bold text-sm group-hover:bg-teal-500/30 transition-all duration-200">
                      0{idx + 1}
                    </div>
                    <div>
                      <h4 className="font-bold text-white text-sm group-hover:text-teal-300 transition-colors">{b.title}</h4>
                      <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                        {b.detail}
                      </p>
                    </div>
                  </div>
                ))}
              </div>

              {/* SDK Download Actions */}
              <div className="pt-6 flex flex-col sm:flex-row gap-4">
                <a
                  href="/sdk/xibalba-shield-sdk.ts"
                  download="xibalba-shield-sdk.ts"
                  id="download-ts-sdk"
                  className="inline-flex items-center justify-center gap-2 px-5 py-3 bg-teal-600 hover:bg-teal-700 text-white rounded-lg font-bold text-xs shadow-md transition-all cursor-pointer"
                >
                  📥 Download Node/TS SDK
                </a>
                <button
                  onClick={() => alert('Python SDK (.whl / pip install xibalba-shield) bundle is auto-generating from the ledger. Mock download successful.')}
                  id="download-py-sdk"
                  className="inline-flex items-center justify-center gap-2 px-5 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-bold text-xs border border-slate-700 transition-all cursor-pointer"
                >
                  🐍 Download Python SDK
                </button>
              </div>
            </div>

            {/* Right Terminal Column (7 cols) */}
            <div className="lg:col-span-7">
              <div className="bg-slate-950 rounded-2xl border border-slate-800 shadow-2xl overflow-hidden flex flex-col h-[520px]">
                {/* Terminal Header */}
                <div className="bg-slate-900 px-5 py-4 border-b border-slate-800 flex justify-between items-center">
                  <div className="flex items-center space-x-2">
                    <span className="w-3 h-3 rounded-full bg-red-500/80" />
                    <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <span className="w-3 h-3 rounded-full bg-green-500/80" />
                    <span className="text-xs font-mono text-slate-500 ml-4 font-semibold">
                      {activeContract === 'sdk' ? 'xibalba-shield-sdk.ts' : activeContract === 'sbt' ? 'ReputationSBT.sol' : activeContract === 'audit' ? 'AuditShield.sol' : 'StakingReputation.sol'}
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-teal-400 bg-teal-500/10 border border-teal-500/20 px-2.5 py-0.5 rounded">
                    {activeContract === 'sdk' ? 'TYPESCRIPT SDK' : 'EVM COMPLIANT'}
                  </div>
                </div>

                {/* Contract Selection Tabs */}
                <div className="flex bg-slate-900/50 border-b border-slate-800/80 text-xs font-mono">
                  <button
                    onClick={() => setActiveContract('sbt')}
                    className={`px-5 py-3 border-r border-slate-800 transition-colors cursor-pointer ${
                      activeContract === 'sbt'
                        ? 'bg-slate-950 text-teal-400 border-t-2 border-t-teal-500'
                        : 'text-slate-500 hover:text-slate-300 bg-slate-900/30'
                    }`}
                  >
                    ReputationSBT.sol
                  </button>
                  <button
                    onClick={() => setActiveContract('audit')}
                    className={`px-5 py-3 border-r border-slate-800 transition-colors cursor-pointer ${
                      activeContract === 'audit'
                        ? 'bg-slate-950 text-teal-400 border-t-2 border-t-teal-500'
                        : 'text-slate-500 hover:text-slate-300 bg-slate-900/30'
                    }`}
                  >
                    AuditShield.sol
                  </button>
                  <button
                    onClick={() => setActiveContract('staking')}
                    className={`px-5 py-3 border-r border-slate-800 transition-colors cursor-pointer ${
                      activeContract === 'staking'
                        ? 'bg-slate-950 text-teal-400 border-t-2 border-t-teal-500'
                        : 'text-slate-500 hover:text-slate-300 bg-slate-900/30'
                    }`}
                  >
                    StakingReputation.sol
                  </button>
                  <button
                    onClick={() => setActiveContract('sdk')}
                    className={`px-5 py-3 border-r border-slate-800 transition-colors cursor-pointer ${
                      activeContract === 'sdk'
                        ? 'bg-slate-950 text-teal-400 border-t-2 border-t-teal-500'
                        : 'text-slate-500 hover:text-slate-300 bg-slate-900/30'
                    }`}
                  >
                    xibalba-shield-sdk.ts
                  </button>
                </div>

                {/* Terminal Editor View */}
                <div className="p-6 font-mono text-[11px] md:text-xs overflow-y-auto bg-slate-950 text-slate-300 flex-1 leading-relaxed selection:bg-teal-500/30">
                  {activeContract === 'sbt' && (
                    <pre className="text-teal-300/90">
{`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ReputationSBT is ERC721, Ownable {
    uint256 private _nextTokenId;

    struct ReputationMetrics {
        uint8 accuracy;    // Cognitive clinical precision (0-100)
        uint8 privacy;     // ZK edge boundary compliance (0-100)
        uint8 reliability; // Latency and uptime operational verification (0-100)
        uint32 lastUpdated;
    }

    mapping(uint256 => ReputationMetrics) public agentMetrics;

    event MetricsUpdated(uint256 indexed tokenId, uint8 accuracy, uint8 privacy, uint8 reliability, uint32 lastUpdated);

    constructor() ERC721("ReputationSBT", "RSBT") Ownable(msg.sender) {}

    function mint(address to, uint8 accuracy, uint8 privacy, uint8 reliability) external onlyOwner {
        uint256 tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        agentMetrics[tokenId] = ReputationMetrics({
            accuracy: accuracy,
            privacy: privacy,
            reliability: reliability,
            lastUpdated: uint32(block.timestamp)
        });
        emit MetricsUpdated(tokenId, accuracy, privacy, reliability, uint32(block.timestamp));
    }

    function updateMetrics(uint256 tokenId, uint8 accuracy, uint8 privacy, uint8 reliability) external onlyOwner {
        require(_ownerOf(tokenId) != address(0), "Nonexistent token");
        agentMetrics[tokenId] = ReputationMetrics({
            accuracy: accuracy,
            privacy: privacy,
            reliability: reliability,
            lastUpdated: uint32(block.timestamp)
        });
        emit MetricsUpdated(tokenId, accuracy, privacy, reliability, uint32(block.timestamp));
    }

    // SBT logic: Non-transferable identity anchoring
    function _update(address to, uint256 tokenId, address auth) internal virtual override returns (address) {
        address from = _ownerOf(tokenId);
        require(from == address(0) || to == address(0), "SBT: Transfer not allowed");
        return super._update(to, tokenId, auth);
    }
}`}
                    </pre>
                  )}

                  {activeContract === 'audit' && (
                    <pre className="text-cyan-300/90">
{`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AuditShield {
    struct LogEntry {
        bytes32 dataHash;
        address agent;
        uint256 timestamp;
    }

    mapping(bytes32 => LogEntry) public auditLogs;

    event LogAnchored(bytes32 indexed dataHash, address indexed agent, uint256 timestamp);

    function anchorLog(bytes32 _dataHash) external {
        require(auditLogs[_dataHash].timestamp == 0, "Log already anchored");
        
        auditLogs[_dataHash] = LogEntry({
            dataHash: _dataHash,
            agent: msg.sender,
            timestamp: block.timestamp
        });

        emit LogAnchored(_dataHash, msg.sender, block.timestamp);
    }
}`}
                    </pre>
                  )}

                  {activeContract === 'staking' && (
                    <pre className="text-emerald-300/90">
{`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract StakingReputation is Ownable {
    IERC20 public itkToken;
    mapping(address => uint256) public stakes;

    event Staked(address indexed agent, uint256 amount);
    event Slashed(address indexed agent, uint256 amount, string reason);

    constructor(address _itkToken) Ownable(msg.sender) {
        itkToken = IERC20(_itkToken);
    }

    function stake(uint256 amount) external {
        require(itkToken.transferFrom(msg.sender, address(this), amount), "Stake failed");
        stakes[msg.sender] += amount;
        emit Staked(msg.sender, amount);
    }

    // Slashing mechanism directly tied to LLM hallucination occurrences
    function slash(address agent, uint256 amount, string memory reason) external onlyOwner {
        require(stakes[agent] >= amount, "Insufficient stake to slash");
        stakes[agent] -= amount;
        emit Slashed(agent, amount, reason);
    }
}`}
                    </pre>
                  )}

                  {activeContract === 'sdk' && (
                    <pre className="text-cyan-200/95">
{`import { XibalbaShield } from '@xibalba/shield-sdk';

// Initialize the secure client-side Edge SDK
const shield = new XibalbaShield({
  agentAddress: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
  sbtAddress: "0xReputationSBTAddress",
  auditShieldAddress: "0xAuditShieldAddress",
  providerUrl: "https://rpc.itk-testnet.xibalba.network"
});

// Run a secure, blinded clinical inference session
const result = await shield.secureSession({
  clinicalData: { 
    patientName: "Jane Doe", 
    diagnosis: "Hypertension", 
    icd10: "I10" 
  },
  prompt: "Determine medication compatibility and check contraindications.",
  minAccuracyScore: 90,  // Restrict to models with >=90 accuracy
  minPrivacyScore: 95,   // Restrict to models with >=95 privacy compliance
  minReliabilityScore: 85 // Restrict to models with >=85 operational reliability
});

if (result.isApproved) {
  console.log("✅ Shield verification passed.");
  console.log("ZK Blinded Audit Hash:", result.auditHash);
  console.log("L2 Anchor TxHash:", result.transactionHash);
} else {
  console.error("❌ Shield verification failed:", result.error);
}`}
                    </pre>
                  )}
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* Security Officers & Compliance Auditing Section */}
      <section id="compliance-officers" className="py-24 px-6 bg-slate-950 text-white border-b border-slate-900 relative overflow-hidden">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-teal-500/10 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none" />

        <div className="max-w-7xl mx-auto relative z-10">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              🛡️ CISO & Compliance Portal
            </span>
            <h2 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white leading-tight">
              Sovereign Guardrails for <br />
              <span className="bg-gradient-to-r from-cyan-400 to-teal-400 bg-clip-text text-transparent">Healthcare Security Officers</span>
            </h2>
            <p className="text-slate-400 text-sm md:text-base leading-relaxed">
              Equip your compliance directors, IT security officers, and risk management teams with a trustless ledger. Verify operational security and model alignment without compromising patient privacy.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {/* Card 1 */}
            <div className="bg-slate-900/60 backdrop-blur-md p-6 rounded-xl border border-slate-800 flex flex-col justify-between hover:border-slate-700 transition-all group">
              <div className="space-y-4">
                <div className="w-12 h-12 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 text-xl font-bold">
                  🚨
                </div>
                <h3 className="text-lg font-bold text-white group-hover:text-cyan-300 transition-colors">Incident Prevention</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Compliance officers define reputation thresholds in the gateway. The system blocks out-of-alignment models instantly before they can ingest or process patient clinical notes.
                </p>
              </div>
              <div className="pt-4 border-t border-slate-800/60 mt-4 text-[10px] font-mono text-cyan-400 bg-cyan-950/20 p-2 rounded">
                STATUS: ACTIVE ACTIVE
              </div>
            </div>

            {/* Card 2 */}
            <div className="bg-slate-900/60 backdrop-blur-md p-6 rounded-xl border border-slate-800 flex flex-col justify-between hover:border-slate-700 transition-all group">
              <div className="space-y-4">
                <div className="w-12 h-12 rounded-lg bg-teal-500/10 border border-teal-500/20 flex items-center justify-center text-teal-400 text-xl font-bold">
                  🔍
                </div>
                <h3 className="text-lg font-bold text-white group-hover:text-teal-300 transition-colors">ZK Audit Verification</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Reconcile logs offline for HHS or OCR audits. Re-hash raw database charts locally and match them against the on-chain <code className="text-teal-300">AuditShield</code> hash index to mathematically prove non-tampering.
                </p>
              </div>
              <div className="pt-4 border-t border-slate-800/60 mt-4 text-[10px] font-mono text-teal-400 bg-teal-950/20 p-2 rounded">
                PROOF: HASH MATCH VERIFIED
              </div>
            </div>

            {/* Card 3 */}
            <div className="bg-slate-900/60 backdrop-blur-md p-6 rounded-xl border border-slate-800 flex flex-col justify-between hover:border-slate-700 transition-all group">
              <div className="space-y-4">
                <div className="w-12 h-12 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 text-xl font-bold">
                  ⚖️
                </div>
                <h3 className="text-lg font-bold text-white group-hover:text-emerald-300 transition-colors">Staked Slashing</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Establish economic accountability for third-party AI agent models. Automatic consensus disputes trigger slashing of staked $ITK tokens in cases of catastrophic hallucinations.
                </p>
              </div>
              <div className="pt-4 border-t border-slate-800/60 mt-4 text-[10px] font-mono text-emerald-400 bg-emerald-950/20 p-2 rounded">
                ESCROW: 15,000 $ITK ACTIVE
              </div>
            </div>

            {/* Card 4 */}
            <div className="bg-slate-900/60 backdrop-blur-md p-6 rounded-xl border border-slate-800 flex flex-col justify-between hover:border-slate-700 transition-all group">
              <div className="space-y-4">
                <div className="w-12 h-12 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 text-xl font-bold">
                  📊
                </div>
                <h3 className="text-lg font-bold text-white group-hover:text-blue-300 transition-colors">SOC2/HIPAA Reports</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Generate cryptographic evidence with a single click. Compile on-chain log receipts and transaction payloads as immutable proof of continuous HIPAA and SOC2 compliance.
                </p>
              </div>
              <div className="pt-4 border-t border-slate-800/60 mt-4 text-[10px] font-mono text-blue-400 bg-blue-950/20 p-2 rounded">
                COMPLIANCE INDEX: 99.8%
              </div>
            </div>
          </div>

          {/* Verification Walkthrough for Compliance Officers */}
          <div className="mt-16 bg-slate-900/40 border border-slate-800/80 rounded-2xl p-8 max-w-5xl mx-auto flex flex-col md:flex-row gap-8 items-center">
            <div className="flex-shrink-0 w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-2xl font-bold">
              📋
            </div>
            <div className="space-y-4">
              <h4 className="text-lg font-bold text-white">How Compliance Teams Conduct ZK Audit Reconciliation:</h4>
              <ol className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-slate-400 list-none font-sans">
                <li className="relative pl-6">
                  <span className="absolute left-0 top-0 text-cyan-400 font-mono font-bold">01.</span>
                  <span className="font-bold text-slate-200">Generate Audit Hash</span>
                  <p className="mt-1">
                    Select a patient record and execute the local edge hashing tool. The record is salted and hashed client-side inside the local database environment.
                  </p>
                </li>
                <li className="relative pl-6">
                  <span className="absolute left-0 top-0 text-cyan-400 font-mono font-bold">02.</span>
                  <span className="font-bold text-slate-200">Query AuditShield Ledger</span>
                  <p className="mt-1">
                    Query the on-chain <code className="text-cyan-300">AuditShield</code> mapping for the generated hash using the compliance portal reconciliation view.
                  </p>
                </li>
                <li className="relative pl-6">
                  <span className="absolute left-0 top-0 text-cyan-400 font-mono font-bold">03.</span>
                  <span className="font-bold text-slate-200">Verify Zero-Knowledge Proof</span>
                  <p className="mt-1">
                    The portal mathematically matches hashes to prove the clinical note was securely logged at the exact time timestamp without exposing any patient PHI.
                  </p>
                </li>
              </ol>
            </div>
          </div>
        </div>
      </section>

      {/* HIPAA Regulatory Compliance Matrix Section */}
      <section id="regulatory-compliance" className="py-24 px-6 bg-slate-900 text-white border-t border-b border-slate-800 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-teal-500/10 text-teal-400 border border-teal-500/20">
              📊 Regulatory-Grade Compliance Ledger
            </span>
            <h2 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white leading-tight">
              Cryptographic Safeguards Matrix <br />
              <span className="bg-gradient-to-r from-teal-400 to-cyan-400 bg-clip-text text-transparent">Fulfilling 45 CFR § 164.312</span>
            </h2>
            <p className="text-slate-400 text-sm md:text-base leading-relaxed">
              Verify how Xibalba Shield maps smart contract primitives and decentralized workflows directly to federal HIPAA Technical Safeguards.
            </p>
          </div>

          {/* Dual-Layer Identity Primitive Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-16">
            {/* Identity Layer 1 */}
            <div className="bg-slate-950 p-8 rounded-2xl border border-slate-800 relative group overflow-hidden">
              <div className="absolute top-0 right-0 w-32 h-32 bg-teal-500/5 rounded-full blur-2xl group-hover:bg-teal-500/10 transition-all duration-300" />
              <div className="flex justify-between items-start mb-6">
                <span className="text-xs font-mono text-teal-400 bg-teal-950/40 border border-teal-800 px-3 py-1 rounded-full">LAYER 1: CLINICAL PRACTITIONER</span>
                <span className="text-2xl">👤</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-3">Human Operator Authentication</h3>
              <p className="text-xs text-slate-400 leading-relaxed mb-6">
                All clinicians, staff, and enterprise compliance officers are authenticated through localized private key signatures. No medical action is authorized without verifiable signature headers.
              </p>
              <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 text-[11px] font-mono text-teal-300 space-y-1.5">
                <div>{"// ECDSA Clinician Signature Gateway Check"}</div>
                <div>{"const isValid = await verifySignature(operatorAddress, sessionPayload, signature);"}</div>
                <div>{"require(isValid, \"HIPAA § 164.312(d): Entity Not Authenticated\");"}</div>
              </div>
            </div>

            {/* Identity Layer 2 */}
            <div className="bg-slate-950 p-8 rounded-2xl border border-slate-800 relative group overflow-hidden">
              <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-2xl group-hover:bg-cyan-500/10 transition-all duration-300" />
              <div className="flex justify-between items-start mb-6">
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-800 px-3 py-1 rounded-full">LAYER 2: SOVEREIGN MACHINE AGENT</span>
                <span className="text-2xl">🤖</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-3">Sovereign Agent Model Identification</h3>
              <p className="text-xs text-slate-400 leading-relaxed mb-6">
                AI software programs and Large Language Models are bound to individual smart contract addresses. Model parameters and performance metrics are locked permanently inside Soulbound tokens.
              </p>
              <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 text-[11px] font-mono text-cyan-300 space-y-1.5">
                <div>{"// SBT Machine Identity Gating Check"}</div>
                <div>{"ReputationMetrics memory metrics = sbt.agentMetrics(tokenId);"}</div>
                <div>{"require(metrics.privacy >= minPrivacyScore, \"HIPAA § 164.312(a)(1): Access Gated\");"}</div>
              </div>
            </div>
          </div>

          {/* Interactive Compliance Matrix Table */}
          <div className="bg-slate-950 rounded-2xl border border-slate-800 overflow-hidden shadow-2xl mb-16">
            <div className="px-8 py-6 bg-slate-900/50 border-b border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
              <div>
                <h3 className="font-bold text-white">Technical Safeguards Matrix</h3>
                <p className="text-xs text-slate-400">Strict mapping to federal HIPAA Security Rule specifications.</p>
              </div>
              <span className="text-xs font-mono bg-teal-500/10 border border-teal-500/20 text-teal-400 px-3 py-1 rounded">AUDITED B2B STANDARD</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs md:text-sm">
                <thead>
                  <tr className="bg-slate-900/30 text-slate-400 border-b border-slate-800/80 font-mono">
                    <th className="py-4 px-6 font-semibold">HIPAA Regulation</th>
                    <th className="py-4 px-6 font-semibold">Mandate Details</th>
                    <th className="py-4 px-6 font-semibold">Cryptographic Primitive Deployed</th>
                    <th className="py-4 px-6 font-semibold">Implementation Standard</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  <tr className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-4 px-6 font-semibold text-white">§ 164.312(a)(1) Access Control</td>
                    <td className="py-4 px-6 text-slate-400 text-xs leading-relaxed">Limit systems access to authorized users or automated software programs.</td>
                    <td className="py-4 px-6 text-teal-400 font-mono text-xs">SovereignAgent.sol &amp; ReputationSBT.sol</td>
                    <td className="py-4 px-6 text-slate-400 text-xs">Models query SBT score arrays before processing. Low accuracy/privacy triggers immediate block.</td>
                  </tr>
                  <tr className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-4 px-6 font-semibold text-white">§ 164.312(a)(2)(i) Unique Identity</td>
                    <td className="py-4 px-6 text-slate-400 text-xs leading-relaxed">Assign a unique identification name or number for tracking user and agent identity.</td>
                    <td className="py-4 px-6 text-teal-400 font-mono text-xs">SovereignAgent Contract Address</td>
                    <td className="py-4 px-6 text-slate-400 text-xs">Maps human EHR practitioners and active LLM models to distinct cryptographic public key signatures.</td>
                  </tr>
                  <tr className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-4 px-6 font-semibold text-white">§ 164.312(a)(2)(ii) Emergency Access</td>
                    <td className="py-4 px-6 text-slate-400 text-xs leading-relaxed">Establish procedures for obtaining clinical information in emergencies.</td>
                    <td className="py-4 px-6 text-teal-400 font-mono text-xs">Pre-Inference Gateway Override</td>
                    <td className="py-4 px-6 text-slate-400 text-xs">Supports localized override controls that log immediate alarms to compliance dashboards.</td>
                  </tr>
                  <tr className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-4 px-6 font-semibold text-white">§ 164.312(b) Audit Controls</td>
                    <td className="py-4 px-6 text-slate-400 text-xs leading-relaxed">Implement procedural audits to record activity in systems storing ePHI.</td>
                    <td className="py-4 px-6 text-teal-400 font-mono text-xs">AuditShield.sol Blockchain Ledger</td>
                    <td className="py-4 px-6 text-slate-400 text-xs">Every model transaction is anchored as a blinded hash to the block ledger with gasless paymaster operations.</td>
                  </tr>
                  <tr className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-4 px-6 font-semibold text-white">§ 164.312(c)(1) Integrity Controls</td>
                    <td className="py-4 px-6 text-slate-400 text-xs leading-relaxed">Verify that clinical data has not been altered or destroyed without authorization.</td>
                    <td className="py-4 px-6 text-teal-400 font-mono text-xs">ZK Audit Reconciliation</td>
                    <td className="py-4 px-6 text-slate-400 text-xs">Re-calculates hashes offline locally and performs lookup queries against on-chain block states.</td>
                  </tr>
                  <tr className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-4 px-6 font-semibold text-white">§ 164.312(d) Authentication</td>
                    <td className="py-4 px-6 text-slate-400 text-xs leading-relaxed">Implement procedures to verify that entities accessing ePHI are who they claim.</td>
                    <td className="py-4 px-6 text-teal-400 font-mono text-xs">ECDSA Cryptographic Signatures</td>
                    <td className="py-4 px-6 text-slate-400 text-xs">Inferences require clinical operator signature verification, preventing spoofing.</td>
                  </tr>
                  <tr className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-4 px-6 font-semibold text-white">§ 164.312(e)(1) Transmission Security</td>
                    <td className="py-4 px-6 text-slate-400 text-xs leading-relaxed">Guard against unauthorized access to EPHI transmitted over networks.</td>
                    <td className="py-4 px-6 text-teal-400 font-mono text-xs">Client-Side Edge Blinding</td>
                    <td className="py-4 px-6 text-slate-400 text-xs">Performs SHA-256 hashing locally at the edge firewall. No raw patient charts are transmitted.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Mathematical Edge Blinding Proof Box */}
          <div className="bg-slate-950 p-8 rounded-2xl border border-slate-800 max-w-4xl mx-auto">
            <h4 className="text-base font-bold text-white mb-4 flex items-center gap-2">
              <span>🔒</span> Zero-Knowledge Patient Privacy Isolation (Safe Harbor Standard)
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed mb-6">
              Under the HIPAA Privacy Rule (45 CFR § 164.514), patient clinical records are fully protected from public exposure. The edge SDK enforces a strict, non-reversible local hashing schema:
            </p>
            <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 text-center font-mono text-sm md:text-base text-teal-400 mb-6 py-8">
              H = SHA-256( Patient Record || System Prompt || Secure Salt )
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs text-slate-400 list-none">
              <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                <span className="font-bold text-white block mb-1">01. Safe Harbor Compliant</span>
                All 18 HIPAA identifiers are isolated at the local Edge boundary. No identifiable health records traverse the network.
              </div>
              <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                <span className="font-bold text-white block mb-1">02. Mathematical Proof</span>
                Hash H proves the exact model prompt and patient charts were logged without exposing the medical note details.
              </div>
              <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                <span className="font-bold text-white block mb-1">03. Audit-Ready</span>
                Auditors re-compute H using clinical DB records and secure salts to prove historical non-tampering.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-24 px-6 bg-slate-50 border-t border-slate-200">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight text-slate-900 mb-4">Pricing Models</h2>
            <p className="text-slate-500">Start with our free local simulation sandbox or scale up to live testnet production pipelines.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {/* Plan 1 */}
            <div className="bg-white p-8 rounded-xl shadow-sm border border-slate-200 flex flex-col justify-between">
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Developer</h3>
                <p className="text-sm text-slate-500 mb-6">Test and compile guardrails locally offline.</p>
                <div className="mb-6"><span className="text-4xl font-bold text-slate-900">$0</span> <span className="text-slate-400">/ forever</span></div>
                <ul className="space-y-3 text-sm text-slate-600 mb-8">
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> Local Hardhat Sandbox</li>
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> 5 Core Solidity Templates</li>
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> Basic SDK access</li>
                </ul>
              </div>
              <button
                onClick={() => setCheckoutPlan({ name: 'Developer Plan', price: '$0' })}
                className="w-full py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-lg transition-all text-sm"
              >
                Launch Sandbox
              </button>
            </div>

            {/* Plan 2 */}
            <div className="bg-white p-8 rounded-xl shadow-md border-2 border-teal-500 flex flex-col justify-between relative transform -translate-y-2">
              <span className="absolute top-0 right-6 transform -translate-y-1/2 bg-teal-500 text-white text-[10px] uppercase font-bold tracking-widest px-3 py-1 rounded-full">Popular</span>
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Startup</h3>
                <p className="text-sm text-slate-500 mb-6">Fully live ITK testnet deployment and paymaster gas subsidies.</p>
                <div className="mb-6"><span className="text-4xl font-bold text-slate-900">$199</span> <span className="text-slate-400">/ month</span></div>
                <ul className="space-y-3 text-sm text-slate-600 mb-8">
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> Unlimited ITK Testnet API Logs</li>
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> Live SovereignAgent Deployer</li>
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> Custom paymaster gas rules</li>
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> Email & Discord Support</li>
                </ul>
              </div>
              <button
                onClick={() => setCheckoutPlan({ name: 'Startup Plan', price: '$199' })}
                className="w-full py-2.5 bg-teal-600 hover:bg-teal-700 text-white font-bold rounded-lg shadow-sm transition-all text-sm"
              >
                Deploy Startup Shield
              </button>
            </div>

            {/* Plan 3 */}
            <div className="bg-white p-8 rounded-xl shadow-sm border border-slate-200 flex flex-col justify-between">
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Enterprise</h3>
                <p className="text-sm text-slate-500 mb-6">Dedicated nodes, advanced ZK circuits, and SLA guarantees.</p>
                <div className="mb-6"><span className="text-4xl font-bold text-slate-900">Custom</span></div>
                <ul className="space-y-3 text-sm text-slate-600 mb-8">
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> Dedicated ITK Node Network</li>
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> Custom HIPAA Audit reporting</li>
                  <li className="flex items-center"><span className="text-teal-500 mr-2">✓</span> 24/7 SLA Priority Support</li>
                </ul>
              </div>
              <button
                onClick={() => setCheckoutPlan({ name: 'Enterprise Plan', price: 'Custom' })}
                className="w-full py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-lg transition-all text-sm"
              >
                Contact Sales
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Modals & Stripe Checkout Simulation Overlay */}

      {/* Auth Modals */}
      {authModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex justify-center items-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-md w-full p-8 relative">
            <button
              onClick={() => setAuthModal(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 font-bold text-lg"
            >
              ✕
            </button>

            <h3 className="text-2xl font-bold text-slate-900 mb-2">
              {authModal === 'signin' ? 'Welcome Back' : 'Get Started'}
            </h3>
            <p className="text-sm text-slate-500 mb-6">
              {authModal === 'signin' ? 'Sign in to access your secure Shield Dashboard' : 'Provision a secure operator account instantly'}
            </p>

            <form onSubmit={handleAuth} className="space-y-4">
              {authModal === 'signup' && (
                <div>
                  <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Username</label>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full p-2.5 border border-slate-200 rounded-lg text-sm bg-slate-50 focus:ring-2 focus:ring-teal-500 focus:outline-none"
                    placeholder="xibalba_operator"
                  />
                </div>
              )}
              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  value={userEmail}
                  onChange={(e) => setUserEmail(e.target.value)}
                  className="w-full p-2.5 border border-slate-200 rounded-lg text-sm bg-slate-50 focus:ring-2 focus:ring-teal-500 focus:outline-none"
                  placeholder="name@company.com"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Password</label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full p-2.5 border border-slate-200 rounded-lg text-sm bg-slate-50 focus:ring-2 focus:ring-teal-500 focus:outline-none"
                  placeholder="••••••••"
                />
              </div>

              <button
                type="submit"
                disabled={authLoading}
                className="w-full py-3 bg-teal-600 hover:bg-teal-700 text-white font-bold rounded-lg shadow-sm transition-all text-sm flex items-center justify-center"
              >
                {authLoading ? (
                  <span className="flex items-center"><span className="animate-spin mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full" /> Authenticating...</span>
                ) : (
                  authModal === 'signin' ? 'Sign In' : 'Sign Up'
                )}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Stripe checkout simulation modal */}
      {checkoutPlan && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex justify-center items-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-lg w-full overflow-hidden relative">
            <button
              onClick={() => setCheckoutPlan(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 font-bold text-lg"
            >
              ✕
            </button>

            <div className="bg-gradient-to-r from-teal-600 to-cyan-600 p-6 text-white">
              <h3 className="text-xl font-bold">Stripe Checkout</h3>
              <p className="text-teal-100 text-sm mt-1">Complete your checkout securely for {checkoutPlan.name}</p>
            </div>

            {checkoutSuccess ? (
              <div className="p-12 text-center flex flex-col items-center justify-center">
                <span className="text-5xl mb-4 text-teal-500 animate-bounce">✓</span>
                <h4 className="text-2xl font-bold text-slate-900 mb-2">Checkout Successful!</h4>
                <p className="text-sm text-slate-500">Your SaaS plan is activated. Deployed mock subscription.</p>
              </div>
            ) : (
              <form onSubmit={handleCheckout} className="p-8 space-y-6">
                <div className="flex justify-between items-center bg-slate-50 p-4 rounded-lg border border-slate-100">
                  <div>
                    <div className="font-semibold text-slate-800">{checkoutPlan.name} Subscription</div>
                    <div className="text-xs text-slate-400">Automatic monthly billing renewal</div>
                  </div>
                  <div className="text-xl font-bold text-slate-900">{checkoutPlan.price}</div>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Cardholder Name</label>
                    <input
                      type="text"
                      required
                      className="w-full p-2.5 border border-slate-200 rounded-lg text-sm bg-slate-50 focus:ring-2 focus:ring-teal-500 focus:outline-none"
                      placeholder="Operator Name"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Card Number (Stripe Element)</label>
                    <div className="relative">
                      <input
                        type="text"
                        required
                        maxLength={19}
                        value={cardNumber}
                        onChange={(e) => setCardNumber(e.target.value.replace(/\D/g, '').replace(/(\d{4})/g, '$1 ').trim())}
                        className="w-full p-2.5 pl-10 border border-slate-200 rounded-lg text-sm bg-slate-50 focus:ring-2 focus:ring-teal-500 focus:outline-none font-mono"
                        placeholder="4242 4242 4242 4242"
                      />
                      <span className="absolute left-3.5 top-3 text-slate-400">💳</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Expiry Date</label>
                      <input
                        type="text"
                        required
                        maxLength={5}
                        value={cardExpiry}
                        onChange={(e) => setCardExpiry(e.target.value.replace(/\D/g, '').replace(/(\d{2})/g, '$1/').replace(/\/$/, ''))}
                        className="w-full p-2.5 border border-slate-200 rounded-lg text-sm bg-slate-50 focus:ring-2 focus:ring-teal-500 focus:outline-none font-mono"
                        placeholder="MM/YY"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">CVC</label>
                      <input
                        type="text"
                        required
                        maxLength={3}
                        value={cardCvc}
                        onChange={(e) => setCardCvc(e.target.value.replace(/\D/g, ''))}
                        className="w-full p-2.5 border border-slate-200 rounded-lg text-sm bg-slate-50 focus:ring-2 focus:ring-teal-500 focus:outline-none font-mono"
                        placeholder="123"
                      />
                    </div>
                  </div>
                </div>

                <div className="flex items-center text-xs text-slate-400 bg-slate-50/50 p-2.5 rounded-lg border border-slate-100">
                  <span className="mr-2">🔒</span> Stripe Secured SSL transaction. Paymaster integration automatically active.
                </div>

                <button
                  type="submit"
                  disabled={checkoutLoading}
                  className="w-full py-3.5 bg-teal-600 hover:bg-teal-700 text-white font-bold rounded-lg shadow-sm transition-all text-sm flex items-center justify-center"
                >
                  {checkoutLoading ? (
                    <span className="flex items-center"><span className="animate-spin mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full" /> Processing Transaction...</span>
                  ) : (
                    `Pay ${checkoutPlan.price}`
                  )}
                </button>
              </form>
            )}
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="bg-slate-900 text-white py-12 px-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center border-b border-slate-800 pb-8 mb-8">
          <div className="mb-6 md:mb-0">
            <h4 className="text-xl font-bold tracking-tight mb-2">Xibalba Shield</h4>
            <p className="text-sm text-slate-400">Cryptographically enforcing healthcare data integrity.</p>
          </div>
          <div className="flex space-x-6 text-sm text-slate-400">
            <a href="#how-it-works" className="hover:text-teal-400 transition-colors">How It Works</a>
            <a href="#use-cases" className="hover:text-teal-400 transition-colors">Use Cases</a>
            <a href="#pricing" className="hover:text-teal-400 transition-colors">Pricing</a>
          </div>
        </div>
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center text-xs text-slate-500">
          <p>© 2026 Xibalba Shield. All rights reserved. HIPAA Audited.</p>
          <p>Powered by the Integrity Protocol ($ITK)</p>
        </div>
      </footer>
    </div>
  );
}
