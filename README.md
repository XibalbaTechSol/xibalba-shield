# Xibalba Shield — Cryptographic HIPAA Compliance-as-a-Service

Xibalba Shield is an enterprise-grade clinical security portal and decentralized verification pipeline built on top of the **Integrity Protocol** ecosystem. It empowers healthcare clinics, hospitals, and telemedicine networks to run high-performance AI inference models on patient data while cryptographically guaranteeing complete **HIPAA Technical Safeguards compliance (45 CFR § 164.312)**.

Through a dual-layer identity primitive, client-side zero-knowledge edge hashing, and soulbound compliance gating, Xibalba Shield guarantees that private **Protected Health Information (PHI) never touches the blockchain**.

---

## 🚀 Key Architectural Pillars

### 1. Dual-Layer Identity Primitive
- **Operator ECDSA Keypair**: The human medical professional or administrator authenticates using standard public-key cryptography.
- **Machine Agent SBT**: The autonomous AI model is registered as an on-chain asset mapped to a non-transferable Soulbound Token (`ReputationSBT.sol`) that tracks its real-time compliance metrics.

### 2. Tri-Metric Agent Reputation Gating
AI models are continuously audited across three performance vectors:
- **Accuracy**: Integrity of clinical summaries, diagnosis codes, and billing classifications.
- **Privacy**: Zero exposure of identifiable fields or accidental leakage of raw text.
- **Reliability**: Query latency, contract execution consistency, and node health.

If any vector dips below predefined enterprise thresholds, the SBT access token is dynamically revoked or locked.

### 3. ZK Edge Blinding (Safe Harbor Method)
Under the HIPAA Safe Harbor standard, raw text must be blinded pre-network interface. The Xibalba Shield Edge SDK hashes raw patient records locally:
$$\text{ZK\_Hash} = \text{SHA256}(\text{clinicalData} + \text{nonce})$$
Only this blind, cryptographic hash is sent to the blockchain for timestamping and anchoring, ensuring absolute privacy.

### 4. Collateralized Staking & Slashing
AI model performance is backed by financial stakes. If an agent experiences severe hallucinations or breaches compliance thresholds, the $ITK collateral is slashed and disbursed as an insurance callback to affected clinic systems.

---

## 🛠️ Smart Contract Ecosystem (`/contracts`)

The underlying Web3 primitive layer comprises the following Solidity smart contracts:

- **`SovereignAgent.sol`**: Manages registration, authorization, and ownership records of AI models.
- **`ReputationSBT.sol`**: Implements soulbound reputation tracking using performance structs (`uint8 accuracy`, `uint8 privacy`, `uint8 reliability`).
- **`AuditShield.sol`**: Handles cryptographic log anchoring. Employs duplicate transaction modifiers (`Log already anchored`) to prevent replay or hash reuse.
- **`StakingReputation.sol`**: Manages $ITK collateral staking, delegation, and penalty execution (slashing).
- **`MockPaymaster.sol`**: Underpins gasless Layer-2 transactions, subsidizing clinical audit logs with L2 paymaster networks.

---

## 📦 Client-Side Edge SDK (`src/lib/sdk/`)

The edge SDK (`xibalba-shield-sdk.ts`) allows developers to easily integrate ZK compliance checks into outpatient scribes, billing bots, and triage channels:

```typescript
import { XibalbaShieldSDK } from "./sdk/shield-sdk";

// Initialize with ITK Testnet provider
const sdk = new XibalbaShieldSDK({
  rpcUrl: "https://testnet.itk-protocol.io",
  reputationSbtAddress: "0x...",
  auditShieldAddress: "0x..."
});

// Perform local cryptographic blinding of patient data
const { dataHash, payload } = await sdk.blindClinicalRecord({
  patientId: "PAT-8831",
  symptoms: "Persistent dry cough, fatigue, low-grade fever",
  vitals: { temp: "100.1F", bp: "120/80" }
});

// Verify if the active AI model is compliant pre-inference
const isCompliant = await sdk.verifyAgentCompliance("0xModelAgentAddress");
if (isCompliant) {
  // Send ZK Hash to on-chain AuditShield
  const txHash = await sdk.anchorAuditLog("0xModelAgentAddress", dataHash);
  console.log(`Compliance verified. Audit log anchored: ${txHash}`);
}
```

---

## 🚀 Quickstart & Deployed Workspace

### Prerequisites
- Node.js (v18 or higher)
- Hardhat (`npx hardhat`)
- `uv` (for Python-based agent sync and simulation scripts)

### Installation
1. Clone the repository and install packages:
   ```bash
   npm install
   ```
2. Set up environment variables:
   ```bash
   cp .env.example .env
   ```

### Running Local Development Environment
1. Launch the local Hardhat Node simulating the ITK Testnet:
   ```bash
   npx hardhat node
   ```
2. Deploy the smart contracts to the local network:
   ```bash
   npx hardhat run scripts/deploy.ts --network localhost
   ```
3. Boot the Next.js dev portal:
   ```bash
   npm run dev
   ```
4. Access the clinical console landing page at `http://localhost:3000` and the secure command center dashboard at `http://localhost:3000/dashboard`.

---

## 🔬 Simulation & Automated Tests

To run the B2B outpatient simulation loop testing concurrent block mining and duplicate log prevention modifiers:
```bash
npx hardhat run scripts/test-scribe-loop.ts --network localhost
```
The simulation tests key parameters:
1. **Happy Path**: Successful hashing, SBT lookup, gas paymaster subsidy, and block mining.
2. **Duplicate Prevention Guard**: Re-submitting identical hashes successfully triggers the contract-level modifier, reverting with `Log already anchored`.

---

## 🛡️ Regulatory Compliance Matrix

Xibalba Shield maps directly to the **45 CFR § 164.312 HIPAA Technical Safeguards Matrix**:
- **§ 164.312(a)(1) Access Control**: Enforced pre-inference via `ReputationSBT` checks.
- **§ 164.312(b) Transmission Security**: Ensured locally via ZK-edge blinding hashing.
- **§ 164.312(c)(1) Integrity**: Deriving local raw patient data offline and checking the hash against `AuditShield.sol` dynamically verifies file integrity.
- **§ 164.312(d) Authentication**: Dual-Layer cryptographic identity primitive mapping machine SBT address and operator ECDSA signatures.

---

## 📄 License & Integrity Statement

This codebase is published under the **MIT License**.
*Form-First Engineering. Mathematical Certainty. Proliferating the Integrity Protocol.*

---

## 🏛️ Relationship to Integrity Protocol

Xibalba Shield is a **Vertical Implementation** of the Integrity Protocol. While the core protocol provides a generic "Trust Layer," Xibalba Shield extends it with healthcare-specific logic:

- **Clearance Bitmask**: Xibalba Shield utilizes the protocol's generic `clearance_bitmask` to represent HIPAA compliance status (Bit 0: PHI Access, Bit 1: Billing Authority).
- **ZK-Edge Blinding**: Shield utilizes the protocol's ZK-verification engine to prove an agent meets HIPAA-specific AIS thresholds (>= 750) without revealing clinical metadata.
- **Service Layer**: Shield acts as the "Healthcare Credit Bureau," interpreting the raw reputation scores into clinical trust levels.
