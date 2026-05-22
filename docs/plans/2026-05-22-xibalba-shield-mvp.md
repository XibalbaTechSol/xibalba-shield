# Xibalba Shield MVP Implementation Plan

This document outlines the architecture and execution strategy for **Xibalba Shield**, a B2B SaaS platform providing Compliance-as-a-Service for AI healthcare startups. The platform ensures compliance with the April 2026 HSCC AI Third-Party Risk Guide using the Integrity Protocol and the ITK token.

> [!NOTE]  
> All work will be built in `~/Projects/xibalba-shield`. This plan will be exported to `docs/plans/2026-05-22-xibalba-shield-mvp.md` upon approval to maintain the Antigravity Artifact Protocol.

## User Review Required

> [!IMPORTANT]  
> **Confirmation on Blockchain Framework**: We will use Next.js for the full-stack application and Hardhat/Ethers.js to compile and run local tests for the smart contracts. Is this stack acceptable for the MVP?
>
> **Mocking the ITK Token & AA Paymaster**: For the MVP, we will mock the Account Abstraction (ERC-4337) flow and ITK token logic using local smart contracts. Is this the correct approach for the MVP demonstration?

## Proposed Changes (NEXUS-Sprint Methodology)

We will execute the MVP build across 4 structured sprints.

---

### Sprint 1: Foundation & Scaffolding
Initialize the project structure, repositories, and documentation.

#### [NEW] [docs/plans/2026-05-22-xibalba-shield-mvp.md](file:///home/xibalba/Projects/xibalba-shield/docs/plans/2026-05-22-xibalba-shield-mvp.md)
Export this approved implementation plan.

#### [NEW] [Next.js App Skeleton](file:///home/xibalba/Projects/xibalba-shield/package.json)
Initialize a Next.js (React) project with Tailwind CSS for rapid prototyping of the "clinical aesthetic" (crisp white, dark slate text, cool blues and teals).

#### [NEW] [Hardhat Setup](file:///home/xibalba/Projects/xibalba-shield/hardhat.config.js)
Setup Hardhat environment for developing and compiling the Solidity smart contracts.

---

### Sprint 2: Core Smart Contracts & Economics
Build the Web3 primitives for Identity-Based Access Control (RBAC) and Integrity mechanisms.

#### [NEW] [SovereignAgent.sol](file:///home/xibalba/Projects/xibalba-shield/contracts/SovereignAgent.sol)
Wrap AI agents in unique contracts transitioning their identity to a hard, on-chain asset.

#### [NEW] [ReputationSBT.sol](file:///home/xibalba/Projects/xibalba-shield/contracts/ReputationSBT.sol)
Soulbound Token (SBT) representing the agent's verified compliance and integrity score.

#### [NEW] [AuditShield.sol](file:///home/xibalba/Projects/xibalba-shield/contracts/AuditShield.sol)
Zero-knowledge ledger to provide automated, regulatory-ready log anchoring. Processes cryptographic hashes only, ensuring raw PHI never touches the chain.

#### [NEW] [StakingReputation.sol](file:///home/xibalba/Projects/xibalba-shield/contracts/StakingReputation.sol)
Enforces financial accountability. Slashes collateral (ITK) when AI agents hallucinate or commit errors.

#### [NEW] [MockPaymaster.sol](file:///home/xibalba/Projects/xibalba-shield/contracts/MockPaymaster.sol)
ERC-4337 Account Abstraction Paymaster to subsidize Layer-2 gas fees in the background, abstracting crypto management away from the startup.

---

### Sprint 3: Backend Verification & AI Linkage
Implement the secure backend routing that acts as the barrier between off-chain PHI and on-chain logs.

#### [NEW] [api/inference/route.ts](file:///home/xibalba/Projects/xibalba-shield/app/api/inference/route.ts)
"Blind" Execution endpoint. Receives clinical data, creates a cryptographic hash of the data, processes the inference, and submits the hash to `AuditShield.sol`.

#### [NEW] [lib/web3/integrityProtocol.ts](file:///home/xibalba/Projects/xibalba-shield/lib/web3/integrityProtocol.ts)
Backend utilities for verifying `ReputationSBT` before granting access to data, and executing Account Abstraction transactions on behalf of the user.

---

### Sprint 4: Clinical UI/UX Development
Generate the frontend to build trust with hospital administrators.

#### [NEW] [app/page.tsx](file:///home/xibalba/Projects/xibalba-shield/app/page.tsx)
**Landing Page**: Hero messaging detailing the Compliance-as-a-Service value. Streamlined onboarding that automatically provisions a Web3 wallet via Account Abstraction.

#### [NEW] [app/dashboard/page.tsx](file:///home/xibalba/Projects/xibalba-shield/app/dashboard/page.tsx)
**Client Dashboard**:
- Overview metrics (API calls, data streams).
- Live feed of `AuditShield.sol` verification logs and ITK network efficiency.
- Identity Management UI to view `SovereignAgents` and `ReputationSBT` scores.

---

## Verification Plan

### Automated Validation
- **Code validation:** Run `npm run lint` and `npx hardhat test` to ensure syntactic and smart contract correctness.
- **Contract verification:** Write a suite of local tests to verify that `AuditShield.sol` correctly logs hashes, and `StakingReputation.sol` slashes misbehaving agents.

### Empirical & Visual Validation
- **HIPAA Statutory Requirements 2026 Checklist:**
  - Verify NO raw PHI is present in blockchain transaction payloads.
  - Verify Identity-Based Access Control gatekeeping via `ReputationSBT.sol`.
  - Verify audit logging is intact.
- **UI/UX Walkthrough:** Use screenshots or capture tools to verify the clinical aesthetic (slate, white, cool blue) and functional Dashboard metrics. A walkthrough report will be generated.
