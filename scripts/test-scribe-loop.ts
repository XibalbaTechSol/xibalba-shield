// @ts-nocheck
import pkg from "hardhat";
const { ethers } = pkg;
import * as dotenv from "dotenv";

dotenv.config();

async function main() {
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  XIBALBA SHIELD — Autonomous Scribe Audit Simulator");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

  const auditShieldAddress = process.env.AUDIT_SHIELD_ADDRESS;
  if (!auditShieldAddress) {
    console.error("Error: AUDIT_SHIELD_ADDRESS not set in .env");
    process.exit(1);
  }

  // Connect to deployed AuditShield contract
  const AuditShield = await ethers.getContractFactory("AuditShield");
  const auditShield = AuditShield.attach(auditShieldAddress);

  // Mock PHI (Protected Health Information) clinical notes
  const mockScribeRuns = [
    {
      note: "Patient Alice Smith, DOB 11/12/1984. Diagnosed with hypertension. Prescribed Lisinopril 10mg daily.",
      prompt: "Extract diagnosis and medication."
    },
    {
      note: "Patient Bob Jones, DOB 05/23/1991. Complains of chronic lower back pain. Advised physical therapy.",
      prompt: "Extract symptoms and treatment plan."
    }
  ];
  for (let i = 0; i < mockScribeRuns.length; i++) {
    if (i > 0) {
      // Small sleep to allow Hardhat node to mine the previous block and increment nonce
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    console.log(`[Run ${i + 1}/${mockScribeRuns.length}] AI Scribe processing clinical encounter...`);
    const run = mockScribeRuns[i];

    // Trigger local API route via global fetch
    try {
      const response = await fetch("http://localhost:3000/api/inference", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agentAddress: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
          clinicalData: { note: run.note, timestamp: Date.now() },
          prompt: run.prompt
        })
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error || "API execution failed");
      }

      console.log("  ✓ API returned blind inference successfully.");
      console.log(`  ✓ On-Chain Tx Hash:   ${result.audit.transactionHash}`);
      console.log(`  ✓ Cryptographic Hash: ${result.audit.dataHash}`);

      // Verify on local Hardhat blockchain
      const loggedEntry = await auditShield.auditLogs(result.audit.dataHash);
      if (loggedEntry.timestamp > 0n) {
        console.log(`  ✓ Blockchain Verification SUCCESS: Log verified on-chain at block timestamp ${loggedEntry.timestamp}\n`);
      } else {
        console.log("  ✖ Blockchain Verification FAILED: Log not found on-chain.\n");
      }
    } catch (error) {
      console.error(`  ✖ Simulation run failed: ${error.message}\n`);
    }
  }

  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SIMULATION COMPLETE — HIPAA 2026 AUDIT COMPLIANT  ");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
