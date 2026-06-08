import { NextResponse } from "next/server";
import crypto from "crypto";
import { verifyIntegrityScore, anchorAuditLog } from "@/lib/web3/integrityProtocol";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { agentAddress, clinicalData, prompt, complianceMetadata } = body;

    if (!agentAddress || !clinicalData || !prompt) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 });
    }

    // 1. Verify Identity-Based Access Control via ReputationSBT
    const isAuthorized = await verifyIntegrityScore(agentAddress);
    if (!isAuthorized) {
      return NextResponse.json({ error: "Agent reputation score too low or not found" }, { status: 403 });
    }

    // 2. Zero-Knowledge "Blind" Execution - Hash the PHI
    // Raw PHI must NEVER touch the blockchain.
    const dataString = JSON.stringify(clinicalData) + prompt;
    const dataHash = "0x" + crypto.createHash("sha256").update(dataString).digest("hex");

    // 2b. Compile the Compliance Bitmask for the generic Integrity Oracle Telemetry
    let clearanceFlags = 0;
    if (complianceMetadata) {
      if (complianceMetadata.hipaaEligible) clearanceFlags |= (1 << 0);
      if (complianceMetadata.zdrEnabled) clearanceFlags |= (1 << 1);
      if (!complianceMetadata.externalWebAccess) clearanceFlags |= (1 << 2);
    }

    // 3. Perform AI Inference (Mocked for MVP)
    const inferenceResult = {
      summary: "Patient presents with symptoms consistent with acute pharyngitis.",
      suggestedBillingCode: "J02.9",
      confidence: 0.95
    };

    // 4. Anchor the interaction on-chain using AuditShield
    const txHash = await anchorAuditLog(dataHash);

    // 5. Dispatch telemetry to Integrity Protocol Oracle with clearanceFlags (Mocked)
    // await dispatchToOracle({ agentId: agentAddress, clearance_flags: clearanceFlags });

    return NextResponse.json({
      success: true,
      inference: inferenceResult,
      audit: {
        dataHash,
        transactionHash: txHash,
        clearanceFlags
      }
    });
  } catch (error) {
    console.error("Inference Error:", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}
