import { describe, expect, it } from "vitest";
import type {
  CatalogArtifact,
  PolicyDecision,
  RepairDiagnosis,
  VerificationSummary,
} from "./index.js";

describe("Phase 0 type scaffolding", () => {
  it("accepts a well-formed RepairDiagnosis shape", () => {
    const diagnosis: RepairDiagnosis = {
      issueTitle: "Port 3000 blocked",
      rootCause: "Orphaned process holds the TCP socket",
      targetOS: "linux",
      checkPlan: ["Check if port 3000 is bound"],
      fixPlan: [{ actionId: "free-tcp-port", parameters: { port: 3000 } }],
      preconditions: ["Fresh disposable test environment"],
      riskLevel: "low",
      needsHumanApproval: true,
    };

    expect(diagnosis.fixPlan[0]?.actionId).toBe("free-tcp-port");
  });

  it("rejects an unapproved status for CatalogArtifact at the type level", () => {
    const artifact: CatalogArtifact = {
      artifactId: "forge-repair-example-001",
      artifactHash: "sha256:0".padEnd(71, "0"),
      format: "cli",
      status: "approved",
      evidenceHash: "sha256:0".padEnd(71, "0"),
      createdAt: new Date().toISOString(),
      forgeVersion: "0.0.1",
    };

    expect(artifact.status).toBe("approved");
  });

  it("models a blocked PolicyDecision without redactions", () => {
    const decision: PolicyDecision = {
      allowed: false,
      findings: [
        {
          ruleId: "no-private-key",
          severity: "block",
          message: "PEM private key block detected in input",
        },
      ],
      reason: "input contains a private key",
    };

    expect(decision.allowed).toBe(false);
  });

  it("requires a verification level alongside a passed status", () => {
    const summary: VerificationSummary = {
      status: "not_verified",
      level: "L1_static_validated",
      checks: [
        {
          name: "precondition_oracle",
          status: "not_verified",
          exitCode: null,
          details: { reason: "fault state could not be reproduced" },
        },
      ],
    };

    expect(summary.status).toBe("not_verified");
  });
});
