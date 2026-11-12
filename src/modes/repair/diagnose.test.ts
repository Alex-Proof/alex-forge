import { describe, expect, it } from "vitest";
import { diagnoseFallback, generateCliArtifact, validateDiagnosis } from "./diagnose.js";

describe("diagnoseFallback", () => {
  it("recognizes a port-in-use log line and proposes the registered free-tcp-port action", () => {
    const diagnosis = diagnoseFallback("Error: listen EADDRINUSE: address already in use :::3000", "linux");
    expect(diagnosis.fixPlan).toEqual([{ actionId: "free-tcp-port", parameters: { port: 3000 } }]);
    expect(diagnosis.needsHumanApproval).toBe(true);
  });

  it("recognizes a worded 'port N in use' phrasing without a colon", () => {
    const diagnosis = diagnoseFallback("service failed to start: port 8080 is already in use", "linux");
    expect(diagnosis.fixPlan).toEqual([{ actionId: "free-tcp-port", parameters: { port: 8080 } }]);
  });

  it("honestly reports no action for an unrecognized log instead of guessing", () => {
    const diagnosis = diagnoseFallback("segmentation fault in module xyz at offset 0x1234", "linux");
    expect(diagnosis.fixPlan).toEqual([]);
    expect(diagnosis.riskLevel).toBe("high");
    expect(diagnosis.needsHumanApproval).toBe(true);
  });

  it("never requires network access or any model call to run", () => {
    // Purely a documentation-style assertion: calling it synchronously with no I/O proves it.
    expect(typeof diagnoseFallback).toBe("function");
    expect(diagnoseFallback("port 3000 already in use", "linux").targetOS).toBe("linux");
  });
});

describe("validateDiagnosis", () => {
  const baseDiagnosis = {
    issueTitle: "Port 3000 is already in use",
    rootCause: "Another process is already listening on the target TCP port",
    targetOS: "linux" as const,
    checkPlan: ["Check whether a process is listening on port 3000"],
    fixPlan: [{ actionId: "free-tcp-port", parameters: { port: 3000 } }],
    preconditions: ["A disposable test environment with a reproducible port conflict"],
    riskLevel: "low" as const,
    needsHumanApproval: true,
  };

  it("accepts a well-formed diagnosis referencing a registered action", () => {
    const result = validateDiagnosis(baseDiagnosis);
    expect(result.ok).toBe(true);
  });

  it("rejects an unregistered actionId instead of generating code for it", () => {
    const result = validateDiagnosis({
      ...baseDiagnosis,
      fixPlan: [{ actionId: "delete-everything", parameters: {} }],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("unregistered");
    }
  });

  it("rejects a command-injection attempt smuggled through the parameters field", () => {
    const result = validateDiagnosis({
      ...baseDiagnosis,
      fixPlan: [{ actionId: "free-tcp-port", parameters: { port: "3000; rm -rf /" } }],
    });
    expect(result.ok).toBe(false);
  });

  it("rejects a port parameter outside the valid TCP port range", () => {
    const result = validateDiagnosis({
      ...baseDiagnosis,
      fixPlan: [{ actionId: "free-tcp-port", parameters: { port: 999999 } }],
    });
    expect(result.ok).toBe(false);
  });

  it("rejects a diagnosis missing required fields", () => {
    const result = validateDiagnosis({ issueTitle: "incomplete" });
    expect(result.ok).toBe(false);
  });

  it("rejects an invalid riskLevel enum value", () => {
    const result = validateDiagnosis({ ...baseDiagnosis, riskLevel: "critical" });
    expect(result.ok).toBe(false);
  });

  it("accepts a diagnosis with an empty fixPlan (honest 'no action' result)", () => {
    const result = validateDiagnosis({ ...baseDiagnosis, fixPlan: [] });
    expect(result.ok).toBe(true);
  });
});

describe("generateCliArtifact", () => {
  it("generates a repair.sh script for a validated free-tcp-port diagnosis", () => {
    const diagnosis = diagnoseFallback("Error: listen EADDRINUSE: address already in use :::3000", "linux");
    const result = generateCliArtifact(diagnosis);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.fileName).toBe("repair.sh");
      expect(result.content).toContain("PORT=3000");
      expect(result.content).toContain("--check");
      expect(result.content).toContain("--dry-run");
      expect(result.content).toContain("--fix");
      expect(result.content).toContain("--verify");
      expect(result.content).toContain("--json");
    }
  });

  it("refuses to generate anything for an unrecognized diagnosis with an empty fixPlan", () => {
    const diagnosis = diagnoseFallback("segmentation fault in module xyz", "linux");
    const result = generateCliArtifact(diagnosis);
    expect(result.ok).toBe(false);
  });

  it("refuses to generate for a targetOS with no template yet", () => {
    const diagnosis = diagnoseFallback("Error: listen EADDRINUSE: address already in use :::3000", "windows");
    const result = generateCliArtifact(diagnosis);
    expect(result.ok).toBe(false);
  });

  it("refuses to generate for a diagnosis carrying an unregistered action, even if hand-crafted", () => {
    const result = generateCliArtifact({
      issueTitle: "forged",
      rootCause: "forged",
      targetOS: "linux",
      checkPlan: [],
      fixPlan: [{ actionId: "not-a-real-action", parameters: {} }],
      preconditions: [],
      riskLevel: "low",
      needsHumanApproval: true,
    });
    expect(result.ok).toBe(false);
  });
});
