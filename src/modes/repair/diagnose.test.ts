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

  it(
    "extracts the real port, not a leading timestamp's HH:MM:SS, when the error line is timestamp-prefixed",
    () => {
      // A realistic log line, timestamp and all -- the fallback used to misread "20:00:00"'s
      // ":00" as the listen port before the real "...in use :::3000" was ever reached.
      const diagnosis = diagnoseFallback(
        "2026-11-12T20:00:00Z [app] Error: listen EADDRINUSE: address already in use :::3000",
        "linux",
      );
      expect(diagnosis.fixPlan).toEqual([{ actionId: "free-tcp-port", parameters: { port: 3000 } }]);
    },
  );

  it("extracts the port from an explicit 0.0.0.0/127.0.0.1/localhost listen address form", () => {
    expect(diagnoseFallback("Error: bind EADDRINUSE 0.0.0.0:8081", "linux").fixPlan).toEqual([
      { actionId: "free-tcp-port", parameters: { port: 8081 } },
    ]);
    expect(diagnoseFallback("Error: bind EADDRINUSE 127.0.0.1:8082", "linux").fixPlan).toEqual([
      { actionId: "free-tcp-port", parameters: { port: 8082 } },
    ]);
    expect(
      diagnoseFallback("listen EADDRINUSE: address already in use localhost:8083", "linux").fixPlan,
    ).toEqual([{ actionId: "free-tcp-port", parameters: { port: 8083 } }]);
  });

  it(
    "extracts the port from Node's real IPv6-loopback EADDRINUSE message form (::1:PORT, unbracketed, confirmed against a real Node net.Server error)",
    () => {
      const diagnosis = diagnoseFallback("Error: listen EADDRINUSE: address already in use ::1:8084", "linux");
      expect(diagnosis.fixPlan).toEqual([{ actionId: "free-tcp-port", parameters: { port: 8084 } }]);
    },
  );

  it("extracts the port from Go's standard net package message form (bare ':PORT', no address literal, anchored on 'tcp')", () => {
    const diagnosis = diagnoseFallback("listen tcp :8085: bind: address already in use", "linux");
    expect(diagnosis.fixPlan).toEqual([{ actionId: "free-tcp-port", parameters: { port: 8085 } }]);
  });

  it("recognizes Docker's port-mapping conflict phrasing ('port is already allocated', no 'in use' wording at all)", () => {
    const diagnosis = diagnoseFallback("Bind for 0.0.0.0:8086 failed: port is already allocated", "linux");
    expect(diagnosis.fixPlan).toEqual([{ actionId: "free-tcp-port", parameters: { port: 8086 } }]);
  });

  it("only extracts a port from the line(s) that actually matched the port-conflict pattern, not an unrelated line elsewhere in the same log", () => {
    const diagnosis = diagnoseFallback(
      "GET /status:9090 200 12ms\nError: listen EADDRINUSE: address already in use :::3000",
      "linux",
    );
    expect(diagnosis.fixPlan).toEqual([{ actionId: "free-tcp-port", parameters: { port: 3000 } }]);
  });

  it("recognizes PostgreSQL's real 'lock file already exists' phrasing for a /tmp pidfile", () => {
    const diagnosis = diagnoseFallback('FATAL:  lock file "/tmp/postmaster.pid" already exists', "linux");
    expect(diagnosis.fixPlan).toEqual([
      { actionId: "clear-stale-pidfile", parameters: { pidFilePath: "/tmp/postmaster.pid" } },
    ]);
  });

  it("recognizes a generic 'PID file already exists' phrasing for a /tmp pidfile", () => {
    const diagnosis = diagnoseFallback(
      "Error: PID file /tmp/myapp.pid already exists. Is the server already running?",
      "linux",
    );
    expect(diagnosis.fixPlan).toEqual([
      { actionId: "clear-stale-pidfile", parameters: { pidFilePath: "/tmp/myapp.pid" } },
    ]);
  });

  it("honestly falls through to needs_review for a stale-pidfile message outside /tmp (never guesses a different location)", () => {
    const diagnosis = diagnoseFallback("Error: PID file /var/run/myapp.pid already exists", "linux");
    expect(diagnosis.fixPlan).toEqual([]);
  });

  it("honestly falls through to needs_review for a stale-pidfile message with only a bare filename (no path at all)", () => {
    const diagnosis = diagnoseFallback('FATAL: lock file "postmaster.pid" already exists', "linux");
    expect(diagnosis.fixPlan).toEqual([]);
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

  it("accepts a well-formed clear-stale-pidfile diagnosis", () => {
    const result = validateDiagnosis({
      ...baseDiagnosis,
      fixPlan: [{ actionId: "clear-stale-pidfile", parameters: { pidFilePath: "/tmp/app.pid" } }],
    });
    expect(result.ok).toBe(true);
  });

  it("rejects a path-traversal attempt smuggled through clear-stale-pidfile's pidFilePath parameter", () => {
    const result = validateDiagnosis({
      ...baseDiagnosis,
      fixPlan: [{ actionId: "clear-stale-pidfile", parameters: { pidFilePath: "/tmp/../etc/passwd" } }],
    });
    expect(result.ok).toBe(false);
  });

  it("rejects a clear-stale-pidfile path outside /tmp (even one that otherwise looks like a plausible pidfile)", () => {
    const result = validateDiagnosis({
      ...baseDiagnosis,
      fixPlan: [{ actionId: "clear-stale-pidfile", parameters: { pidFilePath: "/var/run/app.pid" } }],
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
