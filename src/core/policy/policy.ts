import path from "node:path";
import type { PolicyDecision, PolicyEngine, PolicyFinding, PolicyStage, Redaction } from "../../types/policy.js";
import { COMMAND_RULES, FORBIDDEN_PATH_RULES, SECRET_PATTERNS } from "./rules.js";
import { detectInjection } from "./injection.js";
import { scanAndRedactSecrets } from "./redact.js";

export const MAX_TEXT_LENGTH = 500_000;
export const MAX_FILE_BYTES = 1_000_000;
export const MAX_TOTAL_INPUT_BYTES = 5_000_000;

/**
 * Runs `fn` and turns any thrown error into a blocked decision instead of letting it propagate as
 * an allow-by-default. Policy, validation, or runner errors must never resolve to an allowed
 * input -- this is the single chokepoint that guarantees that for every public method below.
 */
export function withFailClosed(onErrorRuleId: string, fn: () => PolicyDecision): PolicyDecision {
  try {
    return fn();
  } catch (error) {
    return {
      allowed: false,
      findings: [
        {
          ruleId: onErrorRuleId,
          severity: "block",
          message: `Policy check failed internally and fails closed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        },
      ],
      reason: "internal policy error -- failing closed",
    };
  }
}

function decide(findings: PolicyFinding[], redactions: Redaction[]): PolicyDecision {
  const blocking = findings.filter((f) => f.severity === "block");
  if (blocking.length > 0) {
    return {
      allowed: false,
      findings,
      reason: blocking.map((f) => f.message).join("; "),
    };
  }
  return { allowed: true, findings, redactions };
}

function isLikelyBinary(content: Uint8Array): boolean {
  const sampleLength = Math.min(content.length, 8_000);
  for (let i = 0; i < sampleLength; i++) {
    if (content[i] === 0) {
      return true;
    }
  }
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(content);
    return false;
  } catch {
    return true;
  }
}

function normalizePathSeparators(rawPath: string): string {
  return rawPath.replace(/\\/g, "/");
}

function hasTraversalSegment(rawPath: string): boolean {
  return normalizePathSeparators(rawPath)
    .split("/")
    .some((segment) => segment === "..");
}

function isAbsolutePath(rawPath: string): boolean {
  return (
    rawPath.startsWith("/") ||
    /^[A-Za-z]:[/\\]/.test(rawPath) ||
    rawPath.startsWith("\\\\")
  );
}

export class ForgePolicyEngine implements PolicyEngine {
  inspectText(text: string, _stage: PolicyStage): PolicyDecision {
    return withFailClosed("policy-internal-error-text", () => {
      const findings: PolicyFinding[] = [];

      if (text.length > MAX_TEXT_LENGTH) {
        findings.push({
          ruleId: "input-too-large",
          severity: "block",
          message: `Input exceeds the maximum allowed length of ${MAX_TEXT_LENGTH} characters`,
        });
      }

      const secretScan = scanAndRedactSecrets(text);
      for (const match of secretScan.matches) {
        findings.push({ ruleId: match.ruleId, severity: match.severity, message: match.message });
      }

      findings.push(...detectInjection(text));

      const redactions = secretScan.redactions.filter((redaction) =>
        secretScan.matches.some((m) => m.ruleId === redaction.ruleId && m.severity !== "block"),
      );

      return decide(findings, redactions);
    });
  }

  inspectPath(rawPath: string, _stage: PolicyStage): PolicyDecision {
    return withFailClosed("policy-internal-error-path", () => {
      const findings: PolicyFinding[] = [];

      if (rawPath.includes("\0")) {
        findings.push({ ruleId: "path-null-byte", severity: "block", message: "Path contains a null byte" });
      }
      if (hasTraversalSegment(rawPath)) {
        findings.push({
          ruleId: "path-traversal",
          severity: "block",
          message: "Path contains a '..' traversal segment",
          location: rawPath,
        });
      }
      if (isAbsolutePath(rawPath)) {
        findings.push({
          ruleId: "path-absolute-outside-workspace",
          severity: "block",
          message: "Absolute paths are not permitted; paths must stay within the workspace",
          location: rawPath,
        });
      }

      const normalized = normalizePathSeparators(rawPath);
      for (const rule of FORBIDDEN_PATH_RULES) {
        if (rule.pattern.test(normalized)) {
          findings.push({ ruleId: rule.ruleId, severity: rule.severity, message: rule.message, location: rawPath });
        }
      }

      return decide(findings, []);
    });
  }

  inspectCommand(executable: string, args: string[]): PolicyDecision {
    return withFailClosed("policy-internal-error-command", () => {
      const findings: PolicyFinding[] = [];
      const base = path.basename(executable).toLowerCase().replace(/\.exe$/, "");

      for (const rule of COMMAND_RULES) {
        if (rule.matches(base, args)) {
          findings.push({ ruleId: rule.ruleId, severity: rule.severity, message: rule.message });
        }
      }

      const joinedArgs = args.join(" ");
      for (const secretPattern of SECRET_PATTERNS) {
        if (secretPattern.severity !== "block") {
          continue;
        }
        const pattern = new RegExp(secretPattern.pattern.source, secretPattern.pattern.flags);
        if (pattern.test(joinedArgs)) {
          findings.push({
            ruleId: "secret-in-command-argument",
            severity: "block",
            message: `Command argument contains what looks like a secret (${secretPattern.message})`,
          });
        }
      }

      return decide(findings, []);
    });
  }

  inspectFiles(
    files: Array<{ path: string; content: Uint8Array }>,
    stage: PolicyStage,
  ): PolicyDecision {
    return withFailClosed("policy-internal-error-files", () => {
      const findings: PolicyFinding[] = [];
      const redactions: Redaction[] = [];

      const totalBytes = files.reduce((sum, file) => sum + file.content.byteLength, 0);
      if (totalBytes > MAX_TOTAL_INPUT_BYTES) {
        return decide(
          [
            {
              ruleId: "input-too-large-total",
              severity: "block",
              message: `Total input size ${totalBytes} bytes exceeds the maximum of ${MAX_TOTAL_INPUT_BYTES} bytes`,
            },
          ],
          [],
        );
      }

      for (const file of files) {
        if (file.content.byteLength > MAX_FILE_BYTES) {
          findings.push({
            ruleId: "input-file-too-large",
            severity: "block",
            message: `File exceeds the maximum allowed size of ${MAX_FILE_BYTES} bytes`,
            location: file.path,
          });
          continue;
        }

        const pathDecision = this.inspectPath(file.path, stage);
        findings.push(...pathDecision.findings);

        if (isLikelyBinary(file.content)) {
          findings.push({
            ruleId: "input-binary-content-unsupported",
            severity: "block",
            message: "Binary content is not a supported input type",
            location: file.path,
          });
          continue;
        }

        const text = new TextDecoder("utf-8").decode(file.content);
        const textDecision = this.inspectText(text, stage);
        findings.push(...textDecision.findings);
        if (textDecision.allowed) {
          redactions.push(...textDecision.redactions);
        }
      }

      return decide(findings, redactions);
    });
  }
}

export const policyEngine = new ForgePolicyEngine();
