import type { PolicyFinding } from "../../types/policy.js";
import { INJECTION_PATTERNS } from "./rules.js";

/**
 * Scans text for prompt-injection indicators. Logs and source files are data, never instructions:
 * this never grants the scanned text any authority, it only flags it for the policy decision.
 */
export function detectInjection(text: string): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  for (const injectionPattern of INJECTION_PATTERNS) {
    const pattern = new RegExp(injectionPattern.pattern.source, injectionPattern.pattern.flags);
    const match = pattern.exec(text);
    if (match) {
      findings.push({
        ruleId: injectionPattern.ruleId,
        severity: injectionPattern.severity,
        message: injectionPattern.message,
        location: `offset:${match.index}`,
      });
    }
  }

  return findings;
}
