import type { Redaction } from "../../types/policy.js";
import { SECRET_PATTERNS, type SecretPattern } from "./rules.js";

export interface SecretScanResult {
  /** Text with every matched secret pattern replaced by a redaction marker. */
  redactedText: string;
  /** One entry per match, in order of appearance. */
  matches: Array<{ ruleId: string; message: string; severity: SecretPattern["severity"] }>;
  redactions: Redaction[];
}

/**
 * Scans text against the known secret catalog and returns a redacted copy plus a record of what
 * was found. Called unconditionally before any model call, independent of whether the policy
 * decision will ultimately block the input.
 */
export function scanAndRedactSecrets(text: string): SecretScanResult {
  let redactedText = text;
  const matches: SecretScanResult["matches"] = [];
  const redactions: Redaction[] = [];

  for (const secretPattern of SECRET_PATTERNS) {
    // Clone the regex per use: a shared `/g` instance's lastIndex must never leak between calls.
    const pattern = new RegExp(secretPattern.pattern.source, secretPattern.pattern.flags);
    redactedText = redactedText.replace(pattern, (match: string, ...rest: unknown[]) => {
      const offset = typeof rest[rest.length - 2] === "number" ? (rest[rest.length - 2] as number) : undefined;
      matches.push({
        ruleId: secretPattern.ruleId,
        message: secretPattern.message,
        severity: secretPattern.severity,
      });
      redactions.push({
        ruleId: secretPattern.ruleId,
        location: offset !== undefined ? `offset:${offset}` : undefined,
      });
      return `[REDACTED:${secretPattern.ruleId}]`;
    });
  }

  return { redactedText, matches, redactions };
}
