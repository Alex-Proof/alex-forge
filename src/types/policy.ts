export type PolicyStage = "input" | "diagnosis" | "generated-code" | "package";

export interface PolicyFinding {
  ruleId: string;
  severity: "info" | "warning" | "block";
  message: string;
  location?: string;
}

export interface Redaction {
  ruleId: string;
  location?: string;
}

export type PolicyDecision =
  | { allowed: true; findings: PolicyFinding[]; redactions: Redaction[] }
  | { allowed: false; findings: PolicyFinding[]; reason: string };

export interface PolicyEngine {
  inspectText(text: string, stage: PolicyStage): PolicyDecision;
  inspectPath(path: string, stage: PolicyStage): PolicyDecision;
  inspectCommand(executable: string, args: string[]): PolicyDecision;
  inspectFiles(
    files: Array<{ path: string; content: Uint8Array }>,
    stage: PolicyStage,
  ): PolicyDecision;
}
