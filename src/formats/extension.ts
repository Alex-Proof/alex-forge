/**
 * Manifest and dependency policy for Forge-generated VS Code extension companions (blueprint
 * section 13, Phase 8). A generated extension is a one-off, throwaway viewer for a single
 * diagnosed repair case -- it must never carry runtime dependencies, install scripts, broad
 * activation, or contributions beyond the two commands it needs. This only checks package.json
 * text; the real build/package and runtime checks live in
 * src/core/verification/verify-extension.ts, because a manifest can look fine and still fail to
 * package or activate.
 */

export interface ManifestFinding {
  ruleId: string;
  message: string;
}

export interface ManifestValidationResult {
  valid: boolean;
  findings: ManifestFinding[];
}

const REQUIRED_STRING_FIELDS = ["name", "publisher", "version", "main"] as const;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validates a Forge-generated extension's package.json text against a strict, narrow policy.
 * This is deliberately far stricter than what VS Code itself requires -- it only needs to accept
 * the one shape Forge's own generator produces, so anything wider than that is refused rather
 * than guessed at.
 */
export function validateExtensionManifest(rawManifestJson: string): ManifestValidationResult {
  const findings: ManifestFinding[] = [];

  let manifest: unknown;
  try {
    manifest = JSON.parse(rawManifestJson);
  } catch (error) {
    return {
      valid: false,
      findings: [{ ruleId: "manifest-invalid-json", message: `package.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}` }],
    };
  }

  if (!isPlainObject(manifest)) {
    return { valid: false, findings: [{ ruleId: "manifest-not-an-object", message: "package.json must be a JSON object" }] };
  }

  for (const field of REQUIRED_STRING_FIELDS) {
    if (typeof manifest[field] !== "string" || manifest[field] === "") {
      findings.push({ ruleId: "manifest-missing-field", message: `package.json is missing required string field "${field}"` });
    }
  }

  if (typeof manifest.main === "string") {
    if (manifest.main.includes("..") || manifest.main.startsWith("/")) {
      findings.push({ ruleId: "manifest-unsafe-main", message: `"main" must be a relative path inside the extension, got "${manifest.main}"` });
    }
  }

  const engines = manifest.engines;
  if (!isPlainObject(engines) || typeof engines.vscode !== "string" || engines.vscode === "") {
    findings.push({ ruleId: "manifest-missing-engines-vscode", message: 'package.json must declare engines.vscode' });
  }

  if ("scripts" in manifest) {
    findings.push({ ruleId: "manifest-forbidden-scripts", message: 'package.json must not declare an npm "scripts" field (no install-time code execution)' });
  }

  for (const depField of ["dependencies", "optionalDependencies", "peerDependencies"]) {
    const value = manifest[depField];
    if (isPlainObject(value) && Object.keys(value).length > 0) {
      findings.push({
        ruleId: "manifest-forbidden-dependency",
        message: `package.json must not declare runtime dependencies (found "${depField}": ${Object.keys(value).join(", ")}); a Forge-generated companion must be self-contained`,
      });
    }
  }

  const activationEvents = manifest.activationEvents;
  if (!Array.isArray(activationEvents) || activationEvents.length === 0) {
    findings.push({ ruleId: "manifest-missing-activation-events", message: "package.json must declare at least one activationEvents entry" });
  } else {
    for (const event of activationEvents) {
      if (typeof event !== "string" || !event.startsWith("onCommand:")) {
        findings.push({
          ruleId: "manifest-broad-activation-event",
          message: `activationEvents entry "${String(event)}" is not an "onCommand:" event; broad/eager activation (e.g. "*", "onStartupFinished") is not allowed`,
        });
      }
    }
  }

  const contributes = manifest.contributes;
  if (!isPlainObject(contributes)) {
    findings.push({ ruleId: "manifest-missing-contributes", message: "package.json must declare contributes.commands" });
  } else {
    const contributesKeys = Object.keys(contributes);
    const unexpectedKeys = contributesKeys.filter((key) => key !== "commands");
    if (unexpectedKeys.length > 0) {
      findings.push({
        ruleId: "manifest-unexpected-contribution",
        message: `package.json contributes unexpected point(s): ${unexpectedKeys.join(", ")}; only "commands" is allowed`,
      });
    }
    if (!Array.isArray(contributes.commands) || contributes.commands.length === 0) {
      findings.push({ ruleId: "manifest-missing-commands", message: "package.json must declare at least one entry in contributes.commands" });
    } else {
      for (const command of contributes.commands) {
        if (!isPlainObject(command) || typeof command.command !== "string" || typeof command.title !== "string") {
          findings.push({ ruleId: "manifest-invalid-command-entry", message: "every contributes.commands entry must have string \"command\" and \"title\" fields" });
        }
      }
    }
  }

  return { valid: findings.length === 0, findings };
}
