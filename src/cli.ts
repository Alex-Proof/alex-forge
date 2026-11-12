import { copyFile, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { policyEngine } from "./core/policy/policy.js";
import { scanAndRedactSecrets } from "./core/policy/redact.js";
import { diagnoseFallback, generateCliArtifact } from "./modes/repair/diagnose.js";
import { getRegisteredAction } from "./modes/repair/actions.js";
import { createSandbox } from "./core/verification/sandbox.js";
import { verifyRedGreen } from "./core/verification/verify-cli.js";
import { buildEvidence } from "./core/evidence/evidence.js";
import { exportRepairPackage, readArtifactAndEvidenceFromZip } from "./core/export/zip-exporter.js";
import { independentlyVerify } from "./core/evidence/independent-verifier.js";
import { admitToCatalog } from "./core/catalog/catalog.js";

export const FORGE_VERSION = "0.0.1";

export interface CliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

function ok(stdout: string): CliResult {
  return { exitCode: 0, stdout, stderr: "" };
}
function fail(exitCode: number, stderr: string): CliResult {
  return { exitCode, stdout: "", stderr };
}
/** A non-zero-but-still-a-report result (needs_review, rejected): JSON goes to stdout in --json
 * mode same as a success, since it's machine-readable output, not a usage/infra error. */
function report(exitCode: number, json: boolean, payload: unknown, humanMessage: string): CliResult {
  if (json) {
    return { exitCode, stdout: `${JSON.stringify(payload)}\n`, stderr: "" };
  }
  return { exitCode, stdout: "", stderr: humanMessage };
}

interface RepairArgs {
  logPath: string;
  os: "linux" | "windows" | "macos";
  outputDir: string;
  json: boolean;
  catalogDir: string;
}

function parseRepairArgs(args: string[]): RepairArgs | { error: string } {
  let logPath: string | undefined;
  let os: RepairArgs["os"] | undefined;
  let outputDir: string | undefined;
  let catalogDir = path.join(process.cwd(), ".forge", "catalog");
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--log":
        logPath = args[++i];
        break;
      case "--os": {
        const value = args[++i];
        if (value !== "linux" && value !== "windows" && value !== "macos") {
          return { error: `invalid --os value: ${value ?? "(missing)"}` };
        }
        os = value;
        break;
      }
      case "--output":
        outputDir = args[++i];
        break;
      case "--catalog-dir":
        catalogDir = args[++i] ?? catalogDir;
        break;
      case "--json":
        json = true;
        break;
      default:
        return { error: `unknown flag: ${arg}` };
    }
  }

  if (!logPath) return { error: "missing required flag: --log" };
  if (!os) return { error: "missing required flag: --os" };
  if (!outputDir) return { error: "missing required flag: --output" };

  return { logPath, os, outputDir, json, catalogDir };
}

/**
 * `forge repair`: log in, repair ZIP out. Every step that can fail honestly (policy block,
 * unrecognized fault, failed verification) stops the pipeline before anything is exported --
 * nothing partially-checked ever reaches --output. Forge never touches the user's own system
 * here: verification runs entirely against a synthetic, disposable sandbox reproduction of the
 * fault, never against whatever actually caused the user's log line.
 */
async function runRepair(args: string[]): Promise<CliResult> {
  const parsed = parseRepairArgs(args);
  if ("error" in parsed) {
    return fail(2, `error: ${parsed.error}\n`);
  }
  const { logPath, os, outputDir, json, catalogDir } = parsed;

  let rawLogText: string;
  try {
    rawLogText = await readFile(logPath, "utf-8");
  } catch (error) {
    return fail(2, `error: could not read --log file: ${error instanceof Error ? error.message : String(error)}\n`);
  }

  // Policy decides block/allow on the real input first -- redaction must never run before the
  // block check, or a block-tier secret (already replaced by a redaction marker) could never be
  // detected by the time the policy engine looks at it.
  const inputDecision = policyEngine.inspectText(rawLogText, "input");
  if (!inputDecision.allowed) {
    return fail(2, `error: input blocked by policy: ${inputDecision.reason}\n`);
  }
  const { redactedText } = scanAndRedactSecrets(rawLogText);

  const diagnosis = diagnoseFallback(redactedText, os);
  if (diagnosis.fixPlan.length === 0) {
    return report(1, json, { status: "needs_review", diagnosis }, `no registered action matched this log: ${diagnosis.rootCause}\n`);
  }

  const artifact = generateCliArtifact(diagnosis);
  if (!artifact.ok) {
    return fail(2, `error: ${artifact.reason}\n`);
  }

  const step = diagnosis.fixPlan[0];
  if (!step) {
    return fail(2, "error: diagnosis has no fix step despite a non-empty fixPlan\n");
  }
  const action = getRegisteredAction(step.actionId);
  if (!action) {
    return fail(2, `error: fixPlan references unregistered actionId: ${step.actionId}\n`);
  }
  const fixture = action.buildFixture(step.parameters);

  const sandbox = await createSandbox({
    network: "disabled",
    readOnlyRoot: true,
    cpuLimit: "0.5",
    memoryLimitMb: 128,
    processLimit: 32,
    image: fixture.sandboxImage,
  });

  let verification;
  try {
    await copyFile(fixture.oracleAssetSourcePath, path.join(sandbox.hostWorkDir, fixture.oracleAssetStagedName));
    await writeFile(path.join(sandbox.hostWorkDir, artifact.fileName), artifact.content, { mode: 0o755 });

    verification = await verifyRedGreen(sandbox, {
      setupCommand: fixture.setupCommand,
      oracleCommand: fixture.oracleCommand,
      cliCommand: (flag) => `sh ${artifact.fileName} ${flag}`,
    });
  } finally {
    await sandbox.destroy();
  }

  const artifactId = `forge-repair-${step.actionId}-${randomUUID()}`;
  const artifactBytes = new TextEncoder().encode(artifact.content);
  const evidence = buildEvidence({
    artifactId,
    artifactFileName: artifact.fileName,
    artifactFormat: "cli",
    artifactContent: artifactBytes,
    sourceLogRedactedText: redactedText,
    targetOS: os,
    sandboxImage: fixture.sandboxImage,
    verification,
    forgeVersion: FORGE_VERSION,
    templateVersion: "1.0.0",
  });

  if (verification.status !== "passed") {
    await mkdir(path.join(outputDir, "rejected"), { recursive: true });
    await writeFile(
      path.join(outputDir, "rejected", `${artifactId}.evidence.json`),
      `${JSON.stringify(evidence, null, 2)}\n`,
    );
    return report(
      1,
      json,
      { status: "rejected", verification },
      `verification did not pass (status=${verification.status}); nothing was exported. See ${path.join(outputDir, "rejected", `${artifactId}.evidence.json`)}\n`,
    );
  }

  const { zipPath } = await exportRepairPackage(outputDir, artifactId, {
    artifactFileName: artifact.fileName,
    artifactBytes,
    evidence,
    readmeContent: `# ${artifactId}\n\nGenerated by Forge ${FORGE_VERSION}. See evidence.json for the full, independently re-checked verification record.\n\nThis artifact is not installed or run automatically. Review it, then run it yourself:\n\n\`\`\`\nsh ${artifact.fileName} --check\nsh ${artifact.fileName} --dry-run\nsh ${artifact.fileName} --fix      # only after you approve the plan\nsh ${artifact.fileName} --verify\n\`\`\`\n`,
  });

  const readBack = readArtifactAndEvidenceFromZip(zipPath, artifact.fileName);
  const reVerification = independentlyVerify(readBack.evidence, readBack.artifactBytes);
  if (!reVerification.verified) {
    return fail(
      2,
      `error: independent re-verification of the exported package failed: ${reVerification.reasons.join("; ")}\n`,
    );
  }

  const evidenceBytes = new TextEncoder().encode(`${JSON.stringify(readBack.evidence, null, 2)}\n`);
  const admission = admitToCatalog(readBack.evidence, readBack.artifactBytes, evidenceBytes, FORGE_VERSION);
  if (!admission.admitted) {
    return fail(2, `error: catalog gate refused this package: ${admission.reasons.join("; ")}\n`);
  }

  await mkdir(catalogDir, { recursive: true });
  await writeFile(
    path.join(catalogDir, `${artifactId}.catalog.json`),
    `${JSON.stringify(admission.artifact, null, 2)}\n`,
  );

  const successReport = { status: "approved", zipPath, catalogArtifact: admission.artifact };
  return ok(
    json
      ? `${JSON.stringify(successReport)}\n`
      : `approved: ${zipPath}\nartifactHash: ${admission.artifact.artifactHash}\n`,
  );
}

async function runCatalogList(args: string[], defaultCatalogDir: string): Promise<CliResult> {
  let catalogDir = defaultCatalogDir;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--catalog-dir") {
      catalogDir = args[++i] ?? catalogDir;
    } else if (args[i] === "--json") {
      json = true;
    } else {
      return fail(2, `error: unknown flag: ${args[i]}\n`);
    }
  }

  let entries: string[];
  try {
    entries = await readdir(catalogDir);
  } catch {
    entries = [];
  }

  const records = await Promise.all(
    entries
      .filter((name) => name.endsWith(".catalog.json"))
      .map(async (name) => JSON.parse(await readFile(path.join(catalogDir, name), "utf-8"))),
  );

  if (json) {
    return ok(`${JSON.stringify(records)}\n`);
  }
  if (records.length === 0) {
    return ok("catalog is empty\n");
  }
  return ok(records.map((r) => `${r.artifactId}  ${r.status}  ${r.artifactHash}`).join("\n") + "\n");
}

export async function main(argv: string[]): Promise<CliResult> {
  const [command, ...rest] = argv;
  const defaultCatalogDir = path.join(process.cwd(), ".forge", "catalog");

  switch (command) {
    case "repair":
      return runRepair(rest);
    case "catalog": {
      if (rest[0] === "list") {
        return runCatalogList(rest.slice(1), defaultCatalogDir);
      }
      return fail(2, `error: unknown catalog subcommand: ${rest[0] ?? "(none)"}\n`);
    }
    case undefined:
      return fail(2, "error: missing command. Usage: forge repair --log <path> --os <linux|windows|macos> --output <dir>\n");
    default:
      return fail(2, `error: unknown command: ${command}\n`);
  }
}
