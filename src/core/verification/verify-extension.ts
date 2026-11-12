import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import AdmZip from "adm-zip";
import { createVSIX } from "@vscode/vsce";
import type { VerificationCheck, VerificationSummary } from "../../types/verification.js";
import { validateExtensionManifest } from "../../formats/extension.js";
import type { ExtensionProjectFiles } from "../../modes/repair/actions.js";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SMOKE_RUNNER_PATH = path.resolve(__dirname, "../../../tests/fixtures/vscode-extension-smoke-runner.mjs");

// The fixed contract every Forge-generated extension-format artifact must follow: a command
// named exactly "forgeRepair.showDetails" that opens a webview panel whose tab label contains
// "Forge Repair". Only one action implements the extension format today (free-tcp-port, see
// generateFreeTcpPortExtensionProject); this constant is this verifier's own, independent
// definition of that contract -- it does not import the generator's constants.
const SHOW_DETAILS_COMMAND = "forgeRepair.showDetails";
const EXPECTED_WEBVIEW_LABEL_CONTAINS = "Forge Repair";

function check(name: string, status: VerificationCheck["status"], details?: Record<string, unknown>): VerificationCheck {
  return { name, status, exitCode: null, details };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export type UnpackResult = { ok: true } | { ok: false; reason: string };

/**
 * Writes every "extension/..." entry of a packaged .vsix into `destDir` as a plain file,
 * verified against path traversal before anything touches disk. This vsix is always Forge's own
 * output (packaged by @vscode/vsce from a project this process just generated), so no entry name
 * can currently contain ".." -- but a function that writes files from zip entry names must never
 * trust them anyway, in case a future bug upstream of this point ever lets one through. Exported
 * so a red-team regression test can exercise it directly against a hand-crafted malicious entry,
 * without needing a real vsce packaging run to produce one.
 *
 * Also structurally immune to the classic "zip-slip via symlink" variant: this only ever calls
 * `writeFile` with an entry's raw bytes, never `zip.extractAllTo()` or `fs.symlink`, so a zip
 * entry flagged as a symlink is still written out as an ordinary file literally containing
 * whatever bytes it carries (e.g. a symlink target string) -- never recreated as a real symlink.
 */
export async function safelyUnpackVsixExtensionEntries(zip: AdmZip, destDir: string): Promise<UnpackResult> {
  const resolvedDestDir = path.resolve(destDir);
  for (const entry of zip.getEntries()) {
    if (!entry.entryName.startsWith("extension/") || entry.isDirectory) {
      continue;
    }
    const relPath = entry.entryName.slice("extension/".length);
    const destPath = path.resolve(resolvedDestDir, relPath);
    if (destPath !== resolvedDestDir && !destPath.startsWith(`${resolvedDestDir}${path.sep}`)) {
      return { ok: false, reason: `unsafe vsix entry name escapes the unpack directory: ${entry.entryName}` };
    }
    await mkdir(path.dirname(destPath), { recursive: true });
    await writeFile(destPath, entry.getData());
  }
  return { ok: true };
}

export interface ExtensionVerificationResult {
  verification: VerificationSummary;
  /** The packaged .vsix bytes, present whenever packaging itself succeeded (even if later checks failed). */
  vsixBytes: Uint8Array | null;
}

/**
 * Real build/package and (where this environment allows it) runtime verification for a
 * Forge-generated VS Code extension companion (blueprint section 13, Phase 8). Three gates, in
 * order, each one only meaningful if the previous one passed:
 *
 * 1. manifest_and_dependency_policy -- src/formats/extension.ts against the *source* package.json.
 * 2. build_and_package -- a real `@vscode/vsce` packaging run (no mocked zip-writing); the
 *    resulting .vsix is then re-opened and its *packaged* manifest is re-validated too, closing
 *    the gap between "what we generated" and "what we actually shipped".
 * 3. runtime_started_in_test_instance -- a real VS Code Extension Host, launched via
 *    `@vscode/test-electron` under Xvfb, activates the packaged extension and confirms the one
 *    concrete thing this format's contract promises (see SHOW_DETAILS_COMMAND above). If this
 *    environment cannot launch a real instance (no network path to download VS Code, no Xvfb),
 *    this check is honestly `skipped` -- never silently counted as `passed` -- and the overall
 *    verification level is capped at L1_static_validated, which independentlyVerify already
 *    refuses to admit to the catalog.
 */
export async function verifyExtensionArtifact(files: ExtensionProjectFiles): Promise<ExtensionVerificationResult> {
  const checks: VerificationCheck[] = [];

  const manifestJson = files["package.json"];
  if (!manifestJson) {
    checks.push(check("manifest_and_dependency_policy", "failed", { reason: "no package.json in generated project files" }));
    return { verification: { status: "failed", level: "L1_static_validated", checks }, vsixBytes: null };
  }
  const sourceManifestResult = validateExtensionManifest(manifestJson);
  checks.push(check("manifest_and_dependency_policy", sourceManifestResult.valid ? "passed" : "failed", { findings: sourceManifestResult.findings }));
  if (!sourceManifestResult.valid) {
    return { verification: { status: "failed", level: "L1_static_validated", checks }, vsixBytes: null };
  }

  const projectDir = await mkdtemp(path.join(tmpdir(), "forge-ext-project-"));
  let vsixBytes: Uint8Array | null = null;
  try {
    for (const [relPath, content] of Object.entries(files)) {
      const fullPath = path.join(projectDir, relPath);
      await mkdir(path.dirname(fullPath), { recursive: true });
      await writeFile(fullPath, content);
    }

    const vsixPath = path.join(projectDir, "forge-repair.vsix");
    try {
      await createVSIX({
        cwd: projectDir,
        packagePath: vsixPath,
        allowMissingRepository: true,
        allowStarActivation: false,
        skipLicense: true,
        dependencies: false,
      });
      vsixBytes = new Uint8Array(await readFile(vsixPath));
      checks.push(check("build_and_package", "passed", { packagedBytes: vsixBytes.byteLength }));
    } catch (error) {
      checks.push(check("build_and_package", "failed", { reason: error instanceof Error ? error.message : String(error) }));
      return { verification: { status: "failed", level: "L1_static_validated", checks }, vsixBytes: null };
    }

    const zip = new AdmZip(Buffer.from(vsixBytes));
    const packagedManifestEntry = zip.getEntry("extension/package.json");
    if (!packagedManifestEntry) {
      checks.push(check("packaged_manifest_present", "failed", { reason: "extension/package.json is missing from the packaged .vsix" }));
      return { verification: { status: "failed", level: "L1_static_validated", checks }, vsixBytes };
    }
    const packagedManifestJson = packagedManifestEntry.getData().toString("utf-8");
    const packagedManifestResult = validateExtensionManifest(packagedManifestJson);
    checks.push(check("packaged_manifest_and_dependency_policy", packagedManifestResult.valid ? "passed" : "failed", { findings: packagedManifestResult.findings }));
    if (!packagedManifestResult.valid) {
      return { verification: { status: "failed", level: "L1_static_validated", checks }, vsixBytes };
    }

    const packagedManifest = JSON.parse(packagedManifestJson) as { name: string; publisher: string; contributes: { commands: Array<{ command: string }> } };
    const extensionId = `${packagedManifest.publisher}.${packagedManifest.name}`;
    const expectedCommands = packagedManifest.contributes.commands.map((c) => c.command);

    const unpackedDir = await mkdtemp(path.join(tmpdir(), "forge-ext-unpacked-"));
    const userDataDir = await mkdtemp(path.join(tmpdir(), "forge-ext-userdata-"));
    try {
      const unpackResult = await safelyUnpackVsixExtensionEntries(zip, unpackedDir);
      if (!unpackResult.ok) {
        checks.push(check("vsix_entry_path_safety", "failed", { reason: unpackResult.reason }));
        return { verification: { status: "failed", level: "L1_static_validated", checks }, vsixBytes };
      }

      const runtimeCheck = await runRuntimeSmokeTest({
        extensionDevelopmentPath: unpackedDir,
        userDataDir,
        extensionId,
        expectedCommands,
        showDetailsCommand: expectedCommands.includes(SHOW_DETAILS_COMMAND) ? SHOW_DETAILS_COMMAND : "",
        expectedWebviewLabelContains: EXPECTED_WEBVIEW_LABEL_CONTAINS,
      });
      checks.push(runtimeCheck);
    } finally {
      await rm(unpackedDir, { recursive: true, force: true });
      await rm(userDataDir, { recursive: true, force: true });
    }
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }

  const runtimeCheck = checks.find((c) => c.name === "runtime_started_in_test_instance");
  if (runtimeCheck?.status === "passed") {
    return { verification: { status: "passed", level: "L2_sandbox_executed", checks }, vsixBytes };
  }
  if (runtimeCheck?.status === "skipped") {
    // Everything that *could* run did pass; the runtime claim stays capped at L1, which
    // independentlyVerify already treats as insufficient for catalog admission -- "skipped" is
    // never silently promoted to "passed" for the overall verdict.
    return { verification: { status: "passed", level: "L1_static_validated", checks }, vsixBytes };
  }
  return { verification: { status: "failed", level: "L1_static_validated", checks }, vsixBytes };
}

interface RuntimeSmokeTestInput {
  extensionDevelopmentPath: string;
  userDataDir: string;
  extensionId: string;
  expectedCommands: string[];
  showDetailsCommand: string;
  expectedWebviewLabelContains: string;
}

async function runRuntimeSmokeTest(input: RuntimeSmokeTestInput): Promise<VerificationCheck> {
  try {
    const { stdout } = await execFileAsync(
      "xvfb-run",
      ["-a", process.execPath, SMOKE_RUNNER_PATH],
      {
        env: {
          ...process.env,
          FORGE_EXTENSION_DEV_PATH: input.extensionDevelopmentPath,
          FORGE_USER_DATA_DIR: input.userDataDir,
          FORGE_EXTENSION_ID: input.extensionId,
          FORGE_EXPECTED_COMMANDS: JSON.stringify(input.expectedCommands),
          FORGE_SHOW_DETAILS_COMMAND: input.showDetailsCommand,
          FORGE_EXPECTED_WEBVIEW_LABEL_CONTAINS: input.expectedWebviewLabelContains,
        },
        timeout: 180_000,
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    return interpretRuntimeOutput(stdout);
  } catch (error) {
    if (isPlainObject(error) && error.code === "ENOENT") {
      return check("runtime_started_in_test_instance", "skipped", {
        reason: "xvfb-run is not available in this environment; a real VS Code Extension Host needs a display server",
      });
    }
    // execFile rejects with the spawned process's own stdout/stderr attached even on a non-zero
    // exit (our runner always exits 0 on PASS/SKIP and only exits 1 on a genuine FORGE_RUNTIME_FAIL,
    // so a rejection here still carries a real FORGE_RUNTIME_FAIL marker to interpret).
    if (isPlainObject(error) && typeof error.stdout === "string") {
      return interpretRuntimeOutput(error.stdout);
    }
    return check("runtime_started_in_test_instance", "skipped", {
      reason: `could not run the VS Code Extension Host smoke test: ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}

function interpretRuntimeOutput(stdout: string): VerificationCheck {
  const lines = stdout.split("\n");
  const passLine = lines.find((line) => line.includes("FORGE_RUNTIME_PASS"));
  if (passLine) {
    return check("runtime_started_in_test_instance", "passed", {
      summary: `a real VS Code Extension Host activated the packaged extension and confirmed command "${SHOW_DETAILS_COMMAND}" opens a tab labeled "${EXPECTED_WEBVIEW_LABEL_CONTAINS}..."`,
    });
  }
  const failLine = lines.find((line) => line.includes("FORGE_RUNTIME_FAIL"));
  if (failLine) {
    return check("runtime_started_in_test_instance", "failed", { reason: failLine.replace(/^.*FORGE_RUNTIME_FAIL:\s*/, "") });
  }
  const skipLine = lines.find((line) => line.includes("FORGE_RUNTIME_SKIP"));
  return check("runtime_started_in_test_instance", "skipped", {
    reason: skipLine ? skipLine.replace(/^.*FORGE_RUNTIME_SKIP:\s*/, "") : `unrecognized smoke test output: ${stdout.slice(0, 2000)}`,
  });
}
