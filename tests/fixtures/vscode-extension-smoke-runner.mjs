// Spawned (via `xvfb-run -a node vscode-extension-smoke-runner.mjs`) by
// src/core/verification/verify-extension.ts to run a real, concrete functional check of a
// Forge-generated VS Code extension companion in an actual VS Code Extension Host instance --
// never a mock. Everything the test needs is passed in by environment variable so this file has
// no dependency on where it's invoked from.
//
// Output protocol (stdout, last matching line wins): the caller greps for one of these rather
// than guessing from VS Code's own log noise.
//   FORGE_RUNTIME_PASS
//   FORGE_RUNTIME_FAIL: <reason>
//   FORGE_RUNTIME_SKIP: <reason>
//
// The distinction that matters: once @vscode/test-electron actually launches VS Code and our
// extensionTestsPath module runs to completion (pass or throw), that is a real, concrete answer
// about the generated extension -- a non-zero exit there is TestRunFailedError, and this is
// reported as FORGE_RUNTIME_FAIL (a real defect), never skipped. Anything that prevents the test
// from running at all (VS Code could not be resolved/downloaded, no display server, etc.) is an
// environment limitation, not evidence about the extension, and is reported as
// FORGE_RUNTIME_SKIP.
import { runTests } from "@vscode/test-electron";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const extensionDevelopmentPath = process.env.FORGE_EXTENSION_DEV_PATH;
const userDataDir = process.env.FORGE_USER_DATA_DIR;

if (!extensionDevelopmentPath || !userDataDir) {
  console.log("FORGE_RUNTIME_SKIP: missing required FORGE_EXTENSION_DEV_PATH/FORGE_USER_DATA_DIR environment variables");
  process.exit(0);
}

try {
  await runTests({
    extensionDevelopmentPath,
    extensionTestsPath: path.join(__dirname, "vscode-extension-smoke-test.cjs"),
    extensionTestsEnv: {
      FORGE_EXTENSION_ID: process.env.FORGE_EXTENSION_ID ?? "",
      FORGE_EXPECTED_COMMANDS: process.env.FORGE_EXPECTED_COMMANDS ?? "[]",
      FORGE_SHOW_DETAILS_COMMAND: process.env.FORGE_SHOW_DETAILS_COMMAND ?? "",
      FORGE_EXPECTED_WEBVIEW_LABEL_CONTAINS: process.env.FORGE_EXPECTED_WEBVIEW_LABEL_CONTAINS ?? "",
    },
    launchArgs: ["--no-sandbox", "--disable-gpu", `--user-data-dir=${userDataDir}`],
  });
  console.log("FORGE_RUNTIME_PASS");
} catch (error) {
  const isRealTestFailure = error instanceof Error && error.constructor.name === "TestRunFailedError";
  const message = error instanceof Error ? error.message : String(error);
  if (isRealTestFailure) {
    console.log(`FORGE_RUNTIME_FAIL: the extension's own activation/assertions failed inside a real VS Code Extension Host: ${message}`);
    process.exit(1);
  }
  console.log(`FORGE_RUNTIME_SKIP: could not launch a real VS Code Extension Host in this environment: ${message}`);
  process.exit(0);
}
