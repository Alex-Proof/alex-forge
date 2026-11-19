import { writeFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createSandbox, type SandboxOptions } from "./sandbox.js";
import { verifyDiff, type DiffVerificationFixture } from "./verify-diff.js";

const sandboxOptions: SandboxOptions = {
  network: "disabled",
  readOnlyRoot: true,
  cpuLimit: "0.5",
  memoryLimitMb: 128,
  processLimit: 32,
  image: "alpine:3.20",
};

// Real fault, real fix, real independent oracle -- nothing mocked, matching this repo's own rule
// (see sandbox.test.ts: "a mock sandbox is not a sandbox"). The fault is a one-line typo in
// greet.sh ("Helo" instead of "Hello"). `verificationCommand` runs the script and checks its
// *output*; `oracleCommand` statically greps the *source* for the typo -- two independently
// implemented ways of detecting the same fault, so a diff that fools one but not the other is
// still caught (see docs/ASSUMPTIONS.md A-026 in alex-core for why this format needs two).
const GREET_SCRIPT_BUGGY = '#!/bin/sh\necho "Helo, World"\n';

const FIX_DIFF = [
  "--- a/greet.sh",
  "+++ b/greet.sh",
  "@@ -1,2 +1,2 @@",
  " #!/bin/sh",
  '-echo "Helo, World"',
  '+echo "Hello, World"',
  "",
].join("\n");

const VERIFICATION_COMMAND = "sh greet.sh | grep -q 'Hello, World'";
const ORACLE_COMMAND =
  "if grep -q 'Helo,' greet.sh; then echo '{\"oracle\":\"fault_present\"}'; exit 1; " +
  "else echo '{\"oracle\":\"fault_absent\"}'; exit 0; fi";

function baseFixture(diffText: string): DiffVerificationFixture {
  return {
    setupCommand: "true",
    diffText,
    verificationCommand: VERIFICATION_COMMAND,
    oracleCommand: ORACLE_COMMAND,
  };
}

describe("verifyDiff fixture (real sandbox, real patch, real independent oracle)", () => {
  it(
    "reproduces the fault, applies a correct fix, and reaches L3 with both checks and the oracle agreeing",
    async () => {
      const sandbox = await createSandbox(sandboxOptions);
      try {
        await writeFile(path.join(sandbox.hostWorkDir, "greet.sh"), GREET_SCRIPT_BUGGY, { mode: 0o755 });

        const summary = await verifyDiff(sandbox, baseFixture(FIX_DIFF));

        expect(summary.status).toBe("passed");
        expect(summary.level).toBe("L3_state_transition_verified");
        for (const check of summary.checks) {
          expect(check.status).toBe("passed");
        }
      } finally {
        await sandbox.destroy();
      }
    },
    20_000,
  );

  it(
    "refuses a diff that no longer applies (never forces a patch)",
    async () => {
      const sandbox = await createSandbox(sandboxOptions);
      try {
        // greet.sh does not contain the exact context lines the diff expects.
        await writeFile(path.join(sandbox.hostWorkDir, "greet.sh"), '#!/bin/sh\necho "completely different"\n', {
          mode: 0o755,
        });

        const summary = await verifyDiff(sandbox, baseFixture(FIX_DIFF));

        expect(summary.status).toBe("not_verified");
        const applyCheck = summary.checks.find((c) => c.name === "apply_check");
        expect(applyCheck?.status).toBe("failed");
      } finally {
        await sandbox.destroy();
      }
    },
    20_000,
  );

  it(
    "resolves to not_verified when the finding does not reproduce before any diff is applied",
    async () => {
      const sandbox = await createSandbox(sandboxOptions);
      try {
        // Already fixed -- the precondition oracle must report fault_absent, not fault_present.
        await writeFile(path.join(sandbox.hostWorkDir, "greet.sh"), '#!/bin/sh\necho "Hello, World"\n', {
          mode: 0o755,
        });

        const summary = await verifyDiff(sandbox, baseFixture(FIX_DIFF));

        expect(summary.status).toBe("not_verified");
        const precondition = summary.checks.find((c) => c.name === "precondition_oracle");
        expect(precondition?.status).toBe("failed");
      } finally {
        await sandbox.destroy();
      }
    },
    20_000,
  );

  it(
    "fails when the diff makes the verification command pass but the independent oracle still finds the fault",
    async () => {
      const sandbox = await createSandbox(sandboxOptions);
      try {
        await writeFile(path.join(sandbox.hostWorkDir, "greet.sh"), GREET_SCRIPT_BUGGY, { mode: 0o755 });

        // A "fix" that satisfies verificationCommand (prints the right line) via a second echo,
        // while leaving the original typo'd line (and therefore the oracle's grep target) intact.
        const foolingDiff = [
          "--- a/greet.sh",
          "+++ b/greet.sh",
          "@@ -1,2 +1,3 @@",
          " #!/bin/sh",
          ' echo "Helo, World"',
          '+echo "Hello, World"',
          "",
        ].join("\n");

        const summary = await verifyDiff(sandbox, baseFixture(foolingDiff));

        expect(summary.status).toBe("failed");
        const postcondition = summary.checks.find((c) => c.name === "postcondition_oracle");
        expect(postcondition?.status).toBe("failed");
      } finally {
        await sandbox.destroy();
      }
    },
    20_000,
  );
});
