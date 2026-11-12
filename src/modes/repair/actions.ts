import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
/** Repo-root-relative tests/fixtures/, resolved from this module's own location. */
const FIXTURES_DIR = path.resolve(__dirname, "../../../tests/fixtures");

/**
 * Registered repair actions. This is the allowlist required by the blueprint: a diagnosis may
 * only reference an actionId that is registered here, with parameters validated against that
 * action's own schema. Free-form shell commands never reach code generation.
 */

export const FreeTcpPortParametersSchema = z.object({
  port: z.number().int().min(1).max(65535),
});

export type FreeTcpPortParameters = z.infer<typeof FreeTcpPortParametersSchema>;

function generateFreeTcpPortScript(rawParameters: unknown): string {
  const { port } = FreeTcpPortParametersSchema.parse(rawParameters);

  return `#!/bin/sh
set -eu

PORT=${port}

usage() {
  echo "Usage: \$0 (--check|--dry-run|--fix|--verify) [--json]" >&2
}

mode=""
json=0
for arg in "$@"; do
  case "$arg" in
    --check|--dry-run|--fix|--verify)
      if [ -n "$mode" ]; then
        echo "error: only one of --check/--dry-run/--fix/--verify may be given at a time" >&2
        exit 2
      fi
      mode="$arg"
      ;;
    --json)
      json=1
      ;;
    *)
      echo "error: unknown flag: $arg" >&2
      exit 2
      ;;
  esac
done

if [ -z "$mode" ]; then
  usage
  exit 2
fi

if ! command -v netstat >/dev/null 2>&1; then
  echo "error: netstat is not available in this environment, state cannot be determined reliably" >&2
  exit 2
fi

find_listener_pid() {
  line=$(netstat -ltnp 2>/dev/null | grep ":\${PORT} " || true)
  if [ -z "$line" ]; then
    return 1
  fi
  pidprog=$(printf '%s' "$line" | awk '{print $7}')
  pid=$(printf '%s' "$pidprog" | cut -d/ -f1)
  if [ -z "$pid" ] || [ "$pid" = "-" ]; then
    return 1
  fi
  printf '%s\\n' "$pid"
  return 0
}

report() {
  status="$1"
  message="$2"
  if [ "$json" = "1" ]; then
    printf '{"status":"%s","port":%s,"message":"%s"}\\n' "$status" "$PORT" "$message"
  else
    printf '%s\\n' "$message"
  fi
}

case "$mode" in
  --check)
    if pid=$(find_listener_pid); then
      report "fault_present" "port $PORT is held by PID $pid"
      exit 1
    else
      report "ok" "port $PORT is free"
      exit 0
    fi
    ;;
  --dry-run)
    if pid=$(find_listener_pid); then
      report "plan" "would terminate PID $pid currently listening on port $PORT"
    else
      report "plan" "port $PORT is already free, no action planned"
    fi
    exit 0
    ;;
  --fix)
    if pid=$(find_listener_pid); then
      kill "$pid" 2>/dev/null || true
      i=0
      while [ "$i" -lt 20 ]; do
        if ! find_listener_pid >/dev/null 2>&1; then
          break
        fi
        i=$((i + 1))
        sleep 0.1
      done
      if still=$(find_listener_pid 2>/dev/null); then
        kill -9 "$still" 2>/dev/null || true
        sleep 0.2
      fi
      if find_listener_pid >/dev/null 2>&1; then
        report "error" "failed to free port $PORT"
        exit 2
      fi
      report "fixed" "freed port $PORT (was held by PID $pid)"
      exit 0
    else
      report "ok" "port $PORT was already free, nothing to fix"
      exit 0
    fi
    ;;
  --verify)
    if pid=$(find_listener_pid); then
      report "still_blocked" "port $PORT is still held by PID $pid"
      exit 1
    else
      report "ok" "port $PORT is confirmed free"
      exit 0
    fi
    ;;
esac
`;
}

function cspHash(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("base64");
}

/**
 * Standalone, offline HTML report for the same action. A browser cannot free a TCP port on its
 * own, so this page never claims to -- it embeds the exact same verified repair.sh (download
 * only, no execution) and otherwise only runs a small piece of real client-side logic (port
 * input validation) that can itself be function-tested with fixed inputs. Rendering is always
 * via textContent, never innerHTML, and the CSP allows only the two inline blocks below by their
 * exact sha256 hash -- no 'unsafe-inline', no external resources, nothing network-reachable.
 */
function generateFreeTcpPortHtml(rawParameters: unknown): string {
  const { port } = FreeTcpPortParametersSchema.parse(rawParameters);
  const scriptContentJson = JSON.stringify(generateFreeTcpPortScript(rawParameters));

  const styleContent = `body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
pre{background:#f0f0f0;padding:1rem;overflow-x:auto;white-space:pre-wrap}
input{font:inherit;padding:.25rem .5rem}
#validation-result{font-weight:bold}`;

  const scriptContent = `(function () {
  "use strict";
  var SCRIPT_CONTENT = ${scriptContentJson};

  document.getElementById("script-content").textContent = SCRIPT_CONTENT;

  var downloadLink = document.getElementById("download-link");
  var blob = new Blob([SCRIPT_CONTENT], { type: "text/x-sh" });
  downloadLink.href = URL.createObjectURL(blob);
  downloadLink.download = "repair.sh";

  var portInput = document.getElementById("port-input");
  var validationResult = document.getElementById("validation-result");

  function validate(rawValue) {
    var trimmed = String(rawValue).trim();
    var port = Number(trimmed);
    var isValid =
      trimmed.length > 0 && Number.isInteger(port) && port >= 1 && port <= 65535 && String(port) === trimmed;
    validationResult.textContent = isValid
      ? "Valid port number: " + port
      : "Not a valid port number (must be a whole number from 1 to 65535).";
  }

  portInput.addEventListener("input", function () {
    validate(portInput.value);
  });
  validate(portInput.value);
})();`;

  const csp = [
    "default-src 'none'",
    `script-src 'sha256-${cspHash(scriptContent)}'`,
    `style-src 'sha256-${cspHash(styleContent)}'`,
    "img-src 'none'",
    "connect-src 'none'",
    "form-action 'none'",
    "base-uri 'none'",
  ].join("; ");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forge repair report: free TCP port ${port}</title>
<style>${styleContent}</style>
</head>
<body>
<h1>Forge repair report</h1>
<p>Action: <code>free-tcp-port</code> &middot; Port <code>${port}</code></p>
<p>This page does not and cannot free the port itself -- a browser has no access to your
system's processes. It only shows the already-verified script below for you to download and
run yourself, and lets you check whether a port number is valid input.</p>
<h2>Generated script</h2>
<pre id="script-content"></pre>
<p><a id="download-link" href="#">Download repair.sh</a></p>
<h2>Validate a port number</h2>
<label for="port-input">Port number</label>
<input id="port-input" type="text" value="${port}" inputmode="numeric" autocomplete="off">
<p id="validation-result" aria-live="polite"></p>
<script>${scriptContent}</script>
</body>
</html>
`;
}

/**
 * Everything Forge's own verification needs to reproduce this action's fault in a disposable
 * sandbox and confirm the fix independently. This is never run against the user's real system --
 * it is Forge's synthetic reproduction of the fault type, used to prove the generated script's
 * own logic is correct before anything is handed to the user. The oracle asset must be
 * implemented independently of the generated script (see tests/fixtures/*-oracle.mjs).
 */
export interface ActionFixture {
  setupCommand: string;
  oracleCommand: string;
  oracleAssetSourcePath: string;
  oracleAssetStagedName: string;
  sandboxImage: string;
}

export interface RegisteredAction {
  actionId: string;
  parametersSchema: z.ZodTypeAny;
  /** Re-validates `rawParameters` itself; never trusts an already-typed caller. */
  generateScript: (rawParameters: unknown) => string;
  buildFixture: (rawParameters: unknown) => ActionFixture;
  /** Re-validates `rawParameters` itself. Optional: not every action has an HTML report yet. */
  generateHtml?: (rawParameters: unknown) => string;
}

function buildFreeTcpPortFixture(rawParameters: unknown): ActionFixture {
  const { port } = FreeTcpPortParametersSchema.parse(rawParameters);
  return {
    setupCommand: `nc -l -p ${port} &`,
    oracleCommand: `node tcp-port-oracle.mjs ${port}`,
    oracleAssetSourcePath: path.join(FIXTURES_DIR, "tcp-port-oracle.mjs"),
    oracleAssetStagedName: "tcp-port-oracle.mjs",
    sandboxImage: "node:22-alpine",
  };
}

export const ACTION_REGISTRY: Readonly<Record<string, RegisteredAction>> = Object.freeze({
  "free-tcp-port": {
    actionId: "free-tcp-port",
    parametersSchema: FreeTcpPortParametersSchema,
    generateScript: generateFreeTcpPortScript,
    buildFixture: buildFreeTcpPortFixture,
    generateHtml: generateFreeTcpPortHtml,
  },
});

export function getRegisteredAction(actionId: string): RegisteredAction | undefined {
  return ACTION_REGISTRY[actionId];
}
