import { z } from "zod";

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

export interface RegisteredAction {
  actionId: string;
  parametersSchema: z.ZodTypeAny;
  /** Re-validates `rawParameters` itself; never trusts an already-typed caller. */
  generateScript: (rawParameters: unknown) => string;
}

export const ACTION_REGISTRY: Readonly<Record<string, RegisteredAction>> = Object.freeze({
  "free-tcp-port": {
    actionId: "free-tcp-port",
    parametersSchema: FreeTcpPortParametersSchema,
    generateScript: generateFreeTcpPortScript,
  },
});

export function getRegisteredAction(actionId: string): RegisteredAction | undefined {
  return ACTION_REGISTRY[actionId];
}
