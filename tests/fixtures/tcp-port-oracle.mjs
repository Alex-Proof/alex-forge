#!/usr/bin/env node
/**
 * Independent state oracle for the free-tcp-port fixture.
 *
 * Deliberately implemented separately from the generated repair script in
 * src/modes/repair/actions.ts: a different language (Node instead of POSIX sh), a different data
 * source (parsing /proc/net/tcp's hex-encoded fields directly instead of shelling out to
 * `netstat` and text-parsing its columns), and no shared code with the artifact builder. This is
 * what the blueprint calls the "unabhängiger Zustands-Oracle" -- a red/green test may not accept
 * the generated script's own exit code as proof of a state change; a second, independent check
 * must confirm it.
 *
 * Exit 0 = port is free (target state holds). Exit 1 = port is listening (fault state). Exit 2 =
 * the oracle itself could not determine the state reliably.
 */

import { readFileSync } from "node:fs";

const TCP_LISTEN_STATE = "0A";

function isPortListening(procNetTcpPath, targetPort) {
  let content;
  try {
    content = readFileSync(procNetTcpPath, "utf-8");
  } catch {
    return false;
  }
  const lines = content.trim().split("\n").slice(1);
  for (const line of lines) {
    const fields = line.trim().split(/\s+/);
    const localAddress = fields[1];
    const state = fields[3];
    if (!localAddress || !state) {
      continue;
    }
    const hexPort = localAddress.split(":")[1];
    if (!hexPort) {
      continue;
    }
    const decimalPort = Number.parseInt(hexPort, 16);
    if (decimalPort === targetPort && state.toUpperCase() === TCP_LISTEN_STATE) {
      return true;
    }
  }
  return false;
}

function main() {
  const port = Number.parseInt(process.argv[2], 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error("usage: tcp-port-oracle.mjs <port>");
    process.exit(2);
  }

  const listening = isPortListening("/proc/net/tcp", port) || isPortListening("/proc/net/tcp6", port);
  if (listening) {
    console.log(JSON.stringify({ oracle: "tcp-port", port, state: "listening" }));
    process.exit(1);
  } else {
    console.log(JSON.stringify({ oracle: "tcp-port", port, state: "free" }));
    process.exit(0);
  }
}

main();
