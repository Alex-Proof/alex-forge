#!/usr/bin/env node
// Thin executable shim. Run `npm run build` first -- this imports the compiled output, not the
// TypeScript source, so it has no ts-node/tsx dependency at runtime.
import { main } from "../dist/cli.js";

const result = await main(process.argv.slice(2));
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
process.exit(result.exitCode);
