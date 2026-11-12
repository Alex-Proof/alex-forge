# Alex Forge

Forge turns an error log into a checked repair artifact (CLI script and standalone HTML so far, a
VS Code extension later) -- and refuses to call anything "verified" unless a real, independent
check actually ran.

## Status: Phase 7 -- standalone HTML repair artifacts

**Implemented:** repository scaffold, TypeScript/CI setup, the type contracts (`src/types/`), the
policy engine (`src/core/policy/`), a real Docker-backed sandbox runner (`src/core/verification/`),
and the first repair mode (`src/modes/repair/`):

- a registered, schema-validated action allowlist (currently `free-tcp-port`) -- a diagnosis can
  never introduce a new capability just by naming an unregistered `actionId`
- a deterministic, offline diagnosis fallback that recognizes a TCP-port-in-use log pattern and
  otherwise honestly reports "no registered action matches" instead of guessing
- a CLI script generator implementing the five-flag contract (`--check`/`--dry-run`/`--fix`/
  `--verify`/`--json`) with exit codes `0`/`1`/`2` per the documented semantics
- `verifyRedGreen` (`src/core/verification/verify-cli.ts`): runs the full precondition/check/
  dry-run/fix/postcondition/verify protocol and cross-checks every state transition against
  `tests/fixtures/tcp-port-oracle.mjs`, an oracle deliberately implemented in a different
  language, reading `/proc/net/tcp` directly instead of reusing the generated script's own
  `netstat`-based check. A sandbox or policy failure resolves to `not_verified`/`blocked`, and a
  fault that can't be reproduced resolves to `not_verified` -- never to a guessed pass.
- a negative-control test proves the point: a deliberately "lying" script that fakes success via
  a self-trusted marker file passes its *own* self-check, but the independent oracle still catches
  that nothing actually changed, and the overall verdict is `failed`, not `passed`.

- `buildEvidence` (`src/core/evidence/`): produces a versioned `evidence.json` strictly from
  observed results -- the artifact hash is computed over the artifact's own bytes only (never
  circularly over the evidence itself), and the policy fields come from actually running the
  Phase 1 policy engine on the real input/output/package content, not from a caller's claim.
- `exportRepairPackage` (`src/core/export/`): writes a reproducible ZIP (`artifact/`,
  `evidence.json`, `manifest.json`, `README.md`, `checksums.txt`) atomically (temp name, then
  rename), with every entry name checked against path traversal / absolute paths before it's
  ever added to the archive.
- `independentlyVerify` (`src/core/evidence/independent-verifier.ts`): a second verifier that
  imports nothing from the evidence builder. It recomputes the artifact hash itself, and
  re-derives pass/fail from the raw `verification.checks` array rather than trusting
  `verification.status` as given -- so a forged or buggy "passed" claim whose own checks disagree
  is still caught.
- `admitToCatalog` (`src/core/catalog/`): the single, non-model-controlled function allowed to set
  `status: "approved"`, and it always goes through the independent verifier first.
- An end-to-end test runs the real free-tcp-port fixture through this entire chain -- diagnose,
  generate, verify in the sandbox, build evidence, export, re-open from disk, independently
  re-verify, admit -- and a companion test proves the lying-script case from Phase 4 is refused
  catalog admission.

- `forge repair` (`src/cli.ts`, shim at `bin/forge.mjs`): the actual end-to-end command. Reads a
  log file, policy-checks it (fail closed, before any redaction happens -- redacting first and
  checking policy second would let a redacted secret slip past the block it should trigger),
  diagnoses, generates, runs the real sandboxed red/green verification, builds evidence, exports
  a ZIP, re-opens it from disk, independently re-verifies it, and only then writes a catalog
  record. A log forge can't diagnose exits `1` with `needs_review` instead of guessing; a failed
  verification exits `1` with `rejected` and only the evidence (never the script) is kept under
  `<output>/rejected/`; anything policy-blocked or structurally invalid exits `2`.
- `forge catalog list`: lists the (file-based, append-only) catalog records written by successful
  `forge repair` runs.
- `tests/integration/forge-repair.test.ts`: the literal "log to ZIP" end-to-end test, driving the
  real CLI entry point against a real Docker sandbox -- nothing mocked.
- `tests/security/regression.test.ts`: a consolidated regression suite covering the blueprint's
  security test categories (prompt injection, path traversal, secret leakage, dangerous shell
  patterns, output-policy bypass, resource exhaustion, forged evidence, catalog bypass), run in CI
  on every push alongside everything else.
- `generateHtmlArtifact` (`src/modes/repair/diagnose.ts`) + `action.generateHtml`
  (`src/modes/repair/actions.ts`): a self-contained, offline `repair.html` report. It cannot and
  does not claim to free the port itself -- a browser has no OS-level access -- so it embeds the
  same verified `repair.sh` as a download-only Blob and otherwise only runs real client-side port
  validation logic, always rendered via `textContent` (never `innerHTML`). Its CSP allows only its
  own two inline `<script>`/`<style>` blocks, by exact sha256 hash -- no `'unsafe-inline'`, no
  external resources, `connect-src 'none'`.
- `validateHtmlArtifact` (`src/formats/html.ts`): static checks for external references, inline
  event handlers, `eval`, `innerHTML` assignment, and a CSP that is present and not weakened.
- `verifyHtmlArtifact` (`src/core/verification/verify-html.ts`): real functional verification in
  headless Chromium (the project's "no mocked sandbox" rule applies here too) -- confirms the
  page renders correctly for a fixed input, that typing DOM-XSS payload markup into the port
  field never executes and is never reflected as live markup, and that the CSP genuinely refuses
  to run a freshly injected inline script and genuinely blocks an outbound `fetch`. On success
  this reaches `L2_sandbox_executed` (a real sandboxed process actually ran the artifact); there
  is no OS-level state to red/green-verify for this format, so it never claims `L3`.
- The independent verifier (`src/core/evidence/independent-verifier.ts`) now accepts either the
  CLI's named `L3_state_transition_verified` protocol or a generic `L2_sandbox_executed` result
  (format-agnostic: every recorded check must have passed, and at least one must exist) --
  HTML artifacts go through the exact same evidence-build, ZIP-export, independent-re-verify, and
  catalog-admission chain as CLI artifacts, proven by a real end-to-end test.

### Usage

```bash
npm install
npm run build
node bin/forge.mjs repair --log ./error.log --os linux --output ./out [--json] [--catalog-dir ./.forge/catalog]
node bin/forge.mjs catalog list [--json] [--catalog-dir ./.forge/catalog]
```

Forge never installs or changes anything on your system by itself. `forge repair` only ever
writes to `--output` (and the catalog directory); the generated script inside the resulting ZIP
is yours to review and run yourself with `--check` / `--dry-run` / `--fix` / `--verify`.

### Known limitations (honest, as of this phase)

- Exactly one fault type is recognized: a TCP port held by another process (`free-tcp-port`).
  Everything else correctly falls through to `needs_review` rather than a guess.
- Only `--os linux` has a generated-script template; `windows`/`macos` are rejected with a clear
  error, not silently mis-generated.
- The VS Code extension format (Phase 8) is not started.
- `forge repair` itself still only ever produces the CLI script; `generateHtmlArtifact` and
  `verifyHtmlArtifact` are complete, tested library code (including the full evidence/export/
  catalog chain), but there is no `--format html` or equivalent CLI flag to invoke them yet.
- No LLM provider is wired in yet -- only the deterministic fallback. `validateDiagnosis` is
  already the intended gate for a future model response, so adding a provider later doesn't
  change the trust boundary.
- The catalog is a flat directory of JSON files, not a database -- adequate for this MVP, not for
  scale.
- `forge validate`/`forge verify`/`forge evidence` as separate subcommands (blueprint section 12)
  are not implemented; everything they'd expose is already visible inside the exported ZIP's
  `evidence.json`.

No claim stronger than what actually ran in CI is made anywhere in this repository.

## Why this exists

Two earlier prototypes in this space (not part of this repository) turned out to be
"claim-without-verify" by construction: a hardcoded `verified: true` response regardless of what
was checked, mock SHA-256 hashes presented as cryptographic proof, and a UI terminal animation
standing in for a real process run. Forge is the deliberate opposite: every verification level
(`L0`...`L4`) must be backed by something that actually executed, with an independent oracle for
the before/after state, and a second, independently implemented verifier that never shares code
with the artifact builder.

## Guiding principles

- **Evidence, not claims.** "Verified" is only used when the documented checks actually ran.
- **Fail closed.** Policy, validation, or runner errors block release; they never default to pass.
- **Real isolation.** Verification runs in Docker (`--network=none`, resource limits, read-only
  root), never on the developer or production host.
- **Independent oracle.** The red/green state check is implemented separately from the generated
  script -- a nonzero exit code alone is never accepted as proof of a state change.
- **No circular hashing.** The artifact hash is computed over the artifact bytes, not the evidence
  package that references it.
- **Separation of generation and verification.** A model may propose a diagnosis; it never
  produces or asserts a verification result.

Full architecture, threat model and phased build plan: [`docs/blueprint.md`](docs/blueprint.md).

## Development

```bash
npm install
npm run lint   # tsc --noEmit
npm test       # vitest run
```

`npm test` needs a reachable Docker daemon (CLI sandbox tests) and a working Playwright/Chromium
install (HTML artifact tests) -- both run real containers/browsers rather than a mock, per this
project's "no fake verification" rule. CI runs `npx playwright install --with-deps chromium`
before the test step.

## License

MIT, see [`LICENSE`](LICENSE).
