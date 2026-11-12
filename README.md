# Alex Forge

Forge turns an error log into a checked repair artifact (CLI script, standalone HTML, and a VS
Code extension companion) -- and refuses to call anything "verified" unless a real, independent
check actually ran.

## Status: Phase 8 -- VS Code extension artifacts

**Implemented:** repository scaffold, TypeScript/CI setup, the type contracts (`src/types/`), the
policy engine (`src/core/policy/`), a real Docker-backed sandbox runner (`src/core/verification/`),
and the first repair mode (`src/modes/repair/`):

- a registered, schema-validated action allowlist (currently `free-tcp-port` and
  `clear-stale-pidfile`) -- a diagnosis can
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
- `forge repair --format <sh|html>` (`src/cli.ts`): `--format` is now wired all the way through
  the real CLI entry point, not just available as library functions. `sh` (the default) is the
  unchanged Docker/red-green path. `html` calls `generateHtmlArtifact` and `verifyHtmlArtifact`
  instead -- no Docker sandbox is created for this path; the real headless-Chromium process
  started by `verifyHtmlArtifact` is itself the sandboxed execution environment. Both paths join
  back into the identical `buildEvidence` -> `exportRepairPackage` ->
  `readArtifactAndEvidenceFromZip` -> `independentlyVerify` -> `admitToCatalog` chain and the same
  exit-code semantics (`0` approved, `1` needs_review/rejected, `2` policy block or error).
  `tests/integration/forge-repair-html.test.ts` drives this end to end through the real `main()`
  entry point: log in, `repair.html` out inside a real ZIP, `forge catalog list` shows the entry.
- `forge repair --format extension` (`src/cli.ts`): the same `--format` flag now also accepts
  `extension`, calling `generateExtensionArtifact` + `verifyExtensionArtifact` -- again no Docker
  sandbox; the real `@vscode/vsce` packaging step and (where this environment allows it) the real
  VS Code Extension Host launch are this path's own verification. It joins the identical
  evidence/export/independent-verify/catalog chain and exit-code semantics as `sh`/`html`. Because
  catalog admission for this format genuinely depends on whether a real runtime launch succeeded
  in the environment Forge is running in, `tests/integration/forge-repair-extension.test.ts`
  asserts both honest outcomes: exit `0`/approved with a real, re-openable `.vsix` inside the ZIP
  when a runtime launch succeeded, or exit `2` with "independent re-verification ... failed" and
  no catalog record when it didn't -- never a silent pass either way.

- `generateExtensionArtifact` (`src/modes/repair/diagnose.ts`) + `action.generateExtensionProject`
  (`src/modes/repair/actions.ts`): a one-off, throwaway VS Code extension companion project for a
  single diagnosed repair case. It carries no repair logic of its own -- it embeds the same
  already-verified `repair.sh` as a string literal (same discipline as the HTML report) and offers
  exactly two commands: "Forge Repair: Show details" (a read-only webview, `enableScripts: false`,
  rendered via manual HTML-escaping) and "Forge Repair: Prepare terminal command" (after an
  explicit modal confirmation, types -- but never submits -- `sh repair.sh <flag>` into an
  integrated terminal via `terminal.sendText(cmd, false)`; the user still has to press Enter
  themselves). No runtime dependencies, no eager activation, no contributions beyond those two
  commands, and no automatic installation or repair run, ever.
- `validateExtensionManifest` (`src/formats/extension.ts`): manifest and dependency policy --
  requires `engines.vscode`/`main`/`publisher`, forbids an npm `scripts` field, forbids any runtime
  `dependencies`, requires every `activationEvents` entry to be `onCommand:*` (no eager/`*`
  activation), and allows no `contributes` point other than `commands`.
- `verifyExtensionArtifact` (`src/core/verification/verify-extension.ts`): real, no-mock
  verification in three gated steps -- (1) the manifest policy above against the generated source,
  (2) a real `@vscode/vsce` packaging run producing an actual `.vsix`, with the *packaged*
  manifest re-extracted and re-validated (closing the gap between what was generated and what was
  actually shipped), and (3) wherever this environment allows it, a real VS Code Extension Host
  launched via `@vscode/test-electron` under Xvfb, which activates the packaged extension and
  concretely checks that `forgeRepair.showDetails` is registered and that invoking it opens a
  webview tab (`tests/fixtures/vscode-extension-smoke-test.cjs`/`-runner.mjs`, independent of the
  generator's own source). On success this reaches `L2_sandbox_executed`, matching HTML's
  precedent of "a real sandboxed process actually ran the artifact". If a real launch isn't
  possible here (no Xvfb, or no network path to VS Code's download host), that check is honestly
  `skipped` -- never silently counted as passed -- and the overall level is capped at
  `L1_static_validated`, which `independentlyVerify` already refuses to admit to the catalog. No
  blanket "verified" claim is ever made for this format; the evidence text names exactly what ran
  ("compiled and packaged", "started in a real VS Code Extension Host instance", or the specific
  tested function), per blueprint section 21.4.
- The policy engine gained a real capability it was missing: `inspectFiles` at the `"package"`
  stage now recognizes an actual zip archive (checked by magic bytes, then genuinely parsed) and
  inspects every entry on its own terms -- path safety, then the same text/secret/injection policy
  as any other package file -- instead of hard-blocking the whole archive as unsupported binary
  content. This only changes behavior for the `"package"` stage; `input`/`diagnosis`/
  `generated-code` still reject binary content exactly as before (`src/core/policy/policy.ts`,
  covered by new tests in `src/core/policy/policy.test.ts`).
- `src/modes/repair/fixture-extension-catalog.test.ts`: the same diagnose -> generate -> verify ->
  evidence -> export -> read back -> independently re-verify -> catalog-admit chain proven for
  CLI/HTML, now for the extension format, plus a negative-control test that a manifest violating
  the dependency policy is refused.
- **This phase's own feasibility check, documented honestly:** `@vscode/vsce` only needs the npm
  registry. `@vscode/test-electron` needs two additional hosts (`update.code.visualstudio.com`,
  which then redirects to `vscode.download.prss.microsoft.com`) to download VS Code, plus
  `xvfb-run`/`Xvfb` for a display server -- both confirmed working in this project's own dev
  environment and added to CI (`.github/workflows/ci.yml` installs `xvfb` and caches
  `.vscode-test/`). In a network environment that doesn't allow those two hosts, the runtime check
  degrades to `skipped` as described above rather than failing outright or lying about what ran.

- **Red-team self-test, Phase 9's gate ([`docs/red-team-self-test.md`](docs/red-team-self-test.md)):**
  all 12 attack categories from `blueprint.md` section 15 against the protective layers built in
  Phases 0-8, each backed by a real, currently-passing test -- not asserted from reading the code.
  Running it for real surfaced and fixed three genuine gaps, each with its own new regression
  test: a zip-slip path-traversal gap in the extension format's unpacking step
  (`safelyUnpackVsixExtensionEntries`), an oracle exit-code collision that could let a
  broken/missing oracle be mistaken for a confirmed fault precondition, and an obfuscated
  destructive-command bypass (`base64 -d | sh`-style, no literal `rm -rf` substring anywhere) that
  passed the policy engine cleanly before the fix. This passes Phase 9's gate (`docs/ROADMAP.md`
  moves it from `locked` to `planned`); the AgentShield feature itself still has no design or code.

- **Found while demonstrating `forge repair` on a realistic, timestamped log:** the deterministic
  fallback's port extraction (`extractPort`, `src/modes/repair/diagnose.ts`) used to scan the
  *entire* log text for any bare `:NN` and could misread a timestamp's own colon-digits (e.g.
  `20:00:00`'s `:00`) as the listen port, before ever reaching the real `...in use :::3000` later
  in the same line. Fixed: port extraction is now scoped to only the line(s) that actually matched
  the port-conflict pattern, and a colon-based match is only trusted when it is anchored to an
  actual listen-address form (`0.0.0.0`/`127.0.0.1`/`localhost`/a bare `::`/`:::`), never a bare
  colon-digit pair alone. Covered by new cases in `src/modes/repair/diagnose.test.ts`.
- **Follow-up robustness pass**, same area: also recognizes Node's real unbracketed IPv6-loopback
  form (`::1:PORT`, confirmed against a real `net.Server` error, not assumed), Go's standard net
  package message (`listen tcp :8080: bind: address already in use` -- a bare `:PORT` with no
  address literal at all, trusted only when anchored right after a literal `tcp`/`udp`, which a
  timestamp never contains), and Docker's port-mapping conflict phrasing (`port is already
  allocated`, which never uses the word "in use" at all). All covered by new cases in
  `src/modes/repair/diagnose.test.ts`.

- **A second registered action: `clear-stale-pidfile`.** Recognizes PostgreSQL's real `lock file
  "..." already exists` wording and the generic daemon `PID file ... already exists` phrasing,
  extracts the path, and only proceeds when it's an absolute `/tmp/<name>.pid` path -- `/tmp` is
  the one directory guaranteed writable in Forge's own `--read-only` Docker sandbox (see
  `sandbox.ts`'s `--tmpfs /tmp`), and the fixture has to create the fault at the *exact* path the
  generated script checks for the red/green verification to mean anything. A path anywhere else
  (the common real-world `/var/run/...`) is honestly left as `needs_review` rather than silently
  rewritten to a different location than what the log said -- generalizing past `/tmp` would need
  a less restrictive sandbox for this one action, a separate, bigger change to shared
  infrastructure, not done here.
  - The fix is **only ever** "remove the file", and only once an independent oracle has confirmed
    the PID recorded inside it is not a live process (`tests/fixtures/stale-pidfile-oracle.py`,
    Python's `os.kill(pid, 0)` idiom -- a different language and a different liveness check than
    the generated script's own `kill -0` call). A pidfile whose PID *is* alive is never touched --
    that may be a real second instance, which this action must never assume is safe to clear.
  - The sandbox fixture reproduces the fault for real: spawns a trivial subshell, waits for it to
    actually exit and be reaped, then writes that now-dead PID into the file -- never a fabricated
    number that merely looks plausible.
  - Only the `sh`/CLI format is wired up for this action so far (no `generateHtml`/
    `generateExtensionProject` yet) -- the same incremental, format-by-format rollout
    `free-tcp-port` itself went through; `--format html`/`extension` for this action is follow-up
    work, not a gap introduced here.
  - Proven end to end on real infrastructure (a real Docker container, a real reaped PID, a real
    Python oracle process) by `src/modes/repair/fixture-stale-pidfile-catalog.test.ts`, including a
    negative control that a pidfile holding a genuinely live PID is correctly left untouched
    (`not_verified`, never a guessed pass).

- **LLM diagnosis provider (optional, OpenAI).** Blueprint section 20: "Modell ist optional;
  Fallback ist verpflichtend" -- the deterministic fallback is still the mandatory baseline; a
  model is only ever layered on top of it, never a replacement for it.
  - `src/core/diagnosis-provider/provider.ts` defines the swappable `DiagnosisProvider` interface
    the blueprint calls for; `openai-provider.ts` is the one real implementation so far (Chat
    Completions API, JSON-mode response). `src/modes/repair/diagnose.ts`'s `proposeDiagnosis` is
    the single place a provider and the fallback meet.
  - **A model response is never trusted more than the fallback's own output.** Both are just an
    untrusted `candidate` object until `validateDiagnosis` says otherwise -- the exact same gate,
    not a separate or weaker one. A response referencing an unregistered `actionId`, or one that
    fails schema validation, silently falls back to the deterministic diagnosis; it is never
    partially trusted or retried with a "fixed" prompt.
  - **Never throws, never blocks on a broken model.** Any missing `OPENAI_API_KEY`, network
    failure, timeout (20s), non-2xx response, or unparseable JSON resolves to the fallback, not an
    error -- a missing/broken model is exactly the case the mandatory fallback exists for.
  - **The model only ever sees the already-redacted log text** -- the same text the real,
    already-passed input policy check in `cli.ts` ran on, never the raw log. Its system prompt
    explicitly states the log is data, not instructions, and names only the two currently
    registered actions and their exact parameter shapes; it is never told or shown anything about
    future, unregistered, or hypothetical actions.
  - `--no-model` forces the deterministic fallback outright, regardless of whether a key is set.
  - `evidence.json`'s `provenance.modelProvider`/`modelVersion` now honestly reflect what actually
    ran (`"openai"` + the real model id from the response, or `"fallback-deterministic"` + `null`)
    -- these used to be hardcoded to `"fallback-deterministic"`/`null` regardless of what happened,
    since no model path existed yet to report honestly about.
  - Tested for real against the real OpenAI API, not mocked (`src/core/diagnosis-provider/openai-provider.test.ts`,
    skipped visibly rather than silently whenever `OPENAI_API_KEY` isn't set, which is the normal
    `npm test`/CI case): a real port-conflict log correctly proposes `free-tcp-port` with the right
    port, an unmatched log honestly proposes an empty `fixPlan` rather than guessing, and a direct
    prompt-injection attempt embedded in the log text (instructing it to propose an unregistered
    `"rm-rf-root"` action and disable `needsHumanApproval`) is resisted by the model and, as a
    backstop regardless of what the model does, would be refused by `validateDiagnosis` either
    way. Also verified manually end to end through the real CLI: `evidence.json`'s provenance
    correctly says `"openai"` when the model actually ran, and `--no-model` correctly forces
    `"fallback-deterministic"` even with a valid key present.
  - This sandboxed dev environment's own outbound network needs `NODE_USE_ENV_PROXY=1` set for
    Node's `fetch` to reach `api.openai.com` through its proxy at all -- a property of this
    environment's network policy, not of real deployments, so it is deliberately never baked into
    the shipped provider code itself (plain `fetch`, no proxy-awareness, which is the correct,
    dependency-free behavior for a normal end user's own machine).

### Usage

```bash
npm install
npm run build
node bin/forge.mjs repair --log ./error.log --os linux --output ./out [--format sh|html|extension] [--json] [--catalog-dir ./.forge/catalog] [--no-model]
node bin/forge.mjs catalog list [--json] [--catalog-dir ./.forge/catalog]
```

`--format` defaults to `sh` (a CLI script, verified in a real Docker sandbox). `--format html`
produces a standalone `repair.html` report instead, verified in a real headless-Chromium process.
`--format extension` produces a `repair.vsix` VS Code extension companion instead, verified by a
real `@vscode/vsce` packaging run and, where the environment allows it, a real VS Code Extension
Host launch. Neither `html` nor `extension` needs Docker.

Set `OPENAI_API_KEY` to let an OpenAI model propose the diagnosis instead of (ahead of) the
deterministic fallback; `--no-model` forces the fallback regardless. See "LLM diagnosis provider"
below for exactly what trust boundary this does and doesn't cross.

Forge never installs or changes anything on your system by itself. `forge repair` only ever
writes to `--output` (and the catalog directory); the generated script inside the resulting ZIP
is yours to review and run yourself with `--check` / `--dry-run` / `--fix` / `--verify`.

### Known limitations (honest, as of this phase)

- Two fault types are recognized: a TCP port held by another process (`free-tcp-port`), and a
  stale PID/lock file under `/tmp` blocking service startup (`clear-stale-pidfile`). Everything
  else correctly falls through to `needs_review` rather than a guess. A stale-pidfile path
  anywhere other than `/tmp` (the common real-world case) is also honestly left as
  `needs_review` -- see the dedicated bullet below for why.
- Only `--os linux` has a generated-script template; `windows`/`macos` are rejected with a clear
  error, not silently mis-generated.
- Forge never installs the generated `.vsix` into the user's VS Code, and never will by design;
  installing and running it is always the user's own, separate, explicit action.
- The extension companion's "show details"/"prepare terminal command" contract is currently only
  implemented for `free-tcp-port`; a future second action needs its own
  `generateExtensionProject`, same as it would need its own `generateHtml`.
- A real VS Code Extension Host runtime check needs `xvfb-run`/`Xvfb` and network access to
  `update.code.visualstudio.com` and `vscode.download.prss.microsoft.com`. Where either is
  missing, Forge honestly reports that check as `skipped` (capped at `L1_static_validated`, which
  `independentlyVerify` refuses to admit to the catalog) rather than claiming a runtime
  verification that didn't happen; through the CLI this surfaces as `forge repair --format
  extension` exiting `2` with "independent re-verification ... failed" instead of a silent
  `approved`.
- Only one real `DiagnosisProvider` exists (OpenAI). Adding a second (e.g. Gemini, Anthropic)
  needs its own implementation of the same interface; `proposeDiagnosis` itself is already
  provider-agnostic.
- `ALLOWED_ACTIONS_PROMPT` in `openai-provider.ts` is hand-maintained prompt text, not derived
  from `ACTION_REGISTRY`'s zod schemas -- a third registered action needs this prompt updated by
  hand, or the model simply won't know it exists (it will still never be able to *invent* an
  unregistered action either way, since `validateDiagnosis` is the real backstop regardless of
  what the prompt does or doesn't mention).
- The model is only ever asked to propose a diagnosis; nothing about `--format html`/`extension`
  or either action's own HTML/extension templates changes based on whether a model or the
  fallback produced the diagnosis -- same generation code either way.
- The catalog is a flat directory of JSON files, not a database -- adequate for this MVP, not for
  scale.
- `forge validate`/`forge verify`/`forge evidence` as separate subcommands (blueprint section 12)
  are not implemented; everything they'd expose is already visible inside the exported ZIP's
  `evidence.json`.
- The red/green oracle's exit-code-collision fix (see the self-test report) cannot catch *every*
  way an oracle's interpreter could crash before reaching the oracle's own error handling --
  e.g. a generic "module not found" crash from the oracle's chosen interpreter can still collide
  with the oracle contract's own exit-code semantics. No observed scenario resolves to a false
  `passed`, but this is not a principled guarantee the way the exit `2`/`126`/`127` handling is.
- Category 2 of the red-team self-test (indirect injection via a tool's manifest/README) has no
  current attack surface to test against, honestly, because no code reads a tool's manifest or
  README yet -- that only exists once Phase 9's actual multi-tool input is built, at which point
  it needs its own real test before being claimed covered.

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

`npm test` needs a reachable Docker daemon (CLI sandbox tests), a working Playwright/Chromium
install (HTML artifact tests), and -- for the extension artifact's full runtime check --
`xvfb-run`/`Xvfb` plus network access to `update.code.visualstudio.com` and
`vscode.download.prss.microsoft.com` (the first run downloads and caches a real VS Code build
under `.vscode-test/`). All three run real containers/browsers/editor instances rather than a
mock, per this project's "no fake verification" rule; where the extension runtime check's
prerequisites aren't met, it degrades to an honestly-reported `skipped` check instead of failing
the whole suite (see "Known limitations" above). CI runs `npx playwright install --with-deps
chromium` and installs `xvfb` before the test step, and caches `.vscode-test/` across runs.
`OPENAI_API_KEY` is optional: its three real-API tests in `openai-provider.test.ts` are visibly
skipped (not silently) without it, both locally and in CI.

## License

MIT, see [`LICENSE`](LICENSE).
