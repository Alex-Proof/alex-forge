# Alex Forge

Forge turns an error log into a checked repair artifact (CLI script first, HTML and a VS Code
extension later) -- and refuses to call anything "verified" unless a real, independent check
actually ran.

## Status: Phase 4 -- red/green verification with an independent oracle

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

**Not implemented yet:** evidence builder, independent second verifier, catalog, export. Nothing
in this repository can currently produce a catalog-eligible repair artifact end to end. See
[`docs/ROADMAP.md`](docs/ROADMAP.md).

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

`npm test` now needs a reachable Docker daemon: the sandbox tests run real containers rather than
a mock, per this project's "no fake verification" rule.

## License

MIT, see [`LICENSE`](LICENSE).
