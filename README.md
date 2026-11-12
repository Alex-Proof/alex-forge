# Alex Forge

Forge turns an error log into a checked repair artifact (CLI script first, HTML and a VS Code
extension later) -- and refuses to call anything "verified" unless a real, independent check
actually ran.

## Status: Phase 2 -- process runner and Docker sandbox

**Implemented:** repository scaffold, TypeScript project setup, CI (type-check + test), the type
contracts for diagnosis/policy/verification/catalog (`src/types/`), the policy engine
(`src/core/policy/`), and a real Docker-backed sandbox runner (`src/core/verification/`):
network disabled, read-only root, CPU/memory/process-count limits, timeout and output-byte
enforcement with guaranteed container and workspace cleanup, and a policy check on every command
before it is ever spawned. A sandbox that fails to start always resolves to `runner_error`, never
to anything that could be mistaken for a passing result. Covered by real Docker integration tests
(no mocked sandbox).

**Not implemented yet:** diagnosis fallback, CLI, red/green verification oracle, evidence builder,
independent verifier, catalog. Nothing in this repository can currently generate or verify a
repair artifact end to end. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the planned order.

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
