# Roadmap

Order and scope follow [`blueprint.md`](blueprint.md) section 13. Nothing is built out of order.
Each phase below becomes one PR with its own tests before the next phase starts.

Status legend: `planned` -- not started · `in progress` -- being built · `done` -- implemented
and covered by a passing test.

| Phase | Scope | Status |
|---|---|---|
| 0 | Repository scaffold, TS/test/CI setup, type contracts | done |
| 1 | Policy engine (`inspectText`/`inspectPath`/`inspectCommand`/`inspectFiles`) + unit tests | done |
| 2 | Process runner + Docker sandbox adapter (network disabled, resource limits, cleanup) | done |
| 3 | CLI contract (`--check`/`--dry-run`/`--fix`/`--verify`/`--json`) + deterministic diagnosis fallback + one fixture | done |
| 4 | Red/green verification with an independent before/after oracle | done |
| 5 | Evidence builder + independently implemented second verifier (no shared code with the builder) | done |
| 6 | `forge repair` end to end, security regression suite in CI -- CLI MVP done | done |
| -- | Distribution: thin Forge MCP server package, `alex-control-layer` tool entry | planned |
| 7 | Standalone HTML artifacts | done |
| 8 | VS Code extension artifacts | done |
| 9 | Multi-tool hardening mode | locked -- requires a documented, passed red-team self-test first |

## What "done" means here

A phase is marked `done` only once its acceptance criteria from `blueprint.md` section 13 are met
and demonstrated by a real test run in CI -- not by a status update in this table alone.
