# Preflight — agent notes

**Preflight** pre-flights a dependency manifest *before* you add or auto-update a package:
known CVEs, framework-lockstep status, and an auto-update verdict. It's the tool the
grocery-helper project wished it had — Expo's lockstep made Dependabot open unmergeable PRs,
security alerts were off, and transitive CVEs couldn't be cleanly fixed. **The edge over
Dependabot/Snyk/Socket is the framework-lockstep registry** (`packages/core/src/lockstep.ts`):
knowing which packages a framework pins as a coordinated set, so the tool can say "don't
auto-bump this — use `npx expo install`."

## Status
Stage 1 (CLI) is a **working vertical slice**: manifest → OSV vulns + lockstep → verdict → table.
Stages 2 (GitHub Action) and 3 (web dashboard) are speced in `docs/` but not built. **Start from
[docs/kickoff.md](docs/kickoff.md).** Full plan: [docs/roadmap.md](docs/roadmap.md),
[docs/spec.md](docs/spec.md).

## Layout (npm-workspaces monorepo, TypeScript ESM)
- `packages/core` (`@preflight/core`) — the engine, reused by CLI/Action/web. **Single source of truth.**
  - `manifest.ts` — parse package.json (+ lockfile versions) / requirements.txt
  - `osv.ts` — OSV.dev client (querybatch for presence, then vuln details)
  - `registry.ts` — latest version (npm registry / PyPI)
  - `depsdev.ts` — deps.dev OpenSSF Scorecard (2-hop; wired behind `--health`)
  - `lockstep.ts` — **the framework-pinned registry: the product's edge — keep extending it**
  - `verdict.ts` — combine → `safe | pinned | cve | stale`
  - `analyze.ts` — orchestrator: `analyze(path, opts) -> Report`
- `packages/cli` (`@preflight/cli`) — commander CLI (`preflight check`)
- `packages/action` — Stage 2 (not built yet)
- `packages/web` — Stage 3, Next.js dashboard (not built; design in `docs/dashboard-mockup.html`)

## Commands
- Install: `npm install`
- Run: `npm run check -- <path/to/package.json|requirements.txt>` (`--json`, `--latest`)
- Test: `npm test` (vitest — pure logic in `lockstep`/`verdict`) · Typecheck: `npm run typecheck` · Lint: `npm run lint`
- Demo: `npm run check -- ~/grocery-helper/mobile/package.json` → 9 Expo-pinned, 8 safe, 0 CVE.

## Conventions / gotchas
- **All logic lives in `@preflight/core`**; CLI/Action/web are thin wrappers — never duplicate.
- `@preflight/core` exports `./src/index.ts` directly (no build step in the seed; tsx/vitest/tsc
  resolve TS via the workspace symlink). A publish build (tsup → `dist`) is a stage-1 polish task.
- **Verify API shapes against the live docs before trusting them** — OSV
  (https://google.github.io/osv.dev/api/), deps.dev (https://docs.deps.dev/api/v3/). Don't assert
  response formats from memory; that bit the previous project. `depsdev.ts` especially is unverified.
- All APIs are **keyless** — never hardcode secrets. GitHub OAuth (stage 3) is deferred config.
- **The lockstep registry is data-driven** so it's trivial to extend (Expo/Angular/Nx are seeded;
  add Next/SvelteKit and pip/gem framework sets — Django, Rails). Extending it *is* much of the roadmap.
- Git: author commits as the user only (no Claude co-author trailer); branch + PR, the user merges.

## Résumé framing
"Built a supply-chain pre-flight tool (CLI + GitHub Action + dashboard) that scores dependency
health and CVE exposure via the OSV and deps.dev APIs, flags framework-lockstep packages unsafe to
auto-update, generates SBOMs, and gates pull requests."
