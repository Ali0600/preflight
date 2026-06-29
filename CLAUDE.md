# Preflight — agent notes

**Preflight** pre-flights a dependency manifest *before* you add or auto-update a package:
known CVEs, framework-lockstep status, and an auto-update verdict. It's the tool the
grocery-helper project wished it had — Expo's lockstep made Dependabot open unmergeable PRs,
security alerts were off, and transitive CVEs couldn't be cleanly fixed. **The edge over
Dependabot/Snyk/Socket is the framework-lockstep registry** (`packages/core/src/lockstep.ts`):
knowing which packages a framework pins as a coordinated set, so the tool can say "don't
auto-bump this — use `npx expo install`."

## Status
Stage 1 (CLI) is **complete**: manifest → OSV vulns (+ CVSS-derived severity) + lockstep → verdict
→ table, with a 24h disk cache, `--latest` (latest version + `stale` verdict), `--health` (deps.dev
Scorecard), and a `tsup` build to a standalone `dist`. Stages 2 (GitHub Action) and 3 (web dashboard)
are speced in `docs/`. **Stage 2 is now built** (the Action); Stage 3 (web) is not. Full plan:
[docs/roadmap.md](docs/roadmap.md), [docs/spec.md](docs/spec.md).

## Layout (npm-workspaces monorepo, TypeScript ESM)
- `packages/core` (`@preflight/core`) — the engine, reused by CLI/Action/web. **Single source of truth.**
  - `manifest.ts` — parse package.json (+ lockfile versions) / requirements.txt
  - `osv.ts` — OSV.dev client (querybatch for presence, then vuln details)
  - `cvss.ts` — CVSS v3 base-score → severity (fallback when OSV has no GHSA label)
  - `cache.ts` — `.preflight-cache/` 24h disk cache wrapping every API call (`setCacheEnabled`)
  - `registry.ts` — latest version + last-publish date (npm registry / PyPI)
  - `depsdev.ts` — deps.dev OpenSSF Scorecard (2-hop; wired behind `--health`)
  - `lockstep.ts` — **the framework-pinned registry: the product's edge — keep extending it**
  - `verdict.ts` — combine → `safe | pinned | cve | stale` (`stale` needs `--latest` data)
  - `analyze.ts` — orchestrator: `analyze(path, opts) -> Report`
- `packages/cli` (`@preflight/cli`) — commander CLI (`preflight check`)
- `packages/action` (`@preflight/action`) — Stage 2 JS Action: diff a PR's manifests → sticky
  comment + fail on new CVE. `report.ts` is pure (testable); `index.ts` is octokit glue. Bundled
  to a **committed** `dist/index.js` (tsup, CJS) because Actions run from source with no install.
- `packages/web` — Stage 3, Next.js dashboard (not built; design in `docs/dashboard-mockup.html`)

## Commands
- Install: `npm install`
- Run: `npm run check -- <path/to/package.json|requirements.txt>` (`--json`, `--latest`, `--health`, `--no-cache`)
- Test: `npm test` (vitest — `lockstep`/`verdict`/`cvss`/`manifest` + mocked-fetch `osv`) · Typecheck: `npm run typecheck` · Lint: `npm run lint`
- Build: `npm run build` (tsup → `dist`; CLI is a standalone bundle, runs via `node packages/cli/dist/index.js`)
- Demo: `npm run check -- ~/grocery-helper/mobile/package.json` → 10 Expo-pinned, 7 safe, 0 CVE.
  `npm run check -- examples/requirements.txt --latest` → 4 CVE, 1 safe (exit 1).

## Conventions / gotchas
- **All logic lives in `@preflight/core`**; CLI/Action/web are thin wrappers — never duplicate.
- `@preflight/core` still exports `./src/index.ts` directly (zero-build dev loop: tsx/vitest/tsc
  resolve TS via the workspace symlink). The publishable CLI is built by **bundling** core into it
  (`tsup` `noExternal: ['@preflight/core']`), because **npm's `publishConfig` can't repoint
  `main`/`exports`/`bin`** (only pnpm/yarn can — npm/cli#7586). So don't try to publish core by
  swapping its exports to `dist`; bundle the consumer instead, or wait for a real core publish step.
- **Verify API shapes against the live docs before trusting them** — OSV
  (https://google.github.io/osv.dev/api/), deps.dev (https://docs.deps.dev/api/v3/). OSV + deps.dev +
  npm + PyPI shapes are now **verified** (deps.dev needs UPPERCASE `NPM`/`PYPI` in the path, and the
  scorecard hangs off the `SOURCE_REPO` related project — both handled in `depsdev.ts`).
- All APIs are **keyless** — never hardcode secrets. GitHub OAuth (stage 3) is deferred config.
- **The lockstep registry is data-driven** so it's trivial to extend (Expo/Angular/Nx + Next.js/Nuxt/
  SvelteKit/Remix/Astro are seeded). Next to add: pip (Django) — and gem (Rails) once a Gemfile parser
  exists, else that data is dead. Be conservative: a false `pinned` is bad advice (we omit bare
  `react`/`svelte` from non-owning sets). Extending it accurately *is* much of the roadmap.
- Git: author commits as the user only (no Claude co-author trailer); branch + PR, the user merges.

## Experience Gained
Accomplishment-style phrasing for what's built lives in the README's **Experience Gained** section —
keep it accurate (engine + CLI + GitHub Action are real; SBOM generation and the web dashboard are
not built yet) and separate from Features/Highlights. Don't add a "Résumé"-labelled section to
committed docs.
