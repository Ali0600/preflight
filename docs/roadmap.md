# Preflight — roadmap

## Stage 1 — CLI (started; polish to ship)
**Done:** monorepo, `@preflight/core` (manifest / osv / registry / depsdev / lockstep / verdict /
analyze), CLI `preflight check` with a verdict table + `--json`, vitest for lockstep/verdict, CI.

**To finish:**
- [x] `--health` (deps.dev Scorecard) + the `stale` verdict (major-behind + old last-publish).
      `stale` requires `--latest` (it needs the registry's latest version + publish date).
- [x] Disk cache (`.preflight-cache/`, 24h) for OSV / registry / deps.dev calls (`--no-cache` bypass).
- [x] Extend `lockstep.ts`: Next.js, Nuxt, SvelteKit, Remix, Astro (npm). _pip (Django) / gem (Rails)
      deferred — Rails needs a Gemfile parser, so that data would be dead until one lands._
- [x] `tsup` build → publishable `dist`; `bin` works without tsx (CLI bundles `@preflight/core`).
      _Note: npm's `publishConfig` can't repoint `main`/`exports`/`bin` (only pnpm/yarn) — so the CLI
      is bundled standalone instead, and core stays src-resolved for the zero-build dev loop._
- [x] More tests: manifest parsing (npm lockfile + requirements), OSV severity mapping (mocked fetch),
      CVSS base-score calculator, stale verdict, new lockstep sets. 24 tests across 5 files.

Acceptance: `node packages/cli/dist/index.js check <manifest>` runs standalone ✓; CI green ✓.

## Stage 2 — GitHub Action (`packages/action`)
- `action.yml` + `@actions/core` / `@actions/github`; on PRs touching a manifest, diff the deps and
  comment the verdicts ("adding X: 1 CVE, +N transitive, Expo-pinned → bump via expo install").
- Fail the check on a *new* CVE; annotate the PR. Reuses `analyze()`.

Acceptance: a test PR in this repo gets a Preflight comment.

## Stage 3 — Web dashboard (`packages/web`, Next.js)
- Paste a manifest (textarea) or connect a repo (GitHub OAuth) → `analyze()` via an API route →
  render the metric cards + findings list from `docs/dashboard-mockup.html` (match that design,
  dark-mode aware). Deploy on Vercel.

Acceptance: paste grocery-helper/mobile's `package.json` → the mockup view, live.
