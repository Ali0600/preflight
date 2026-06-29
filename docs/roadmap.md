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

## Stage 2 — GitHub Action (`packages/action`) — **built**
- [x] `action.yml` (node20) + `@actions/core` / `@actions/github`; on PRs touching a manifest, diff
      base-vs-head declared deps, run `analyze()` on the head, and post one **sticky** comment with
      the verdicts for the added/bumped deps.
- [x] Fail the check on a *new* CVE (`fail-on-cve`, default true); reuses `analyze()` + the new
      `parseManifestContent()` (base manifest read over the API).
- [x] Bundled to a single committed `dist/index.js` (tsup); `.github/workflows/preflight.yml` runs
      `./packages/action` on PRs (`pull-requests: write`) — so it pre-flights its own PRs.

Acceptance: a test PR in this repo gets a Preflight comment ✓ (this PR comments on itself).
_Not yet: transitive-dep counts ("+N transitive") and per-line PR annotations — future polish._

## Stage 3 — Web dashboard (`packages/web`, Next.js) — **built**
- [x] Paste a manifest (textarea) → `analyzeContent()` via the `/api/analyze` route handler (Node
      runtime, cache off) → metric cards + findings list + insight callout matching
      `docs/dashboard-mockup.html`, dark-mode aware. App Router + React 19; engine pulled in via
      `transpilePackages`.
- [x] `--latest` always on (version transitions like `0.85.3 → 0.86.0`); an "Include OpenSSF health"
      toggle drives the health-grade card. Exact-pinned npm deps are CVE-checked without a lockfile.
- [ ] Connect a repo via GitHub OAuth (deferred config, per spec) — the paste flow is the MVP.
- [ ] Deploy on Vercel (root directory `packages/web`; builds via the workspace) — ready, not yet pushed.

Acceptance: paste an Expo `package.json` → the mockup view, live ✓ (verified locally; screenshot in PR).
