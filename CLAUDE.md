# Preflight — agent notes

**Preflight** pre-flights a dependency manifest *before* you add or auto-update a package:
known CVEs, framework-lockstep status, and an auto-update verdict. It's the tool the
grocery-helper project wished it had — Expo's lockstep made Dependabot open unmergeable PRs,
security alerts were off, and transitive CVEs couldn't be cleanly fixed. **The edge over
Dependabot/Snyk/Socket is the framework-lockstep registry** (`packages/core/src/lockstep.ts`):
knowing which packages a framework pins as a coordinated set, so the tool can say "don't
auto-bump this — use `npx expo install`."

## Status
All three surfaces (CLI, Action, web dashboard) are **built and on `main`**, plus: v0.2 depth
(whole-lockfile transitive, EPSS+KEV, malicious-package, CycloneDX SBOM, SARIF, scheduled repo scan)
and v0.3 security (install-script, offline typosquat, license risk, per-check Scorecard, and a
shared `preflight.config.json` **policy gate**). The web app is **deployed on Vercel** at
`https://preflight-web.vercel.app` (auto-deploys on push to `main`) exposing keyless `POST /api/scan`
(+ `/api/health`) for embedding — see `docs/integration.md`. `scripts/fleet-scan.mts`
(`npm run scan:repos`) sweeps all `gh` repos (root + one level down). **Deferred:** the
ai-project-dashboard *consumer* side (build it in a session rooted in that repo), npm publish, and
GitHub-repo OAuth. Full plan: [docs/roadmap.md](docs/roadmap.md), [docs/spec.md](docs/spec.md).

## Layout (npm-workspaces monorepo, TypeScript ESM)
- `packages/core` (`@preflight/core`) — the engine, reused by CLI/Action/web. **Single source of truth.**
  - `manifest.ts` — parse package.json (+ enumerate the **full lockfile graph**: direct & transitive,
    each `Finding`/`Dependency` tagged `direct`) / requirements.txt. OSV scans the whole graph;
    `--latest`/`--health` apply to direct deps only.
  - `osv.ts` — OSV.dev client (querybatch → vuln details; captures CVE `aliases`, flags `MAL-` as malicious)
  - `cvss.ts` — CVSS v3 base-score → severity (fallback when OSV has no GHSA label)
  - `epss.ts` — FIRST EPSS exploit-probability per CVE (keyless, batched); `kev.ts` — CISA KEV set
  - `typosquat.ts` — offline lookalike heuristic (bundled top-packages list + Damerau-Levenshtein)
  - `license.ts` — `licenseRisk()` buckets a license id → permissive/copyleft/unknown
  - `cache.ts` — `.preflight-cache/` 24h disk cache wrapping every API call (`setCacheEnabled`)
  - `registry.ts` — latest version + last-publish date + **license** (npm registry / PyPI; under `--latest`)
  - `depsdev.ts` — deps.dev OpenSSF Scorecard: overall + **per-check** security breakdown (`--health`)
  - `lockstep.ts` — **the framework-pinned registry: the product's edge — keep extending it**
  - `verdict.ts` — combine → `malware | cve | pinned | stale | safe` (cve reason adds KEV/EPSS; `stale` needs `--latest`)
  - `policy.ts` — `evaluatePolicy(findings, policy)` + `meetsVulnLevel` (one gate shared by CLI `--policy` + Action `policy-file`; `preflight.config.json`)
  - `sbom.ts` — `toCycloneDX(report)` (1.6); `sarif.ts` — `toSarif(reports[])` (2.1.0, for GitHub code scanning)
  - `analyze.ts` — orchestrator: `analyze(path)` / `analyzeContent(name,text)` / `analyzeFiles({name:text})` → `Report` (EPSS+KEV enrich when CVEs exist). `analyzeFiles` (temp-dir, keyless) powers the web `/api/scan` + embedding (see `docs/integration.md`)
- `packages/cli` (`@preflight/cli`) — commander CLI (`preflight check`)
- `packages/action` (`@preflight/action`) — JS Action. `mode: pr` (default) diffs a PR → sticky
  comment + `fail-level` gate (cve|kev|epss:x); `mode: repo` (scheduled) scans every committed
  manifest → tracking issue. Writes `preflight.sarif` (uploaded to the Security tab). `report.ts`
  pure/testable; `index.ts` octokit glue. **Committed** `dist/index.js` (tsup, CJS — Actions run
  from source). Workflows: `preflight.yml` (PR), `preflight-schedule.yml` (cron), `release.yml`
  (tag → `npm publish @preflight/cli --provenance`).
- `packages/web` (`@preflight/web`) — Stage 3 Next.js App Router dashboard: paste a manifest →
  `/api/analyze` (`analyzeContent()`) → metric cards + findings, matching `docs/dashboard-mockup.html`.
  Also `POST /api/scan` (`analyzeFiles()`, keyless — caller posts manifest+lockfile, `maxDuration=60`
  for Vercel) and `GET /api/health` for **embedding** (docs/integration.md). Engine via
  `transpilePackages`; excluded from root eslint/tsc (self-checks via `next build`); `output:standalone`
  + `Dockerfile` for self-host. **Deployed on Vercel** (preflight-web.vercel.app). Repo-OAuth deferred.

## Commands
- Install: `npm install`
- Run: `npm run check -- <path/to/package.json|requirements.txt>` (`--json`, `--sbom [file]`, `--latest`, `--health`, `--no-cache`)
- Test: `npm test` (vitest — `lockstep`/`verdict`/`cvss`/`manifest` + mocked-fetch `osv`) · Typecheck: `npm run typecheck` · Lint: `npm run lint`
- Build: `npm run build` (tsup → `dist` for core/cli/action; `next build` for web — all 4 workspaces)
- Web: `npm run dev -w @preflight/web` (dashboard at `localhost:3000`; paste a manifest → `/api/analyze`)
- Fleet scan: `npm run scan:repos` (`scripts/fleet-scan.mts` — read-only sweep of all `gh` repos; checks the repo root **+ one level down** so monorepo sub-projects like `mobile/`,`backend/` count; rollout plan in `docs/rollout.md`)
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
