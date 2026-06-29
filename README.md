# Preflight

> Pre-flight a dependency **before** you add or auto-update it — known CVEs, health, and whether
> it's actually safe to bump given your framework.

Most tools (Dependabot, Snyk, Socket) analyze the dependencies you *already have*. Preflight
answers the question that bites you *earlier*: **"is this safe to add, and safe to auto-update?"**
Its edge is a **framework-lockstep registry** — it knows that Expo, Angular, Nx, Next.js, Nuxt,
SvelteKit, Remix, and Astro each pin a coordinated set of packages, so it tells you to bump those
via the framework's own tool (`npx expo install`, `npx nuxi upgrade`, …) instead of letting a
per-package updater break your build.

## Highlights
- **Supply-chain pre-flight engine** — parses npm/pip manifests, batches queries to the OSV
  vulnerability database, and classifies each dependency as `safe` / `pinned` / `cve` / `stale`.
  Keyless, deterministic, and cached on disk (24h) to respect rate limits.
- **Framework-lockstep detection** — a data-driven registry that flags packages a framework pins
  as a set (Expo, Angular, Nx, Next.js, Nuxt, SvelteKit, Remix, Astro), the failure mode generic
  auto-updaters (Dependabot/Renovate) can't see — with the exact upgrade command to use instead.
- **Severity + health enrichment** — maps GHSA labels and computes CVSS v3 base scores for
  advisories that ship only a vector; `--health` adds each dep's OpenSSF Scorecard from deps.dev.
- **CI-gating** — exits non-zero on any CVE, so it drops straight into a pipeline.
- **Three delivery surfaces, one engine** — a CLI (built to a standalone bundle with tsup), a
  GitHub Action that gates PRs, and a web dashboard, all reusing `@preflight/core`.

## Stages
1. **CLI** (`@preflight/cli`) — `preflight check <manifest>` → a verdict table (`safe` / `pinned` /
   `cve` / `stale`), with `--latest` (latest version + staleness), `--health` (OpenSSF Scorecard),
   `--json`, and `--no-cache`. **Working today.**
2. **GitHub Action** (`@preflight/action`) — on every PR, diffs the changed manifests and posts a
   sticky comment with the verdicts for added/bumped deps; fails the check on a newly-introduced
   CVE. **Working today** ([.github/workflows/preflight.yml](.github/workflows/preflight.yml)).
3. **Web dashboard** (`@preflight/web`, Next.js App Router) — paste a manifest → metric cards +
   findings list matching [docs/dashboard-mockup.html](docs/dashboard-mockup.html), dark-mode aware.
   **Working today** (`npm run dev -w @preflight/web`); GitHub-repo OAuth is deferred, Vercel-ready.

## Quickstart
```bash
npm install
npm run check -- path/to/package.json      # or a requirements*.txt
npm run check -- examples/requirements.txt --latest   # add latest-version + staleness
npm test                                    # vitest
npm run build                               # tsup → standalone dist (publishable CLI)
npm run dev -w @preflight/web               # the dashboard at http://localhost:3000
```

Example (an Expo app — everything Expo-pinned, nothing to auto-bump):
```
17 deps · 0 CVE · 10 pinned · 0 stale · 7 safe
 PINNED  react-native@0.85.3   Framework-pinned (Expo) — update via npx expo install
 SAFE    typescript@6.0.3      Independent — safe to auto-update (CI-gated)
```

Example (a pip manifest with old pins — CI would fail on these):
```
5 deps · 4 CVE · 0 pinned · 0 stale · 1 safe
 CVE     pyyaml@5.3.1 · latest 6.0.3    2 advisory · critical
 CVE     jinja2@2.10  · latest 3.1.6    8 advisory · high
 SAFE    rich@13.7.1  · latest 15.0.0   Independent — safe to auto-update (CI-gated)
```

## How it works
`@preflight/core` is the single engine: `manifest` → `osv` + `lockstep` (+ `registry`/`depsdev`)
→ `verdict` → `Report`. The CLI, Action, and dashboard are thin wrappers over `analyze()`.
See [docs/spec.md](docs/spec.md) for the verdict logic and API details, and
[docs/preflight-checklist.md](docs/preflight-checklist.md) for the broader dependency-hygiene
practices this tool automates.

## Data sources (all free, no API keys)
OSV.dev · deps.dev (v3) · npm registry · PyPI JSON · endoflife.date

## Experience Gained
- Designed a keyless supply-chain analysis **engine** (TypeScript, ESM npm-workspaces monorepo) over
  the OSV, deps.dev, npm, and PyPI APIs — batched queries, a 24h on-disk cache, and a CVSS v3
  base-score calculator — shipped as a standalone **CLI** bundled with tsup.
- Built a **CI/CD security gate** as a GitHub Action (`@actions/*` toolkit + Octokit) that diffs
  dependency changes on each pull request, posts an automated review comment, and fails the check on
  a newly-introduced CVE — self-tested by running on its own PRs.
- Shipped a **Next.js (App Router, React 19) dashboard** that analyzes a pasted manifest through a
  Node route handler and renders a dark-mode-aware metric/findings view — one engine reused across a
  CLI, a CI action, and a web app via a TypeScript workspace (`transpilePackages`).
- Modeled framework **lockstep** version sets (Expo, Angular, Nx, Next.js, Nuxt, SvelteKit, Remix,
  Astro) to produce upgrade guidance generic auto-updaters can't, and verified every external API
  shape against live docs before coding.
- Deepened it into a real supply-chain scanner: **whole-lockfile transitive** scanning, **risk-based
  prioritization** (EPSS exploit-probability + CISA KEV) over CVSS, **malicious-package** detection,
  **CycloneDX SBOM** + **SARIF** (GitHub Security tab) export, and a **scheduled cron re-scan** that
  files an issue when a dependency becomes newly vulnerable — all keyless.

## License
MIT (intended).
