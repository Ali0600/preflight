# Preflight — roadmap

## Stage 1 — CLI (started; polish to ship)
**Done:** monorepo, `@preflight/core` (manifest / osv / registry / depsdev / lockstep / verdict /
analyze), CLI `preflight check` with a verdict table + `--json`, vitest for lockstep/verdict, CI.

**To finish:**
- [ ] `--health` (deps.dev Scorecard) + the `stale` verdict (major-behind + old last-publish).
- [ ] Disk cache (`.preflight-cache/`, 24h) for OSV / registry calls.
- [ ] Extend `lockstep.ts`: Next.js, SvelteKit, Remix, Nuxt; pip (Django) / gem (Rails) sets.
- [ ] `tsup` build → publishable `dist`; make `bin` work without tsx; publish `@preflight/cli`.
- [ ] More tests: manifest parsing (npm lockfile + requirements), OSV severity mapping (mocked fetch).

Acceptance: `npx @preflight/cli check <manifest>` runs standalone; CI green.

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
