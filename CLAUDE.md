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
    each `Finding`/`Dependency` tagged `direct`) / requirements.txt / **`Gemfile.lock`** /
    **`go.mod`** / **`Cargo.lock`** / **`.github/workflows/*.yml`**
    (ecosystem `actions`: `uses:` entries → deps named `owner/repo`, `mutableRef` when the ref
    isn't a full SHA, `version` only for exact `vX.Y.Z` refs; matched on the whole path so a random
    `foo.yml` never parses). OSV scans the whole graph; `--latest`/`--health` apply to direct deps
    only. Lockfile discovery order: package-lock.json → pnpm-lock.yaml → yarn.lock (npm's has the
    richest metadata). For `actions`, registry-style lookups (latest/health/runtimes/downloads) are
    forced off in `analyze` — only OSV + KEV/EPSS + typosquat (curated actions list) + ref pinning.
  - `lockfiles.ts` — pnpm (v5/v6/v9) + yarn (classic v1 + berry) graph parsers (`yaml` dep,
    bundled by tsup) **plus `parseGemfileLock`**. Scope: transitive deps get `dev: false`
    (reconstructing dev-only reachability needs a graph walk — conservative, scans MORE);
    `installScript` only where the format exposes it (pnpm v5/v6 `requiresBuild`), never
    fabricated. Action PR-mode triggers on all three npm lockfile names and fetches whichever the
    base tree has. **Gemfile.lock is SELF-LOCKED** (`SELF_LOCKED` in manifest.ts): the file *is*
    the manifest and the graph, so `parseManifestContent` alone yields resolved versions and
    `lockfile` is always `true` — there is no sibling to look for, and a bare `Gemfile` is
    deliberately rejected (requirements, no versions). Gems: `dev: false` throughout (Bundler
    groups live in the Gemfile, not the lock), `PATH` sections skipped (local engines whose names
    would falsely inherit a real gem's advisories), `GIT` sections kept (a fork of a real gem),
    platform suffixes stripped (`1.13.0-x86_64-linux` → `1.13.0`). The **anchored** spec regex is
    the load-bearing filter — the section allowlist and `inSpecs` are redundant defence-in-depth
    (probed: mutating either alone changes nothing). **`parseGoMod`** is self-locked too (go.mod
    since 1.17 is the full pruned graph; **`go.sum` is NOT a graph source** — it hashes candidates
    that were never selected). It applies `replace` (module→module scans the fork; module→local
    path drops the entry, and a replace whose left side isn't required is a no-op per the module
    ref), ignores `exclude`/`retract` in both single-line AND block form, and passes versions
    through **verbatim** (`v` prefix + `+incompatible` — OSV accepts every form, verified live, so
    normalising would only risk breaking a match). Go **stdlib** comes from a `toolchain` directive
    ONLY — the bare `go` directive is a minimum that libraries hold low deliberately, so inferring
    the build version from it manufactures CVEs; when it's absent the ledger says why. Full fork +
    rejected alternatives: `docs/DECISIONS.md`. **`parseCargoLock`** is a purpose-built TOML
    *subset* reader (Cargo emits only `[[package]]`, `key = "str"`, and a `dependencies` array;
    core ships one runtime dep and adding a TOML parser for this would be the second) — handles
    formats v1–v4, both the block and inline `dependencies` forms, and the legacy qualified entry
    `"name ver (source)"`. Crates with **no `source`** are workspace-local: excluded from advisory
    matching (an in-repo `utils` must not inherit crates.io `utils`) but their edges are what
    define `direct`; `git+` sources ARE scanned. Duplicate crate versions are kept separately
    (two majors legitimately coexist in a Rust build).
  - `osv.ts` — OSV.dev client (querybatch → vuln details; captures CVE `aliases`, flags `MAL-` as
    malicious). **GitHub Actions is a separate path**: OSV does NOT evaluate versioned queries for
    that ecosystem (verified live 2026-07-09 — known-affected versions return `{}`), so
    `fetchActionVulns` queries per package and matches ECOSYSTEM ranges **locally** (semver, partial
    boundaries like "41" padded). Floating tags/SHA refs aren't range-matched (mutable-ref warning
    covers them); an advisory with NO scoping data attaches to every ref (fail-safe for MAL)
  - `cvss.ts` — CVSS v3 base-score → severity (fallback when OSV has no GHSA label)
  - `epss.ts` — FIRST EPSS exploit-probability per CVE (keyless, batched); `kev.ts` — CISA KEV set
  - `eol.ts` — endoflife.date runtime EOL (one fetch per product; `cycleOf` maps Node→major,
    Python→major.minor, refuses bare "3"). Report-level (`Report.runtimeEol`), not a per-dep
    verdict; policy `failOn.eolRuntime` gates it via `evaluatePolicy`'s `PolicyContext` third arg
    (report-level facts). Runs whenever a runtime target is set; empty cycle list = failure (never cached)
  - `typosquat.ts` — offline lookalike heuristic (bundled top-packages list + Damerau-Levenshtein)
  - `downloads.ts` — weekly downloads (npm downloads API bulk ≤128/unscoped-only + pypistats.org).
    **Bounded fan-out by design**: fetched ONLY for typosquat candidates + their targets, and for
    direct deps under `--health` — never the whole graph (public web endpoints stay bounded).
    Enriches `suspiciousName` with candidate/target dl/wk; download failure degrades to the
    offline heuristic (announced). A 404/bulk-null is a legit "not a package", not a failure
  - `license.ts` — `licenseRisk()` buckets a license id → permissive/copyleft/unknown
  - `cache.ts` — 24h disk cache (`~/.cache/preflight`, per-user XDG; `PREFLIGHT_CACHE_DIR` overrides) wrapping every API call (`setCacheEnabled`). **Only successful fetches are cached** — the clients throw on failure so a transient outage can't poison the cache and silently weaken detection; failures set `Report.degraded` instead
  - `registry.ts` — latest version + last-publish date + **license** + **deprecation map** (sparse
    version→message: npm `deprecated`, or a PyPI release whose files are ALL yanked — a partial yank
    stays live; empty-string `deprecated` = un-deprecated, not a signal) (npm/PyPI; under `--latest`)
  - `depsdev.ts` — deps.dev OpenSSF Scorecard: overall + **per-check** security breakdown (`--health`);
    the same GetVersion call also yields the detected SPDX `license` (fills registry gaps) and
    `provenance` (npm Sigstore + PyPI PEP 740 attestations both land in `attestations[]`,
    `verified` = deps.dev's signature check — display-only, no gate; shapes verified live 2026-07-09)
  - `lockstep.ts` — **the framework-pinned registry: the product's edge — keep extending it**.
    Sets are **ecosystem-tagged** (`ecosystem?: Ecosystem`, default npm) and `presentFrameworks` /
    `lockstepFor` / `plan.ts`'s `frameworkSet` all take an ecosystem — names are only unique
    *within* a registry, so without the tag the `rails` gem would claim npm projects (and
    `--framework rails` would seed an npm plan with gem names). Rails is the RubyGems entry:
    13 `exact` members, **no prefixes** (`activerecord-import` etc. are unrelated namespaces),
    `bundler` excluded (rails declares it `>= 1.15.0`, not `=`).
  - `combos.ts` — known-bad version *pairs* (break together despite peer ranges admitting each
    other, e.g. eslint 10 × eslint-config-next ≤16 — #31). `plan` holds the subject back to the
    newest known-good runtime-compatible release + dependabot-ignores the boundary. Data-driven
    like lockstep; entries must be documented breakages (strict `satisfies === true` matching —
    never fire on "can't tell")
  - `verdict.ts` — combine → `malware | cve | incompatible | deprecated | pinned | stale | safe`
    (cve reason adds KEV/EPSS; `deprecated` + `stale` need `--latest` and a *resolved* version;
    policy `failOn.deprecated` auto-enables the registry fetch via `policyNeeds`)
  - `types.ts` — shared shapes **plus** `VERDICT_ORDER` + `VERDICT_LABEL` (worst-first rank + badge
    label). types.ts has **zero imports**, so it's re-exported at the `@preflight/core/types` subpath
    for the web **client** bundle (importing the barrel would drag `node:fs`/`crypto` in). CLI/Action/web
    all import these — don't re-declare per-surface LABEL/ORDER (they used to, and drifted). `loadPolicy(path, mustExist)`: pass `mustExist` for an *explicitly-requested* policy (CLI `--policy`/Action `policy-file`) so a typo'd path throws instead of silently gating nothing
  - `policy.ts` — `evaluatePolicy(findings, policy)` + `meetsVulnLevel` (one gate shared by CLI `--policy`/`--fail-level` + Action `fail-level`/`policy-file`; `preflight.config.json`). Levels: `cve|kev|epss:x|severity:x` (unrated=low, KEV beats any floor). `allow: { installScripts, advisories }` exempts adjudicated packages/advisories — every suppression is returned + announced; malware fails unconditionally (even with no `vuln` rule) and is never exemptible
  - `sbom.ts` — `toCycloneDX(report)` (1.6); `sarif.ts` — `toSarif(reports[])` (2.1.0, for GitHub code scanning)
  - `analyze.ts` — orchestrator: `analyze(path)` / `analyzeContent(name,text)` / `analyzeFiles({name:text})` → `Report` (EPSS+KEV enrich when CVEs exist). `analyzeFiles` (temp-dir, keyless) powers the web `/api/scan` + embedding (see `docs/integration.md`). `AnalyzeOptions.maxDeps` throws `GraphTooLargeError` **before any fetch** when the enumerated graph exceeds it — the web routes set it (→ 413) to bound public fan-out; CLI/Action/fleet leave it unset (trusted, unbounded). Also builds `Report.sources` — the per-run **data-source ledger** (`ok`/`degraded`/`skipped` + one-line result per source), derived from what was actually queried so a clean scan still shows *what it checked*. Rendered on every surface (CLI `Data sources` block, Action `📡 Data sources` table + `aggregateSources` in the scheduled issue, web dashboard panel, `/api/*` JSON)
- `packages/cli` (`@preflight/cli`) — commander CLI (`preflight check`)
- `packages/action` (`@preflight/action`) — JS Action (node24). `mode: pr` (default) diffs the
  **whole tree** base↔head (manifest + lockfile via raw `getContent`; lockfile-only PRs trigger
  too) → `fail-level` + policy evaluate the `introduced` set (direct AND transitive `name@version`s
  new to the tree — dogfood BUG-3/#20: gating only direct diffed deps let a lockfile CVE through
  while the comment said "No new CVEs"). Pre-existing findings stay informational. A manifest that
  **fails to scan** (the primary OSV fetch throws — fail-closed by design — or the manifest is
  unparseable) is collected as `skipped`, surfaced in the comment/issue, and **fails the check**
  (`report.ts`'s pure `prGateFails()`) — matching the CLI's non-zero exit; do NOT downgrade it to a
  silent pass. This is distinct from a *degraded* scan (a lost secondary source → warn-only). `mode: repo`
  (scheduled) scans every committed manifest → tracking issue; honors policy
  `allow.advisories` **only** (`isAdjudicated`: a fully-accepted cve finding → "✅ Accepted by policy"
  section, listed but not counted; malware never adjudicable) + `runtimes` — NOT the `failOn` rules,
  which are pr-mode "what a PR introduces" semantics. **`fail-level` DOES apply in repo mode**
  (`report.ts`'s pure `repoFailCount`): the issue lists *every* CVE/malware finding (`count`), but
  the run only goes red on the subset meeting the level (`fail-level: kev` → report all, fail only
  on actively-exploited) — default `cve` counts all, so existing scans are unchanged; malware
  always counts, adjudicated never. Writes `preflight.sarif` (uploaded
  to the Security tab). `report.ts` pure/testable; `index.ts` octokit glue. **Committed**
  `dist/index.js` (tsup, CJS — Actions run from source; REBUILD it whenever action *or core*
  changes, or the shipped action silently runs stale core). **CI enforces this** — `ci.yml` rebuilds
  and runs `git diff --exit-code -- packages/action/dist`, so a forgotten rebuild fails the build.
  **`ignore-paths` applies in BOTH modes** (comma-separated globs, `report.ts`'s pure
  `matchesAnyGlob`/single-pass tokenizer): this repo's `examples/` and `tests/fixtures/` are
  INTENTIONALLY vulnerable known-positives, so without it every PR touching a fixture is blocked by
  the findings that are the fixture's whole point (dogfooded when the Ruby fixture failed PR #63's
  own gate). Exclusions are always announced — in the tracking issue, and in the PR comment on
  *every* path including the green all-clear, because "clean" and "we never looked" must not read
  the same. Default empty; a user's real manifest is never silently skipped.
  Workflows: `preflight.yml` (PR, passes `policy-file: preflight.config.json` +
  `ignore-paths: examples/**,**/tests/fixtures/**`), `preflight-schedule.yml`
  (cron, same `ignore-paths`), `release.yml` (`cli-v*` tag → `npm publish
  @preflight/cli --provenance`); third-party `uses:` are SHA-pinned (Dependabot `github-actions` bumps them).
  **Tag scheme:** plain `v*` (`v1`) = the ACTION's release pointer (consumers write
  `uses: Ali0600/preflight@v1`, resolved by the ROOT `action.yml` → `packages/action/dist`; move the
  `v1` tag to ship Action updates, keep root/packages action.yml inputs in sync); `cli-v*` = npm
  publish trigger (deferred until the user opts in). Never plain-`v*`-tag for npm.
- `packages/web` (`@preflight/web`) — Stage 3 Next.js App Router dashboard: paste a manifest →
  `/api/analyze` (`analyzeContent()`) → metric cards + findings, matching `docs/dashboard-mockup.html`.
  Also `POST /api/scan` (`analyzeFiles()`, keyless — caller posts manifest+lockfile, `maxDuration=60`
  for Vercel) and `GET /api/health` for **embedding** (docs/integration.md). Engine via
  `transpilePackages`; excluded from root eslint/tsc (self-checks via `next build`); `output:standalone`
  + `Dockerfile` for self-host. **Deployed on Vercel** (preflight-web.vercel.app). Repo-OAuth deferred.

## Commands
- Install: `npm install`
- Run: `npm run check -- <path/to/package.json|requirements.txt>` (`--json`, `--sbom [file]`, `--latest`, `--health`, `--fail-level cve|kev|epss:x|severity:x`, `--no-cache`)
- Test: `npm test` (vitest — `lockstep`/`verdict`/`cvss`/`manifest` + mocked-fetch `osv`) · Typecheck: `npm run typecheck` · Lint: `npm run lint`
- Build: `npm run build` (tsup → `dist` for core/cli/action; `next build` for web — all 4 workspaces)
- Web: `npm run dev -w @preflight/web` (dashboard at `localhost:3000`; paste a manifest → `/api/analyze`)
- Fleet scan: `npm run scan:repos` (`scripts/fleet-scan.mts` — read-only sweep of all `gh` repos; checks the repo root **+ one level down** so monorepo sub-projects like `mobile/`,`backend/` count; rollout plan in `docs/rollout.md`)
- Demo: `npm run check -- ~/grocery-helper/mobile/package.json` → 10 Expo-pinned, 7 safe, 0 CVE.
  `npm run check -- examples/requirements.txt --latest` → 4 CVE, 1 safe (exit 1).

## Conventions / gotchas
- **All logic lives in `@preflight/core`**; CLI/Action/web are thin wrappers — never duplicate.
- **Adding an ecosystem** — widen `Ecosystem` in types.ts (values ARE OSV ecosystem names, so
  `OSV_ECOSYSTEM` stays near-identity) and the compiler will point at every exhaustive
  `Record<Ecosystem, …>` (`osv`/`sbom`/`typosquat`). Then: `ecosystemFor` + the parse map in
  manifest.ts, `SCANNABLE_MANIFEST` in analyze.ts, the `MANIFEST` regex in **action/report.ts**
  (pure + unit-tested — it decides what a scan even looks at, so a missing name is a whole
  ecosystem unscanned behind a green check), `scanDir` in fleet-scan, the CLI `[path]` help, and
  the web `<select>`. Registry-style checks are opt-IN via `REGISTRY_ECOSYSTEMS` (npm/PyPI only)
  — never "not actions", so a new ecosystem can't inherit npm/PyPI's `else = PyPI` ternaries;
  `describeSources` then emits a lockstep row + an explicit `skipped` registry row rather than
  going silent (silence reads as coverage).
- **Probe OSV before assuming**: it evaluates versioned `querybatch` queries for RubyGems (unlike
  GitHub Actions, which needs local range matching). Verified live 2026-08-18 with a
  known-positive + a known-clean control.
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
- **Data-source fetchers must fail loud, never silent.** A new client (like `kev`/`epss`/`registry`/
  `depsdev`/`osv`/`runtimes`) must **throw inside `cached()` on failure** (a throwing compute is never
  persisted — so a transient outage can't poison the 24h cache and silently weaken a gate), `catch`
  above to degrade gracefully, and call the `onDegraded(source)` callback so `Report.degraded` surfaces
  it in the CLI/Action. A `404` is a legitimate cacheable empty; an empty-that-should-never-be-empty
  (e.g. the KEV catalog) is a failure. Never reintroduce `catch { return [] }` inside a `cached()` body.
- **The lockstep registry is data-driven** so it's trivial to extend (Expo/Angular/Nx + Next.js/Nuxt/
  SvelteKit/Remix/Astro are seeded). Next to add: pip (Django) — and gem (Rails) once a Gemfile parser
  exists, else that data is dead. Be conservative: a false `pinned` is bad advice (we omit bare
  `react`/`svelte` from non-owning sets). Extending it accurately *is* much of the roadmap.
- **Root `overrides` are security patches for upstream pins** — `tsup→esbuild ^0.28.1`,
  `next→postcss ^8.5.23` (next hard-pins an exact `postcss`), plus flat pins from the Aug-2026
  advisory wave: `sharp ^0.35.0`, `undici ^6.28.0` (satisfies `@actions/*`'s `^6.23.0`; there is no
  6.27.1 — the 6.x line jumps to 6.28.0), `nanoid ^3.3.18`, `js-yaml ^4.3.1`,
  `brace-expansion ^1.1.18`. REMOVE each override once the upstream bumps past it, or it becomes
  invisible drift (Next 16 pins postcss 8.5.23 natively — drop that one when the web app moves).
  **npm quirk — a "clean install" must include the workspaces**:
  `rm -rf node_modules packages/*/node_modules package-lock.json`. Rooting only at the top leaves a
  shadow `packages/web/node_modules` that makes overrides look broken; `npm ls <pkg> --all` shows it
  as `invalid`/`extraneous`. Verify with a real `npm audit` (not `npm install`'s summary line).
- Git: author commits as the user only (no Claude co-author trailer); branch + PR, the user merges.

## Experience Gained
Accomplishment-style phrasing for what's built lives in the README's **Experience Gained** section —
keep it accurate (engine + CLI + GitHub Action are real; SBOM generation and the web dashboard are
not built yet) and separate from Features/Highlights. Don't add a "Résumé"-labelled section to
committed docs.
