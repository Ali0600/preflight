# Preflight

[![CI](https://github.com/Ali0600/preflight/actions/workflows/ci.yml/badge.svg)](https://github.com/Ali0600/preflight/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Keyless](https://img.shields.io/badge/data%20sources-keyless-brightgreen)](#keyless-to-run)

> Check a dependency **before** you add it or let a bot bump it. Preflight reports known CVEs
> (publicly listed security flaws), package health, and whether your framework lets you bump it
> at all.

Most tools — Dependabot, Snyk, Socket — look at the dependencies you *already have*. Preflight
answers the question that bites you *earlier*: **"is this safe to add, and safe to auto-update?"**

What makes it different is the **framework-lockstep registry**. Expo, Angular, Nx, Next.js, Nuxt,
SvelteKit, Remix, and Astro each pin a set of packages that has to move together. Preflight spots
those and tells you to bump them with the framework's own tool (`npx expo install`,
`npx nuxi upgrade`, …). A per-package updater would bump one of them on its own and break your
build.

## Use it

**Check every pull request (GitHub Action)** — the fastest way in. On every PR it diffs the whole
dependency tree, lockfile included. The check fails on anything the PR adds that carries a known
CVE:

```yaml
# .github/workflows/preflight.yml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ali0600/preflight@v1
        # optional:
        # with:
        #   fail-level: kev            # only fail on confirmed-exploited CVEs
        #   policy-file: preflight.config.json
```

Add a weekly re-scan with a second workflow. It runs `mode: repo` on a cron and catches CVEs
disclosed *after* a dependency was merged — see
[.github/workflows/preflight-schedule.yml](.github/workflows/preflight-schedule.yml).
`fail-level` applies there too, and it is worth tuning. A cron run gates nothing, so
`fail-level: kev` reports **every** finding to the tracking issue and the Security tab while only
turning the run red on a confirmed-exploited CVE. Otherwise a wave of new advisories in deps you
already merged keeps the schedule permanently red until upstream ships fixes. The PR gate stays
strict on anything new.

**Run the CLI locally** — not yet on npm (coming), so run it from a clone:

```bash
git clone https://github.com/Ali0600/preflight && cd preflight && npm install
npm run check -- path/to/package.json        # or requirements*.txt, Gemfile.lock, go.mod, Cargo.lock
```

**Or scan it in the browser** — [preflight-web.vercel.app](https://preflight-web.vercel.app),
no install, no account. Paste a manifest, or paste the URL of a **public GitHub repo** and
Preflight fetches the manifests itself. It takes `owner/repo`, a `/tree/<branch>/<subdir>` URL for
one package in a monorepo, or a `/blob/` URL pointed straight at a single manifest. A repo that
carries several manifests gets one report each.

**Supported manifests:** `package.json` (npm), `requirements*.txt` (pip), `Gemfile.lock`
(RubyGems), `go.mod` (Go), `Cargo.lock` (Rust), and `.github/workflows/*.yml` (GitHub Actions).

> **Coverage note:** JavaScript scans always read the full lockfile tree —
> **`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`** (classic v1 and berry) are all parsed.
> Ruby is read straight from `Gemfile.lock`, which already carries the resolved version of every
> installed gem. Point Preflight at the *lock* file, not the `Gemfile` — only the lock has
> versions to check. Go is read from `go.mod`, which since Go 1.17 lists the full pruned module
> graph. `go.sum` is deliberately **not** used: it hashes candidate modules that were never
> selected, so scanning it reports versions your build does not use. The Go **standard library**
> is checked when a `toolchain` directive names the toolchain that will build the module. A bare
> `go` directive is only a *minimum*, so working the build version out from it would report every
> compatibility-minded library as carrying the whole stdlib CVE backlog — the scan says so
> explicitly instead of guessing. Rust is read from `Cargo.lock` (formats v1–v4). Crates with no
> `source` are workspace-local, so they are left out of advisory matching while still deciding
> which crates count as direct. pip has no standard lockfile, so a `requirements.txt` scan covers
> exactly the versions listed in it; for transitive coverage, scan a fully-pinned file
> (`pip freeze` or pip-tools' `requirements.txt` output).

## Highlights
- **Supply-chain pre-flight engine** — reads npm, pip, RubyGems, Go and Rust manifests, sends
  batched queries to the OSV vulnerability database, and labels each dependency `safe` / `pinned` /
  `cve` / `stale`. It needs no key, gives the same answer every run, and caches to disk for 24h to
  stay within rate limits.
- **Framework-lockstep detection** — a data-driven registry of packages a framework pins as a set
  (Expo, Angular, Nx, Next.js, Nuxt, SvelteKit, Remix, Astro, **Prisma**, **Storybook**,
  **tRPC**, **Sentry**, and **Rails**, whose gem declares all 12 components at `= X.Y.Z`). This is
  the failure generic auto-updaters (Dependabot, Renovate) cannot see, and Preflight prints the
  exact upgrade command to use instead. Every entry is copied from the framework's own manifest or
  docs, and a namespace is only claimed where it is genuinely uniform: `@sentry/cli` and
  `@prisma/dev` version independently, so they are deliberately left out.
- **Known-bad version pairs** — two packages that install cleanly under every declared peer range
  and break *together*. The classic case: `@types/react@19` declares **no peer dependency at all**,
  so npm and Dependabot happily bump it beside `react@18` — and the build stops type-checking.
  Nothing in the ecosystem's metadata expresses this, so the list is curated and evidence-backed
  (`combos.ts`), reported by `check` and gateable via `failOn.knownBadPair`.
- **Severity + health enrichment** — maps GHSA labels and computes CVSS v3 base scores for
  advisories that ship only a vector. `--health` adds each dep's OpenSSF Scorecard from deps.dev
  **plus build provenance**: a 🔏 badge when the version ships a *verified* attestation (npm
  Sigstore provenance / PyPI PEP 740) proving which repo and CI run actually built the artifact.
- **Beyond known CVEs** — flags packages that run **install scripts** (npm's #1 supply-chain
  vector), names that look like **typosquats** of popular packages (an offline check first, then
  **weekly download counts** put numbers behind the hunch: `resembles "lodash" (155M dl/wk) —
  this package: 43 dl/wk — classic typosquat signature`), risky or unknown **licenses**, and weak
  **OpenSSF Scorecard** checks — risk that has no CVE yet.
- **GitHub Actions workflow scanning** — `.github/workflows/*.yml` files are manifests too. Every
  `uses:` is checked against OSV's *GitHub Actions* ecosystem, with advisory ranges evaluated
  locally because OSV does not do it server-side for actions. Lookalike action names are flagged
  (`action/checkout` vs `actions/checkout`), and any ref that is not a **full commit SHA** gets a
  mutable-ref warning — a moved tag swaps the code your CI runs, which is the tj-actions
  compromise vector.
- **Deprecation surfacing** — under `--latest`, a dependency whose resolved version the maintainer
  deprecated (npm's `deprecated` notice) or **yanked from PyPI** gets its own `deprecated` verdict,
  with the upstream message repeated word for word — the "stop using this" signal `npm install`
  prints once and CI never sees. Turn it into a gate with `failOn: { "deprecated": true }`.
- **Runtime-compatibility + EOL check** — tell Preflight which runtime the project actually runs
  on (`--python 3.9` / `--node 18`, a `runtimes` key in the config, or auto-detected from
  `.python-version`/`.nvmrc`). It then flags dependencies whose range **cannot install there**
  (`incompatible`), and warns when the runtime itself is **past (or within 90 days of)
  end-of-life** via endoflife.date — no dependency bump fixes a dead interpreter. You also get an
  early warning when the *newest* release dropped your runtime, so the next auto-bump will break.
  This catches the failure CI on a newer interpreter cannot: a floor like `uvicorn>=0.49` is green
  on Python 3.12 but will not install on the 3.9 dev machine (`Requires-Python >=3.10`). Data:
  PyPI `Requires-Python` (a hard install failure) and npm `engines` (advisory), per version.
- **CI-gating** — exits non-zero on any CVE, so it drops straight into a pipeline.
- **Three delivery surfaces, one engine** — a CLI (bundled standalone with tsup), a GitHub Action
  that gates PRs, and a web dashboard. All three reuse `@preflight/core`.

## Stages
1. **CLI** (`@preflight/cli`) — `preflight check <manifest>` gives you a verdict table (`safe` /
   `pinned` / `cve` / `incompatible` / `stale`). Flags: `--latest` (latest version and staleness),
   `--health` (OpenSSF Scorecard), `--node <v>` / `--python <v>` (runtime compatibility),
   `--fail-level <level>` (tune what exits 1 — same grammar as the Action: `cve` / `kev` /
   `epss:<0-1>` / `severity:<low|medium|high|critical>`), `--json`, and `--no-cache`.
   **Working today.**
2. **GitHub Action** (`@preflight/action`) — on every PR it diffs the *whole dependency tree*
   (manifest + lockfile, so lockfile-only PRs count) and posts a sticky comment. The gate fails on
   anything the PR **introduces** — direct or transitive — that meets `fail-level` or breaks the
   policy. Findings that were already there stay informational; the scheduled repo scan owns those.
   **Working today** ([.github/workflows/preflight.yml](.github/workflows/preflight.yml)).
3. **Web dashboard** (`@preflight/web`, Next.js App Router) — paste a manifest and get metric cards
   and a findings list matching [docs/dashboard-mockup.html](docs/dashboard-mockup.html),
   dark-mode aware.
   **Live at [preflight-web.vercel.app](https://preflight-web.vercel.app)**. It also exposes a
   keyless `POST /api/scan` (send a manifest + lockfile, get the full report back) so other apps
   can embed it — see [docs/integration.md](docs/integration.md). GitHub-repo OAuth is deferred.

## Quickstart
```bash
npm install
npm run check -- path/to/package.json      # or requirements*.txt, Gemfile.lock, go.mod, Cargo.lock
npm run check -- examples/requirements.txt --latest   # add latest-version + staleness
npm test                                    # vitest
npm run build                               # tsup → standalone dist (publishable CLI)
npm run dev -w @preflight/web               # the dashboard at http://localhost:3000
npm run scan:repos                          # read-only sweep of all your GitHub repos (needs `gh`)
```

`scan:repos` lists your repos via `gh`, pulls each manifest, and prints one ranked report across
all of them. It writes nothing to any repo. To start gating repos, see
[docs/rollout.md](docs/rollout.md).

Example — an Expo app, where everything is Expo-pinned and nothing should be auto-bumped:
```
17 deps · 0 CVE · 10 pinned · 0 stale · 7 safe
 PINNED  react-native@0.85.3   Framework-pinned (Expo) — update via npx expo install
 SAFE    typescript@6.0.3      Independent — safe to auto-update (CI-gated)
```

Example — a pip manifest with old pins. CI would fail on these:
```
5 deps · 4 CVE · 0 pinned · 0 stale · 1 safe
 CVE     pyyaml@5.3.1 · latest 6.0.3    2 advisory · critical
 CVE     jinja2@2.10  · latest 3.1.6    8 advisory · high
 SAFE    rich@13.7.1  · latest 15.0.0   Independent — safe to auto-update (CI-gated)
```

## Design-phase mode: `preflight plan`

The checks above find problems in a manifest you *already have*. `preflight plan` moves them to
the **start of a project**. Pick the runtime the app will really run on, and a framework if you
want one. List the packages you intend to use. You get back the newest versions that install
there, plus the guardrail files:

```bash
npm run plan -- --python 3.9 fastapi uvicorn httpx --dev pytest
npm run plan -- --node 18 --framework expo axios
npm run plan -- --python 3.9 fastapi --write my-app   # write the files
```

```
uvicorn@0.39.0 (latest 0.49.0 incompatible)
    0.40.0+ requires Python >=3.10 — capped

── requirements.txt ──
uvicorn>=0.39.0,<0.40    # 0.40.0+ requires Python >=3.10 — capped

── .github/dependabot.yml ──
    ignore:
      # These ranges dropped Python 3.9 — don't bump past them.
      - dependency-name: uvicorn
        versions: ['>=0.40']
```

It writes the manifest (`requirements.txt`, or `package.json` with an `engines` field) and a
`dependabot.yml` that groups weekly updates and adds an `ignore` at each runtime boundary. With
`--framework` it ignores the whole lockstep set ("update with `npx expo install`, not
per-package bumps"). Recommended versions are checked against OSV, so the plan flags a floor that
would pin you onto a known CVE.

Plans are also checked against a registry of **known-bad pairs** — combinations whose declared
peer ranges *admit* each other but that break together at runtime. For example, `eslint@10`
beside `eslint-config-next@16` crashes at lint time; the upstream peer range is simply wrong, so
no metadata can reveal it. When a pair matches, the plan holds the package back to the newest
known-good version that still installs on your runtime, says why in the output, and adds a
dependabot `ignore` at the boundary so the auto-updater cannot bring the pair back. Like the
lockstep registry, the list is data-driven and evidence-based — every entry is a documented
breakage, never a heuristic.

## How it works
`@preflight/core` is the single engine: `manifest` → `osv` + `lockstep` (+ `registry`/`depsdev`)
→ `verdict` → `Report`. The CLI, the Action and the dashboard are thin wrappers over `analyze()`.
See [docs/spec.md](docs/spec.md) for the verdict logic and API details, and
[docs/preflight-checklist.md](docs/preflight-checklist.md) for the wider dependency-hygiene
habits this tool automates.

## Policy gate

By default, `preflight check` and the Action fail on any new CVE. For finer control, drop in a
`preflight.config.json` and pass `--policy` (CLI) or set `policy-file:` (Action). It is the same
gate either way, evaluated by `@preflight/core`:

```json
{
  "runtimes": { "python": "3.9" },
  "failOn": {
    "vuln": "kev",
    "installScript": true,
    "suspiciousName": true,
    "license": ["copyleft"],
    "minHealth": 5,
    "runtime": "incompatible"
  },
  "allow": {
    "installScripts": ["esbuild", "sharp"],
    "advisories": ["GHSA-qx2v-qp2m-jg93"]
  }
}
```

- `vuln` — `"cve"` (any), `"kev"` (confirmed-exploited only), `"epss:0.5"` (exploit probability ≥ x),
  or `"severity:medium"` (worst rated severity at or above the floor). Unrated advisories count as
  low, and a KEV'd advisory fails **any** floor — confirmed exploitation beats a severity label.
- `installScript` / `suspiciousName` — fail on a dep that runs an install script, or has a typosquat-like name.
- `deprecated` — fail when a resolved version is deprecated upstream (npm `deprecated`, or fully
  yanked from PyPI).
- `license` — fail on these license ids, or on the buckets `"copyleft"` / `"unknown"`.
- `minHealth` — fail if a *direct* dep's OpenSSF score is below this.
- `runtime` — `"incompatible"` fails when a dep's range cannot install on the target runtime
  (declared in `runtimes` or via flags). `"latest-dropped"` also fails the early warning, where
  the newest release dropped the runtime and the next bump breaks. Without a policy, an explicit
  `--node`/`--python` target that fails to install exits non-zero; auto-detected targets
  (`.nvmrc`/`.python-version`) only warn.
- `eolRuntime` — fail when the target runtime itself is past end-of-life (endoflife.date). This is
  a report-level rule: the violation names the interpreter, not a dependency.
- `unpinnedAction` — fail when a workflow `uses:` an action pinned to a mutable tag or branch
  instead of a full commit SHA (only fires on workflow manifests).

- `allow` — exceptions you have judged, which keep strict rules usable on real dependency trees.
  `installScripts` lists packages permitted to run install scripts (legitimate native binaries
  like esbuild/sharp/fsevents); `advisories` lists GHSA/CVE ids accepted as unactionable, such as
  one vendored by a framework until it ships the fix. **Every allow that fires is announced** in
  the output (`allowed: …`) — the gate says what it deliberately ignored, so exceptions never rot
  invisibly. Malware is never suppressible.

Malicious packages always fail, whatever the config says. `--policy` switches on the lookups its
rules need (`license`/`deprecated` → latest version, `minHealth` → health), so you do not have to
remember the flags.

**Where the file lives:** the CLI looks for `preflight.config.json` next to the directory you run
it *from* (pass `--policy path/to/file.json` for anything else); the Action's `policy-file:` is
relative to the repo root. In a monorepo, one root config passed explicitly is the simplest setup.

## Compliance exports (SBOM + SARIF)

- **CycloneDX SBOM** — `preflight check --sbom [file]` writes a CycloneDX 1.6 JSON inventory of
  the full dependency graph, with each vulnerability, EPSS score and KEV flag attached. An SBOM is
  a parts list of everything your project ships; feed it to Dependency-Track, OSV-Scanner, or any
  other tool that reads one.
- **SARIF** — the Action writes `preflight.sarif` on every run. SARIF is the standard file format
  code-scanning tools use to report findings. The bundled workflows upload it to GitHub **code
  scanning**, so findings appear in the repo's Security tab with severity coloring.

## Keyless to run

Every data source Preflight queries is **free, keyless, and accountless** — nothing to sign up
for, no API key to store, no token to rotate. That is what lets it drop straight into any pipeline
(local, CI, or the dashboard) with zero configuration.

| Source | What Preflight gets from it | Endpoint |
| --- | --- | --- |
| **OSV.dev** | Known vulnerabilities + malicious-package (`MAL-`) advisories → the `cve` / `malware` verdicts + severity | `api.osv.dev` |
| **FIRST EPSS** | Exploit *probability* (0–1) per CVE — rank what's likely to actually be attacked | `api.first.org/data/v1/epss` |
| **CISA KEV** | CVEs *confirmed* exploited in the wild — the "patch this now" list | `cisa.gov/.../known_exploited_vulnerabilities.json` |
| **deps.dev** (v3) | OpenSSF Scorecard + verified build provenance (npm Sigstore / PyPI PEP 740) + detected SPDX license, behind `--health` | `api.deps.dev/v3` |
| **npm registry** | Latest version + last-publish date + per-version deprecation → the `stale` / `deprecated` verdicts | `registry.npmjs.org` |
| **PyPI** (JSON) | Latest version + upload time + yanked releases, for pip manifests | `pypi.org/pypi/{name}/json` |
| **endoflife.date** | End-of-life date of the *target runtime* (Node/Python) — flags a dead interpreter no dependency bump can fix | `endoflife.date/api/{product}.json` |
| **npm downloads API** | Weekly downloads — context for typosquat hits, adoption under `--health` (bulk ≤128/request) | `api.npmjs.org/downloads` |
| **pypistats.org** | Weekly downloads for PyPI packages (same role) | `pypistats.org/api/packages/{p}/recent` |

Every **successful** response is cached on disk for 24h (`~/.cache/preflight`; set
`PREFLIGHT_CACHE_DIR` to override, or `--no-cache` to skip). That keeps Preflight a good API
citizen and makes re-runs instant. A *failed* fetch is never cached. If a source is unreachable,
that scan is marked `degraded` in the CLI and in the PR comment, so a green result is never
mistaken for "all clear" when, say, the KEV feed was down and exploited-status is really unknown.

> **Design principle:** every new check must be *quick, keyless, and accountless*. If a data
> source needs an account or an API key, it does not belong here — that constraint is the whole
> point, and it is what keeps Preflight a drop-in.

## Experience Gained
- Built a keyless supply-chain scanner in TypeScript covering 5 language ecosystems plus GitHub
  Actions workflows — whole-lockfile transitive scans over OSV, cached on disk for 24h.
- Shipped one engine behind 3 surfaces: a tsup-bundled CLI, a GitHub Action that fails a PR on a
  newly introduced CVE plus a weekly cron re-scan, and a Next.js App Router dashboard on React 19.
- Ranked findings by real risk from 9 free data sources — EPSS exploit probability, CISA KEV, and
  CVSS v3 base scores computed from raw vectors — and flagged malicious packages outright.
- Modeled lockstep version sets for 13 frameworks (Expo, Angular, Nuxt, Prisma, Rails and more)
  plus a curated known-bad-pair registry — breakage no package metadata can express.
- Added 6 pre-CVE risk signals: install scripts, an offline typosquat heuristic, license buckets,
  OpenSSF Scorecard, upstream deprecation or yank, and runtime end-of-life.
- Unified every signal into one policy-as-code gate with 9 rule types, shared by the CLI and the
  Action, and exported a CycloneDX 1.6 SBOM plus SARIF into GitHub's Security tab.
- Built a mutation-testing harness over 315 test blocks across 30 test files; it exposed 4
  untested code paths and 1 defect in the harness itself.

## License
[MIT](LICENSE).
