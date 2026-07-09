# Preflight

[![CI](https://github.com/Ali0600/preflight/actions/workflows/ci.yml/badge.svg)](https://github.com/Ali0600/preflight/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Keyless](https://img.shields.io/badge/data%20sources-keyless-brightgreen)](#keyless-to-run)

> Pre-flight a dependency **before** you add or auto-update it — known CVEs, health, and whether
> it's actually safe to bump given your framework.

Most tools (Dependabot, Snyk, Socket) analyze the dependencies you *already have*. Preflight
answers the question that bites you *earlier*: **"is this safe to add, and safe to auto-update?"**
Its edge is a **framework-lockstep registry** — it knows that Expo, Angular, Nx, Next.js, Nuxt,
SvelteKit, Remix, and Astro each pin a coordinated set of packages, so it tells you to bump those
via the framework's own tool (`npx expo install`, `npx nuxi upgrade`, …) instead of letting a
per-package updater break your build.

## Use it

**Gate your pull requests (GitHub Action)** — the fastest way in. On every PR it diffs the whole
dependency tree (lockfile included) and fails the check on anything the PR introduces that carries
a known CVE:

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

Add a weekly re-scan (catches CVEs disclosed *after* a dep was merged) with a second workflow using
`mode: repo` on a cron — see [.github/workflows/preflight-schedule.yml](.github/workflows/preflight-schedule.yml).

**Run the CLI locally** — not yet on npm (coming), so run it from a clone:

```bash
git clone https://github.com/Ali0600/preflight && cd preflight && npm install
npm run check -- path/to/package.json        # or a requirements*.txt
```

**Or paste a manifest in the browser** — [preflight-web.vercel.app](https://preflight-web.vercel.app),
no install, no account.

> **Python note:** pip has no standard lockfile, so a `requirements.txt` scan covers exactly the
> versions listed in it. For transitive coverage, scan a fully-pinned file (`pip freeze` or
> pip-tools' `requirements.txt` output). JavaScript scans always include the full lockfile tree —
> **`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`** (classic v1 and berry) are all parsed.

## Highlights
- **Supply-chain pre-flight engine** — parses npm/pip manifests, batches queries to the OSV
  vulnerability database, and classifies each dependency as `safe` / `pinned` / `cve` / `stale`.
  Keyless, deterministic, and cached on disk (24h) to respect rate limits.
- **Framework-lockstep detection** — a data-driven registry that flags packages a framework pins
  as a set (Expo, Angular, Nx, Next.js, Nuxt, SvelteKit, Remix, Astro), the failure mode generic
  auto-updaters (Dependabot/Renovate) can't see — with the exact upgrade command to use instead.
- **Severity + health enrichment** — maps GHSA labels and computes CVSS v3 base scores for
  advisories that ship only a vector; `--health` adds each dep's OpenSSF Scorecard from deps.dev
  **plus build provenance**: a 🔏 badge when the version ships a *verified* attestation (npm
  Sigstore provenance / PyPI PEP 740) proving which repo and CI run actually built the artifact.
- **Beyond known CVEs** — flags packages that run **install scripts** (npm's #1 supply-chain
  vector), names that look like **typosquats** of popular packages (offline heuristic, then
  **weekly download counts** put numbers behind the hunch: `resembles "lodash" (155M dl/wk) —
  this package: 43 dl/wk — classic typosquat signature`), risky/unknown **licenses**, and weak
  **OpenSSF Scorecard** checks — catching risk that has no CVE yet.
- **GitHub Actions workflow scanning** — `.github/workflows/*.yml` files are manifests too: every
  `uses:` is checked against OSV's *GitHub Actions* ecosystem (advisory ranges evaluated locally —
  OSV doesn't do it server-side for actions), lookalike action names are flagged
  (`action/checkout` vs `actions/checkout`), and any ref that isn't a **full commit SHA** gets a
  mutable-ref warning — a moved tag swaps the code your CI runs (the tj-actions compromise vector).
- **Deprecation surfacing** — under `--latest`, a dependency whose resolved version the maintainer
  deprecated (npm's `deprecated` notice) or **yanked from PyPI** gets its own `deprecated` verdict,
  with the upstream message repeated verbatim — the "stop using this" signal `npm install` prints
  once and CI never sees. Opt-in gate via `failOn: { "deprecated": true }`.
- **Runtime-compatibility + EOL check** — declare the runtime the project actually runs on
  (`--python 3.9` / `--node 18`, a `runtimes` key in the config, or auto-detected from
  `.python-version`/`.nvmrc`) and Preflight flags dependencies whose range **cannot install
  there** (`incompatible`), warns when the runtime itself is **past (or within 90 days of)
  end-of-life** via endoflife.date — no dependency bump fixes a dead interpreter — plus an early
  warning when the *newest* release dropped your runtime —
  i.e. the next auto-bump will break. Catches the class of failure CI on a newer interpreter
  can't: a floor like `uvicorn>=0.49` is green on Python 3.12 but uninstallable on the 3.9 dev
  machine (`Requires-Python >=3.10`). Data: PyPI `Requires-Python` (hard install failure) and
  npm `engines` (advisory), per version.
- **CI-gating** — exits non-zero on any CVE, so it drops straight into a pipeline.
- **Three delivery surfaces, one engine** — a CLI (built to a standalone bundle with tsup), a
  GitHub Action that gates PRs, and a web dashboard, all reusing `@preflight/core`.

## Stages
1. **CLI** (`@preflight/cli`) — `preflight check <manifest>` → a verdict table (`safe` / `pinned` /
   `cve` / `incompatible` / `stale`), with `--latest` (latest version + staleness), `--health`
   (OpenSSF Scorecard), `--node <v>` / `--python <v>` (runtime-compatibility),
   `--fail-level <level>` (tune the exit-1 gate — same grammar as the Action: `cve` / `kev` /
   `epss:<0-1>` / `severity:<low|medium|high|critical>`), `--json`, and `--no-cache`.
   **Working today.**
2. **GitHub Action** (`@preflight/action`) — on every PR, diffs the *whole dependency tree*
   (manifest + lockfile, so lockfile-only PRs count) and posts a sticky comment; the gate fails
   on anything the PR **introduces** — direct or transitive — that meets `fail-level` or violates
   the policy. Pre-existing findings stay informational (the scheduled repo scan owns those).
   **Working today** ([.github/workflows/preflight.yml](.github/workflows/preflight.yml)).
3. **Web dashboard** (`@preflight/web`, Next.js App Router) — paste a manifest → metric cards +
   findings list matching [docs/dashboard-mockup.html](docs/dashboard-mockup.html), dark-mode aware.
   **Live at [preflight-web.vercel.app](https://preflight-web.vercel.app)**. Also exposes a keyless
   `POST /api/scan` (send a manifest + lockfile → full report) so other apps can embed it —
   see [docs/integration.md](docs/integration.md). GitHub-repo OAuth is deferred.

## Quickstart
```bash
npm install
npm run check -- path/to/package.json      # or a requirements*.txt
npm run check -- examples/requirements.txt --latest   # add latest-version + staleness
npm test                                    # vitest
npm run build                               # tsup → standalone dist (publishable CLI)
npm run dev -w @preflight/web               # the dashboard at http://localhost:3000
npm run scan:repos                          # read-only sweep of all your GitHub repos (needs `gh`)
```

`scan:repos` lists your repos via `gh`, pulls each manifest, and prints a ranked cross-repo report —
it writes nothing to any repo. To gate repos going forward, see [docs/rollout.md](docs/rollout.md).

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

## Design-phase mode: `preflight plan`

The checks above catch problems in an *existing* manifest. `preflight plan` moves them to the
**start of a project** — pick the runtime the app will actually run on (and optionally a
framework), list the packages you intend to use, and get the newest versions that install
there plus the generated guardrails:

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

It emits the manifest (`requirements.txt` / `package.json` with an `engines` field) and a
`dependabot.yml` with grouped weekly updates, an `ignore` at each runtime boundary, and — with
`--framework` — the whole lockstep set ignored ("update with `npx expo install`, not
per-package bumps"). Recommended versions are OSV-checked, so a floor that would pin onto a
known CVE is flagged in the plan.

Plans are also checked against a registry of **known-bad pairs** — combinations whose declared
peer ranges *admit* each other but that break together at runtime (e.g. `eslint@10` beside
`eslint-config-next@16` crashes at lint time; the upstream peer range is simply wrong, so no
metadata can reveal it). When a pair matches, the plan holds the package back to the newest
known-good version that still installs on your runtime, says why in the output, and adds a
dependabot `ignore` at the boundary so the auto-updater can't reintroduce the pair. Like the
lockstep registry, the list is data-driven and evidence-based — entries are documented
breakages, never heuristics.

## How it works
`@preflight/core` is the single engine: `manifest` → `osv` + `lockstep` (+ `registry`/`depsdev`)
→ `verdict` → `Report`. The CLI, Action, and dashboard are thin wrappers over `analyze()`.
See [docs/spec.md](docs/spec.md) for the verdict logic and API details, and
[docs/preflight-checklist.md](docs/preflight-checklist.md) for the broader dependency-hygiene
practices this tool automates.

## Policy gate

By default `preflight check` (and the Action) fail on any new CVE. For finer control, drop a
`preflight.config.json` and pass `--policy` (CLI) or set `policy-file:` (Action) — the same gate,
evaluated by `@preflight/core`:

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
  or `"severity:medium"` (worst rated severity at/above the floor; unrated advisories count as
  low, and a KEV'd advisory fails **any** floor — confirmed exploitation beats a severity label).
- `installScript` / `suspiciousName` — fail on a dep that runs an install script / has a typosquat-like name.
- `deprecated` — fail when a resolved version is deprecated upstream (npm `deprecated` / fully
  yanked from PyPI).
- `license` — fail on these license ids, or the buckets `"copyleft"` / `"unknown"`.
- `minHealth` — fail if a *direct* dep's OpenSSF score is below this.
- `runtime` — `"incompatible"` fails when a dep's range cannot install on the target runtime
  (declared in `runtimes` or via flags); `"latest-dropped"` also fails the early warning (the
  newest release dropped the runtime, so the next bump breaks). Without a policy, an explicit
  `--node`/`--python` target failing to install exits non-zero; auto-detected targets
  (`.nvmrc`/`.python-version`) only warn.
- `eolRuntime` — fail when the target runtime itself is past end-of-life (endoflife.date). A
  report-level rule: the violation names the interpreter, not a dependency.
- `unpinnedAction` — fail when a workflow `uses:` an action pinned to a mutable tag/branch
  instead of a full commit SHA (only fires on workflow manifests).

- `allow` — adjudicated exceptions that keep strict rules usable on real dependency trees:
  `installScripts` lists packages permitted to run install scripts (legitimate native binaries
  like esbuild/sharp/fsevents), `advisories` lists GHSA/CVE ids accepted as unactionable (e.g.
  vendored by a framework until it ships the fix). **Every allow that fires is announced** in
  the output (`allowed: …`) — the gate says what it deliberately ignored, so exceptions never
  rot invisibly. Malware is never suppressible.

Malicious packages always fail, regardless of config. `--policy` auto-enables the lookups its rules
need (`license`/`deprecated` → latest version, `minHealth` → health), so you don't have to remember
the flags.

**Where the file lives:** the CLI resolves `preflight.config.json` relative to the directory you
run it *from* (pass `--policy path/to/file.json` for anything else); the Action's `policy-file:`
is relative to the repo root. In a monorepo, one root config passed explicitly is the simplest setup.

## Compliance exports (SBOM + SARIF)

- **CycloneDX SBOM** — `preflight check --sbom [file]` emits a CycloneDX 1.6 JSON inventory of the
  full dependency graph (with each vulnerability, EPSS score, and KEV flag attached) for
  Dependency-Track, OSV-Scanner, or any SBOM-consuming tool.
- **SARIF** — the Action writes `preflight.sarif` on every run; the bundled workflows upload it to
  GitHub **code scanning**, so findings appear in the repo's Security tab with severity coloring.

## Keyless to run

Every data source Preflight queries is **free, keyless, and accountless** — nothing to sign up for,
no API key to store, no token to rotate. That's what lets it drop straight into any pipeline (local,
CI, or the dashboard) with zero configuration.

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
`PREFLIGHT_CACHE_DIR` to override, or `--no-cache` to skip) to be a good API citizen and make
re-runs instant. A *failed* fetch is never cached — if a source is unreachable, that scan is marked
`degraded` (surfaced in the CLI and the PR comment) so a green result is never mistaken for
"all clear" when, say, the KEV feed was down and exploited-status is actually unknown.

> **Design principle:** every new check must be *quick, keyless, and accountless*. If a data source
> needs an account or an API key, it doesn't belong here — that constraint is the whole point, and
> it's what keeps Preflight a drop-in.

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
- Added proactive, pre-CVE supply-chain signals: **install-script** detection, an **offline typosquat
  heuristic** (Damerau-Levenshtein vs a bundled popular-package list), **license-risk** bucketing, and
  an **OpenSSF Scorecard** per-check breakdown — the risk a vulnerability feed can't tell you about.
- Unified every signal into a configurable **policy-as-code gate** (`preflight.config.json`) shared by
  the CLI and the Action — one source of truth for what fails the build (denied license, install
  script, typosquat, min-health floor, or a tunable CVE/KEV/EPSS threshold).

## License
[MIT](LICENSE).
