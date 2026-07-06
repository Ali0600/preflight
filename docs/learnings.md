# Learnings — Preflight

Teachable, transferable concepts that came up while building this project.

## `publishConfig` is not portable across package managers
`publishConfig` in `package.json` lets you override fields at publish time — but **npm only
overrides registry/tag/access**, while **pnpm and yarn** also override `main`/`exports`/`types`/`bin`.
**Why it came up:** Stage 1's build plan was going to keep `exports` pointing at `src` for the dev
loop and use `publishConfig` to repoint to `dist` at publish — which silently does nothing under
npm (this repo uses `npm ci`). Verifying first (npm/cli#7586 is still an open feature request)
avoided shipping a broken publish.
**Takeaway:** A config key existing ≠ your package manager honoring it — confirm per-tool before
architecting around it.

## Bundle the consumer instead of publishing every workspace package
tsup/esbuild treat `dependencies` as **external** (not bundled) and everything else as **inlined**.
Setting `noExternal: ['@preflight/core']` inlines the workspace engine into the CLI, so the published
CLI is self-contained and only needs its real runtime deps (`commander`, `picocolors`).
**Why it came up:** It sidestepped the `publishConfig` problem entirely — the CLI ships standalone
and `@preflight/core` can stay `src`-resolved for the zero-build dev loop (no need to publish core).
**Takeaway:** If an internal package only exists to feed one entrypoint, bundle it into that
entrypoint rather than publishing + versioning it separately.

## A CVSS vector is not a score — you compute the number
OSV advisories carry severity either as a GHSA label (`LOW/MODERATE/HIGH/CRITICAL`) **or** as a CVSS
*vector* string (`CVSS:3.1/AV:N/AC:L/...`). The vector encodes the metrics, not the 0–10 base score;
you run the CVSS formula (impact + exploitability, scope-adjusted, round-up) to get the number, then
band it (≥9 critical, ≥7 high, ≥4 medium, >0 low).
**Why it came up:** GHSA labels cover most npm/PyPI advisories, but records with only a vector were
mapping to `unknown`; `cvss.ts` closes that gap and is fully unit-testable against known scores.
**Takeaway:** When an upstream gives you a *vector*/encoding rather than a derived value, the
derivation is your job — and it's a perfect pure-function unit test.

## JSON round-trips drop `undefined` — wrap cached values in an envelope
`JSON.stringify(undefined) === undefined`, so writing a bare `undefined`/`null` result to a cache
file and reading it back breaks. Store `{ v: value }` and return `.v`.
**Why it came up:** The disk cache wraps API calls that legitimately resolve to `undefined` (e.g. a
package with no Scorecard); the envelope lets a "negative" result cache cleanly instead of re-fetching.
**Takeaway:** Cache the *envelope*, not the raw value, whenever the value can be `undefined`/`null`.

## A JS GitHub Action runs from committed code — bundle and commit `dist`
GitHub runs a JS action straight from the files in the repo with **no `npm install`** step, so the
entry (`runs.main`) must be a self-contained bundle that already inlines every dependency — and that
bundle has to be **committed**. We bundle with tsup (`noExternal: [/.*/]`, CJS, `node20`) and add a
`.gitignore` negation (`!packages/action/dist/`) so the one build artifact we *do* track isn't
ignored by the blanket `dist/` rule.
**Why it came up:** Stage 2's `packages/action`. The same `pull_request` workflow uses the local
action (`uses: ./packages/action`), so it pre-flights its own PRs — which is also the end-to-end test.
**Takeaway:** Action authoring ≠ normal publishing: commit a bundled `dist`, pin `runs.using` to a
node version, and keep the action's logic split into a pure core (unit-testable) + a thin
`@actions/*` glue layer.

## Consuming a TS-source workspace package from Next.js → `transpilePackages`
`@preflight/core` ships TypeScript source (its `exports` point at `./src`), so Next.js has to
**transpile** it rather than expecting a prebuilt `dist`: `transpilePackages: ['@preflight/core']`
in `next.config.ts`. The engine only loads server-side (the `/api/analyze` route handler, `runtime
= 'nodejs'`); the client imports the package **type-only**, so `node:fs`/`node:crypto` never reach
the browser bundle. The Next app also sits outside the root ESLint/`tsc` globs and self-checks via
`next build`, avoiding JSX-parsing conflicts with the base config.
**Why it came up:** Stage 3 reuses the same engine as the CLI and Action with zero duplication.
**Takeaway:** In a TS monorepo, a framework that bundles (Next/Vite) can consume source packages
directly with a transpile hint — no separate build/publish step — but keep runtime-only deps on the
server and import them as types on the client.

## The lockfile already holds the full dependency graph — scan it, not just the manifest
A `package.json` lists only *declared* deps, but the `package-lock.json` `packages` map lists **every**
installed package — direct and transitive — keyed by its `node_modules/…` path (nested for non-hoisted
copies), each with a resolved `version`. Walking that map (taking the name after the last
`node_modules/`) yields the whole graph with zero extra API calls.
**Why it came up:** ~80% of exploitable CVEs come from indirect deps; Preflight was only checking the
8 declared ones and missing the 352 transitive. The lockfile turned an 8-dep scan into a 360-dep scan
for free. Keyed vuln results by `name@version` since one package can appear at several versions.
**Takeaway:** For supply-chain scanning, the lockfile — not the manifest — is the source of truth for
*what's actually installed*; the manifest only tells you what was *asked for*.

## Reactive (CVE) vs proactive (attack-vector) detection — and proactive is often free
A vulnerability feed (OSV/CVE) is *reactive*: it only flags what's already been reported, so a fresh
malicious package or a risky-but-not-yet-CVE'd dep slips through. The *proactive* signals — does it
run an `install` script, does its name look like a typosquat, what's its license, how healthy is the
upstream project — catch a different, earlier class of risk, and most are **already in data you parse**:
npm's lockfile carries `hasInstallScript`; typosquatting is pure offline string distance against a
bundled popular-package list; license + Scorecard come from registry/deps.dev metadata you may already
fetch.
**Why it came up:** A crafted manifest with `lodahs`/`crossenv` got flagged as malware *and* as a
typosquat — the heuristic catches the lookalike even when OSV hasn't (yet), and `hasInstallScript`
surfaced esbuild/sharp/fsevents with zero extra calls.
**Takeaway:** Don't stop at "known vulnerabilities." The cheapest, highest-signal supply-chain checks
are the proactive ones, and they're usually a field in data you already have — not a new API.

## A heuristic needs a real corpus, not just hand-picked test cases
The typosquat unit tests (`lodahs`→`lodash`, `react`→clean) all passed, but the first run across real
repos flagged `@babel/core` and `@dnd-kit/core` as resembling `cors` — the normalizer stripped the
`@scope/` and compared the bare `core` (distance 1 from `cors`). Crafted tests confirm *true* positives;
they rarely contain the long-tail inputs (scoped names, hyphens, unusual lengths) where a fuzzy matcher
*false*-positives.
**Why it came up:** `npm run scan:repos` over ~11 real repos surfaced it immediately; no unit test had
a scoped package one edit from a short popular name.
**Takeaway:** Before trusting a heuristic/fuzzy matcher, run it over a real corpus and eyeball the
hits — false positives hide in inputs you didn't think to write a test for. Then add the real-world
miss as a regression test (here: `@babel/core` → no match).

## Severity ≠ risk: pair CVSS with EPSS (likelihood) and KEV (confirmed exploitation)
CVSS scores how *bad* a vuln is if exploited; it's "top-heavy" (lots of 9s/10s) and says nothing about
whether anyone is actually exploiting it. **EPSS** (FIRST, keyless batch API) gives a 0–1 *probability*
of exploitation in the next 30 days — and it's "bottom-heavy", so most CVEs score <0.05. **CISA KEV**
is the certainty layer: a free JSON feed of CVEs *confirmed* exploited in the wild. Together they turn
"40 critical CVEs" into "the 2 that are actually being exploited."
**Why it came up:** Preflight graded severity from CVSS alone (Dependabot's exact weakness). Adding
EPSS+KEV let the CI gate fire on *exploitability* (`fail-level: kev` / `epss:0.5`), not just any CVE.
A live check confirmed the design: 19 urllib3 CVEs all scored EPSS <0.03 — correctly *not* flagged as
urgent, where CVSS would have screamed "high" at all of them.
**Takeaway:** Map advisories to their CVE alias and enrich with EPSS+KEV before ranking; "critical
severity" is a starting point for triage, not a priority. Bottom-heavy EPSS is a feature, not a bug.

## An undocumented batch limit only shows up on large real inputs — chunk defensively
OSV's `querybatch` takes a list of package queries but rejects very large batches with a `400` — an
**undocumented** ~1000-query practical cap. It's invisible until a real big repo hits it (the fleet
scan 400'd on a 1177-dep monorepo). The fix is to split into chunks of ≤1000, `Promise.all` them, and
`.flat()` — but two details matter: (1) keep chunk order so `results[i]` still aligns with `deps[i]`
(a batch API's results are positional), and (2) pick the chunk size (1000) so the *common* case
(≤1000 deps) stays a single chunk with the **same cache key as before** — zero cache churn on the 99%
path, only big repos change behavior.
**Why it came up:** `npm run scan:repos` crashed on the one repo big enough to exceed the cap; unit
tests with a handful of deps never approached it, so a 1001-dep test was added to lock the boundary.
**Takeaway:** Assume every batch endpoint has an undocumented size ceiling; chunk before you hit it,
preserve index alignment, and size the chunk so the ordinary case is byte-for-byte the old single
request (stable cache key). Add a test that crosses the chunk boundary, not just a small happy path.

## The npm registry's "corgi" doc: per-version metadata in one cheap fetch

`GET registry.npmjs.org/{name}` with `Accept: application/vnd.npm.install-v1+json` returns the
abbreviated ("corgi") document — the full `versions` map with the install-relevant fields
(`engines`, `dist`, `deprecated`) at a fraction of the full doc's size, one request per package.

**Why it came up:** the runtime-compatibility check needs *per-version* `engines.node`. The full
doc carries megabytes of readme/changelog for big packages; the corgi doc doesn't. (PyPI's
equivalent: the legacy JSON's `releases[version][].requires_python` — also one fetch.)

**Takeaway:** before fanning out per-version API calls, check whether the registry has a
"for installers" document shape that carries the whole history in one response.

## Advisory tooling should degrade to silence, not to false alarms

Every evaluator in the runtime check returns `boolean | undefined`, and `undefined` is
contractually "treat as compatible": an unparseable semver range, a PEP 440 `===` atom, or a
missing constraint can only *suppress* a warning, never fabricate one.

**Why it came up:** version-range grammars in the wild are full of exotica (`workspace:*`,
epochs, local versions). A checker that errs toward flagging would train users to ignore it.

**Takeaway:** for a linter/advisor, decide which error direction is acceptable up front and
encode it in the return type (`undefined` = can't tell = stay quiet); a definite "no" must come
only from fully-parsed input.

## A PR gate must diff the resolved tree, not the declared manifest

"What did this PR introduce?" has two very different answers: the *declared* diff (manifest
entries added/bumped — what a human edited) and the *tree* diff (every `name@version`, direct or
transitive, that's new in the lockfile). The Action gated the first and only *mentioned* the
second, so a PR whose lockfile vendored `postcss@8.4.31` passed with "✅ No new CVEs introduced"
while the CLI failed the same commit. The fix keys both sides on `name@version` (a package can
appear at several versions), fetches the **base** manifest *and lockfile* to enumerate the base
tree, and evaluates the gate + policy over the introduced set — with lockfile-only PRs (npm
audit fix) triggering the scan at all, since `package-lock.json` previously didn't match the
changed-file filter.

**Why it came up:** dogfooding on NutriDex (BUG-3, issue #20) — the CI gate protecting `main`
was strictly weaker than the local CLI on the same commit + policy.

**Takeaway:** any change-scoped gate (security scan, license check, size budget) must diff the
*resolved artifact* the change produces, not the source file the human edited — and every input
that can move that artifact (the lockfile, not just the manifest) must trigger it.

## An allow list is a fallback path — make it announce itself

Adding policy exemptions (`"allow": ["esbuild", "GHSA-…"]`) made the strict `installScript` rule
usable on real trees, but a silent exemption is a future blind spot: nobody remembers *why*
esbuild is allowed, and a compromised allowed package sails through unexamined. So
`evaluatePolicy` returns a `suppressed` count and every surface prints it ("✓ policy ok · 5
suppressed by allow list"); pins like `sharp@0.34.5` deliberately expire on the next version
bump; and malware is structurally exempt from exemption (checked before the allow list is even
consulted).

**Why it came up:** issue #21 — `installScript: true` fired on esbuild/fsevents/sharp in every
real Next.js tree with no adjudication mechanism, so the gate was either red forever or off.

**Takeaway:** design exemption mechanisms like resilient fallbacks: visible (count and print
suppressions), bounded (prefer expiring pins over blanket names), and with a floor that can
never be exempted (malware). Same rule as "a resilient fallback must announce itself".

## When upstream compatibility metadata lies, only curated evidence catches it

Every automated check in `plan` trusts *declared* metadata — `engines`, `Requires-Python`, peer
ranges. T5 broke that trust: eslint-config-next 16 declares `eslint >=9`, which wrongly admits
ESLint 10, so the recommended pair crashed at lint time and **no metadata lookup could have
seen it coming**. The mitigation (`combos.ts`) is a curated known-bad-pairs registry: entries
are documented breakages with an explicit boundary (`eslint >=10` × `eslint-config-next <17`),
matched only when `satisfies()` returns a hard `true` (its "can't tell" never fires), with the
fallback filtered through the same runtime check as everything else — and a dependabot `ignore`
at the boundary so the auto-updater can't quietly reassemble the broken pair next week.

**Why it came up:** dogfood T5 / issue #31 — `plan` validated each package individually but
never the set, and the one failure mode it missed was the one where the upstream's own
declaration is wrong.

**Takeaway:** declared-compatibility checks have a ceiling: the declaration itself can lie.
The escape hatch is a small, evidence-based exception list — each entry a documented breakage
with a version boundary, never a heuristic — and it must pair with an auto-updater ignore, or
the fix lasts exactly one dependabot cycle. Design such lists to self-expire (the boundary
range stops matching when the fixed major ships).

## "Scan didn't run" is not "scan ran degraded" — the first fails closed, the second warns

Preflight has two failure shapes, and they must be handled oppositely. A *degraded* scan ran
but lost a **secondary** enrichment source (KEV/EPSS unreachable) → warn, don't block (announce
via `Report.degraded`, let the gate evaluate what it has). A *scan failure* means the **primary**
OSV fetch threw (fail-closed by design) or the manifest was unparseable → there are **zero**
results, so the gate must fail closed, not pass. The audit-2 bug (#42) was the Action treating
the second like the first: it caught the thrown `analyze`, logged "Skipped", and — if that was
the only changed manifest — returned a **green** check with a stale "✅ No new CVEs" comment,
while the CLI exited non-zero on the exact same throw. Fix: collect skipped manifests, surface
them, and `setFailed` (a pure `prGateFails()` carries the decision so it's testable without octokit).

**Why it came up:** second security audit — the fail-closed OSV throw the *first* audit added was
silently defeated at the Action boundary, so a transient OSV outage during a risky PR → green gate.

**Takeaway:** enumerate a gate's failure modes and classify each as fail-open or fail-closed up
front; "couldn't evaluate at all" is always fail-closed. Then prove **every surface** (CLI, CI
Action, API) makes the same call on the same failure — a `catch` that downgrades an exception to a
skipped item quietly converts fail-closed into fail-open.

## Bound the fan-out, not just the payload, on an untrusted amplifying endpoint

The public `/api/scan` capped the request body at 8 MB but not the **dependency count**, and one
request amplifies: an 8 MB lockfile enumerates tens of thousands of packages, each fanning out to
OSV/registry/deps.dev — thousands of outbound calls per request (self-DoS against the 60 s Vercel
budget, and a way to get Preflight rate-limited by its own free upstreams). Fixed with
`AnalyzeOptions.maxDeps`, thrown as `GraphTooLargeError` **before any network call**; the web
routes cap at 5000 → HTTP 413, while trusted callers (CLI/Action/fleet) stay unbounded.

**Why it came up:** audit-2 finding #2 — a keyless public endpoint whose work per request is
unbounded in the dimension that actually costs (fan-out), not the one that was capped (bytes).

**Takeaway:** for a public endpoint that turns one input into N side effects, cap **N** (the
amplification factor), not just the input size — and enforce the cap before the expensive work,
scoped to the untrusted caller so trusted paths keep full range.
