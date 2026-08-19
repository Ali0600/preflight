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

## A gate should show its coverage, not just its verdict — a green result with no visible scope is a black box

"I don't see any information when I use Preflight through the CI." A clean run reported findings
(or none) but never *what it actually checked* — which sources ran, which were unreachable, which
were off. A pass with no visible scope is indistinguishable from a check that quietly ran nothing.
Fix: `Report.sources` — a per-run ledger (`ok` / `degraded` / `skipped` + a one-line result per
source), derived in core from what was genuinely queried (the options + whether any CVEs were
found) and the degraded set, so it never claims a source ran that didn't. Rendered on every surface
(CLI, Action comment + scheduled issue, web panel, JSON). Skipped sources say *why* ("no CVEs to
prioritize", "enable with --latest"), so the ledger is complete and self-documenting.

**Why it came up:** the tool's whole value is trust, and a green check the user can't inspect earns
none — the same instinct behind "a resilient fallback must announce itself", applied to the happy path.

**Takeaway:** surface a gate's *coverage* alongside its verdict — list the inputs/sources consulted,
their reachability, and what each contributed, even (especially) on a clean pass. Derive the ledger
from what actually ran so it can't drift from reality, and show skipped items with a reason so "what
else could this check?" is answered in-band.

## Sequential string replaces contaminate each other — tokenize instead

The `ignore-paths` glob-to-regex converter chained `.replace()` calls (`**/` → `(?:.*/)?`, then
`**` → `.*`, then `*` → `[^/]*`). The third pass re-matched the `*` characters *inside the
substitutions the earlier passes had produced*, silently corrupting the pattern — `examples/**`
stopped matching nested paths. The tests caught it; the fix is a single-pass tokenizer that
walks the input once and never re-reads its own output. (Bonus trap from the same hour: a JSDoc
comment containing a literal `**/` terminates the block comment early — the docs about globs
broke on their own syntax. Line comments there.)

**Why it came up:** fresh-eyes tier A — adding repo-scan path exclusions with a dependency-free
glob matcher.

**Takeaway:** any multi-rule text transform where one rule's output can match another rule's
pattern must process the input in a single pass (tokenize), not as chained global replaces.
If you must chain, prove no substitution introduces characters a later rule matches.

## One vulnerable package, several entry paths — re-run the scanner after the fix

Bumping `@actions/github` (undici 6) looked like it cleared the 9 undici advisories — `npm ls`
showed 6.27 under that tree. Re-running Preflight's own scheduled scan said otherwise:
`@actions/core@1` *also* pinned `http-client@2 → undici@5.29`, a second path I hadn't looked at.
The fix wasn't complete until the scanner said so (`npm audit`: 0 vulnerabilities).

**Why it came up:** fixing issue #44's findings; the re-dispatched scan caught the leftover.

**Takeaway:** a vulnerable package is a *node in a graph*, not a line in one dependency chain —
fixing the path you traced says nothing about the paths you didn't. The finish line for a
dependency fix is the detector reporting zero, not the bump landing.

## An API can accept your query and silently not evaluate it — probe with a known-positive

Planning GitHub Actions workflow scanning, the OSV docs said the "GitHub Actions" ecosystem is
supported, and a versioned query (`{package, version}`) is the standard shape used for npm/PyPI.
Probing first with a *known-affected* input — `tj-actions/changed-files@45.0.7`, inside the
published advisory range — returned `{}`: OSV stores the advisories (package-level queries return
them, ECOSYSTEM ranges and all) but does **not** evaluate versioned queries against those ranges
server-side for this ecosystem. The request is well-formed, the response is well-formed, and the
answer is silently meaningless. The fix was architectural: query per package and evaluate the
advisory ranges locally with our own semver machinery. Shipped naively, the feature would have
been a scanner that is always green — the worst kind of security tool.

**Why it came up:** PR #55 (workflow scanning), during the pre-coding API-shape verification the
repo's conventions require.

**Takeaway:** before building on a query capability, send a request whose correct answer you
already know is non-empty ("known-positive probe"). A schema-valid `{}` from a supported endpoint
is indistinguishable from "no findings" unless you already know findings exist.

## SHA-pinning GitHub Actions — labels move, fingerprints don't

A `uses: owner/action@v4` line runs someone else's code in your CI with your secrets in reach.
`v4` is a git tag — a movable label the *action's owner* controls; they (or whoever hacks them)
can point it at different code tomorrow and your next build runs it, with no diff in your repo
to review. A 40-character commit SHA is a fingerprint computed from the code itself — it can
never be redirected, so `uses: owner/action@<sha>  # v4.1.2` freezes exactly what you audited.
Updates still happen, but as Dependabot PRs you approve. The March 2025 `tj-actions/changed-files`
compromise was exactly this: tags moved onto secret-dumping code, thousands of repos ran it
automatically. One deliberate exception: a tag you *own* as a release channel (consumers ride
`preflight@v1` so moving the tag ships updates) — there the mutability is the feature, and the
trust question ("who can move this label?") answers "me".

**Why it came up:** Preflight's new workflow scanning (#55) flagged the landing repo's own
`actions/checkout@v4` — and the user asked what SHA-pinning even means.

**Takeaway:** in CI, a version *label* is a live trust relationship with whoever controls it; a
*SHA* is a one-time trust decision. Pin third-party actions to SHAs; float only on tags you own.

## `rm -rf node_modules` misses workspace-local `node_modules` — and stale trees lie

Clearing the August 2026 advisory wave, an `overrides` entry for `next → postcss` appeared not to
work: the lockfile kept showing `packages/web/node_modules/postcss@8.4.31` no matter which override
form I used (top-level, nested, both). I tried four variants, then even test-upgraded to Next 16 —
which *also* "failed". The override was fine the whole time. `rm -rf node_modules` at the repo root
does **not** remove `packages/*/node_modules`, so every install was resolving against a stale
workspace tree; `npm ls` finally exposed it as `next@15.5.23 invalid: "^16.3.1"` alongside
`next@16.3.1 extraneous`. One `rm -rf node_modules packages/*/node_modules package-lock.json`
produced `found 0 vulnerabilities` — and `sharp`, which had looked "dropped by a conflicting
override", was simply another stale-tree artifact; it resolved to the patched 0.35.3.

**Why it came up:** the 21 GitHub Security-tab alerts (Preflight's own SARIF) after the Aug 2026
`next`/`postcss`/`undici`/`sharp` advisory wave.

**Takeaway:** in an npm workspaces monorepo, a "clean install" is
`rm -rf node_modules packages/*/node_modules package-lock.json` — anything less leaves a shadow tree
that silently answers your questions with old data. When a dependency experiment gives an impossible
result, run `npm ls <pkg> --all` and look for `invalid`/`extraneous` before concluding the tool is
broken.

## An "equivalent mutant" is a finding about your code, not a failed test

Adding the `Gemfile.lock` parser, a mutation run reported one survivor: removing the
`GEM_SOURCE_SECTIONS.has(section)` guard changed nothing. The instinct is to write a test that
catches it. Probing first — re-running the parse loop with each guard switched off — showed the
section allowlist *and* the `inSpecs` flag are both no-ops on well-formed input: the anchored
`/^(\S+)\s+\((.+)\)$/` spec regex already rejects every metadata line (`ruby 3.2.2p53`,
`x86_64-linux`, `remote: …`). The mutant wasn't a coverage gap; it was telling me which guard
actually carries the weight. Re-aiming the mutant at the regex (loosening it to unanchored) —
the real constraint — was caught immediately.

**Why it came up:** proving the new Ruby parser's tests bite before shipping them.

**Takeaway:** when a mutant survives, first ask whether the code is *equivalent* under it, not
whether the test is weak — the answer tells you which line is load-bearing and which is
defence-in-depth. Then aim the mutant at the load-bearing line. Keep the redundant guards (they're
cheap and make intent explicit), but don't claim test coverage you don't have.

## A registry keyed on names needs an ecosystem tag before the second ecosystem, not after

Preflight's framework-lockstep registry matched on package *name* only — fine while every entry
was npm. Adding Rails (a gem) meant a project depending on an npm package called `rails` would be
told to run `bundle update rails`. Tagging each set with its ecosystem fixed the lookup, and the
type-checker then found a second, worse leak I hadn't considered: `preflight plan --framework
<name>` seeds the generated manifest with the set's member *names*, so `--framework rails` on an
npm plan would have emitted a `package.json` full of gem names that 404 on npm. An existing test
asserting `frameworkSet('rails')` is `undefined` is what surfaced it.

**Why it came up:** adding the RubyGems ecosystem to a registry that had been npm-only.

**Takeaway:** package names are unique only *within* a registry. Any lookup table keyed on a bare
name needs an ecosystem/namespace field the moment a second namespace exists — and grep every
consumer, because the dangerous one is usually not the lookup you were editing. A test that breaks
when you add data is doing its job: read what it was really asserting before updating it.

## A "minimum version" declaration is not a "version in use" — don't scan it as one

`go.mod`'s `go` directive looks like the obvious source for "which Go stdlib should we check for
CVEs?" It isn't: it declares a *minimum*, and libraries deliberately hold it low so they stay
usable by older consumers. Scanning it as the build version would have reported every
compatibility-minded Go library as carrying the entire stdlib CVE backlog — `go 1.21.0` alone
matches 75 advisories. The `toolchain` directive *is* prescriptive (it names the toolchain that
will be used), so that's what we scan; when it's absent the data-source ledger states that stdlib
went unchecked and why. Worth knowing: OSV-Scanner solves the same problem by running
`go env GOVERSION`, which answers for the *scanner's* machine — fine locally, meaningless when
scanning someone else's repo in CI, and a documented failure when Go isn't installed in the
container.

**Why it came up:** adding `go.mod` support and having to decide what the Go stdlib version is.

**Takeaway:** before treating a declared version as a fact about what runs, ask whether the field
is a floor, a ceiling, or an exact pin — floors (`>=`, "minimum required", "engines") describe what
is *supported*, not what is *installed*. If only a floor is available, report the gap out loud
rather than inventing a value: an unchecked area you name is useful; one you paper over is a lie.

## Scanning the wrong file can be worse than scanning nothing

Go has two candidate files. `go.mod` lists the modules actually selected for the build; `go.sum`
holds hashes for modules that were *considered*, including versions that lost minimal-version
selection and are never compiled. `go.sum` is bigger and looks more thorough, which is exactly the
trap — scanning it reports CVEs for versions the build does not contain. Same shape as choosing
`Gemfile.lock` over `Gemfile`, but inverted: there the *smaller* file was the wrong one because it
lacked resolved versions.

**Why it came up:** picking the input file for each new ecosystem parser.

**Takeaway:** for any new ecosystem, ask which artifact records *what actually got installed* —
not which one is largest, most authoritative-sounding, or most often committed. A file listing
candidates produces false positives; a file listing requirements produces silent misses. Both read
as a successful scan.

## A mutation pattern that matches twice sabotages the wrong function

Mutation-testing the new `Cargo.lock` parser, one mutant reported NOT CAUGHT for a case the test
clearly covered. The mutation was `const id = \`${p.name}@${p.version}\`` → `const id = p.name`,
and that exact line exists **twice** in the file: once in the shared pnpm/yarn `assemble()` helper
and once in the Cargo parser. `String.replace(str, str)` replaces the *first* match, so the harness
had been sabotaging a completely different parser and then reporting a verdict about this one. The
harness now refuses to run any mutant whose pattern occurs more than once, and the mutants are
anchored on a neighbouring line unique to the function under test.

**Why it came up:** a survivor that made no sense, in a parser whose test demonstrably asserted the
behaviour.

**Takeaway:** a mutation harness must assert *where* the edit landed, not just that it landed —
count the matches and fail loudly on ambiguity. Generalises to any find-and-replace over source:
`sed`, codemods, "rename this string". When a mutant survives a test you are sure covers it,
suspect the aim before the test. (Sharpens the existing entry on equivalent mutants: same symptom,
opposite cause — one means the code is equivalent, the other means you never mutated it.)

## Before trusting a namespace prefix, check that the namespace is actually uniform

Adding "these packages must move together" entries for Prisma, Storybook, tRPC and Sentry, the
obvious rule for each was a scope prefix — `@prisma/`, `@sentry/`. Querying the registry for the
actual latest versions killed half of them: `@sentry/cli` is 3.6.2, `@sentry/webpack-plugin` and
`@sentry/vite-plugin` are 5.4.0, `@sentry/conventions` is 0.19.0 — while the SDK is 10.70.0. Same
for `@prisma/dev` (0.25.1) and `@prisma/studio-core` (0.33.0) against Prisma's 7.9.1. A prefix rule
would have told people to hold back build tooling that has nothing to do with the SDK's release
train. Storybook and tRPC *are* uniform, so prefixes are right there — and `@trpc/client` even
declares `peerDependencies: { "@trpc/server": "11.18.0" }`, an exact pin.

**Why it came up:** growing a curated registry whose whole value is being right.

**Takeaway:** a shared scope/namespace is a publishing convention, not a versioning contract.
Before writing a prefix rule (or any "everything under X behaves the same" rule), sample several
members and compare them against the anchor — one counter-example turns the rule from advice into
misinformation. Prefer an explicit list when the sample disagrees.

## The absence of a constraint is the bug — look for what a package *doesn't* declare

`@types/react@19` declares `peerDependencies: {}`. Nothing anywhere ties it to a React version, so
npm resolves it beside `react@18` without a murmur and Dependabot bumps it as a routine update —
after which the build stops type-checking (React 19's types removed the global JSX namespace and
made `useRef` require an argument). Every metadata-driven check passes, because the metadata that
would express the conflict does not exist.

**Why it came up:** picking the strongest possible entry for a known-bad-pairs registry.

**Takeaway:** when hunting for breakage a tool can't see, look for missing declarations rather than
wrong ones — a package with no peer range, no engines field, no lockfile entry. Absence produces
silence at every layer, which is exactly why it survives review, CI and auto-update bots alike. And
when you find one, check the sibling: `@types/react-dom` had the identical gap.

## Never fetch a user-supplied URL — parse it into pieces and rebuild it

The GitHub-URL scan takes an arbitrary string from an anonymous caller on a public endpoint and
ends up making an outbound HTTP request. The whole safety of that hinges on one rule: the pasted
string is *never* fetched. It's split into `owner`/`repo`/`ref`/`dir` segments, each validated
against GitHub's own naming charsets, and the URL is then **rebuilt** from a hardcoded origin plus
those segments. Parsing is deliberately string-only — no `new URL(input)` — because URL parsers
are full of quirks (userinfo, backslash normalisation, unicode host mapping) that can hand you a
host you didn't intend, and `https://github.com@evil.com/o/r` is a host of `evil.com`. Paired with
`redirect: 'error'`, so a redirect can't move the request to a URL we never constructed.

**Why it came up:** adding "paste a GitHub link and scan it" to the public dashboard.

**Takeaway:** the SSRF-safe shape for "fetch something the user named" is *parse → validate each
component → reconstruct*, never *sanitise the string and fetch it*. A denylist of bad prefixes is
the wrong instrument; an allowlist charset per component is the right one, because it defines what
can be expressed rather than enumerating what's forbidden.

## Distinguishing "absent" from "unavailable" is what stops an outage reading as an all-clear

`raw.githubusercontent.com` returns a bare 404 for a file that doesn't exist — and the same bare
404 for a repo that's private or nonexistent. So 404 has to mean "absent" and drive the scan on.
Every *other* non-OK status (429, 403, 5xx) and every timeout must instead fail the whole request
closed with a 502, because "we couldn't reach GitHub" must never render as "this repo has no
manifests to worry about". The same reasoning forbids silently degrading when a lockfile fetch
fails beside a present `package.json`: reporting the direct deps only would look like a clean,
complete scan of a much smaller tree.

**Why it came up:** deciding the fetch loop's error policy for the repo-scan endpoint.

**Takeaway:** in any fetch-many-optional-things loop, write down which status codes mean *absent*
and which mean *unknown* before writing the loop — and make "unknown" loud. A missing thing and an
unreachable thing produce the same empty result, and only one of them is safe to proceed from.
