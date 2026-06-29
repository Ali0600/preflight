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
