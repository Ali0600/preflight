# Design decisions

Forks where a real alternative existed, what we chose, and what we passed on. The point is to keep
the *rejected* options — and the reasoning that killed them — retrievable, so they can be revisited
deliberately instead of rediscovered by accident.

## Backlog — alternatives worth trying later

- **Go as a first-class runtime target** (`RuntimeName` + endoflife.date + runtime-compat), which
  would let the bare `go` directive drive an EOL/support notice instead of being ignored for
  stdlib purposes. See *2026-08-18 — Which Go version do we scan the stdlib against?*
- **Shell out to `go env GOVERSION`** for exact stdlib coverage, if Preflight ever gains a
  "local scan may use installed toolchains" mode. Same entry.

---

## 2026-08-18 — Which Go version do we scan the stdlib against?

**The fork:** Go stdlib CVEs are frequent and high-impact (net/http, crypto/tls), and OSV exposes
them under the pseudo-module `stdlib`. But `go.mod` alone does not say which Go version will build
the module. What do we scan?

| Option | Tradeoff |
| --- | --- |
| **A. Use the `toolchain` directive only** *(chosen)* | The `toolchain` line names the toolchain that will actually be used, so the finding is true. Costs coverage: modules without one get no stdlib check at all. |
| B. Use the `go` directive as the stdlib version | Maximum coverage, but the `go` line is a *minimum* — libraries deliberately hold it low for compatibility, so every well-maintained library would be reported as carrying the entire stdlib CVE backlog. A false CVE is the worst output a security tool can produce. |
| C. Shell out to `go env GOVERSION` (what OSV-Scanner does) | Exact for a local scan, but it reports the **scanner host's** Go version — meaningless when scanning someone else's repo in CI — requires Go installed (OSV-Scanner issue #620 is exactly this failing in a container), and Preflight shells out to no toolchain anywhere by design. |
| D. Treat the `go` directive as a runtime target (like `.nvmrc`/`.python-version`) | Conceptually the best fit — it *is* the declared runtime — but it ripples `RuntimeName` through runtime-compat, plan, artifacts and EOL. Out of scope for the parser PR. |

**Chosen: A**, with the gap stated out loud. When there's no `toolchain` directive the data-source
ledger prints *why* stdlib wasn't evaluated and what to do about it — silence would read as "stdlib
is clean", which is the fail-open shape this codebase keeps closing.

**Status of the rest:** B — `rejected`, it manufactures false positives on exactly the well-maintained
libraries we most want to keep quiet about. C — `rejected` for CI scanning (wrong machine's answer),
but `deferred — worth trying` if a local-only "use installed toolchains" mode ever appears.
D — `deferred — worth trying`.

**Revisit hook:** `parseGoMod` in `packages/core/src/lockfiles.ts` decides this in one place (the
`toolchain` branch that unshifts the `stdlib` dep); the explanatory ledger row is the `ecosystem ===
'Go'` block in `describeSources` (`packages/core/src/analyze.ts`). For option D, the seams are
`RuntimeName` in `types.ts`, `PRODUCT`/`cycleOf` in `eol.ts`, and `FILES` in `runtime-detect.ts`.

---

## 2026-08-18 — Scanning Ruby: `Gemfile` or `Gemfile.lock`?

**The fork:** which file is the Ruby manifest?

| Option | Tradeoff |
| --- | --- |
| **A. `Gemfile.lock` only** *(chosen)* | Carries the resolved version of every installed gem, direct and transitive — exactly what OSV needs. Costs nothing except that a project which doesn't commit its lock can't be scanned. |
| B. `Gemfile` (+ lock when present) | Would scan more repos, but the Gemfile holds *requirements* (`gem "rails", "~> 7.0"`), not versions — so most entries would be unresolvable and silently skipped, producing a scan that looks complete and checks almost nothing. |
| C. Both, preferring the lock | Same as A in every case that matters, plus a second parser and a second failure mode to maintain. |

**Chosen: A.** A bare `Gemfile` is rejected with the standard "unsupported manifest" error, and a
test pins that. Rejecting loudly beats scanning vacuously.

**Status:** B — `rejected` (a scan that can't resolve versions is worse than no scan: it reads as
coverage). C — `rejected — no added value over A`.

**Revisit hook:** `ecosystemFor` in `packages/core/src/manifest.ts`.

---

## 2026-08-18 — Do gems from `PATH` and `GIT` sources get scanned?

**The fork:** `Gemfile.lock` can source gems from rubygems.org (`GEM`), a git remote (`GIT`), or a
local directory (`PATH`). Which are real packages?

| Option | Tradeoff |
| --- | --- |
| **A. Scan `GEM` + `GIT`, skip `PATH`** *(chosen)* | A git dep is a fork of a real gem at a real version, so advisory matching is meaningful. A `PATH` gem is code in this repo whose name is arbitrary — an in-repo `payments` engine would inherit whatever advisories the rubygems `payments` gem has. |
| B. Scan everything | Simpler, and "conservative = scan more" is the house rule elsewhere. But that rule applies to *scope* (dev vs prod), not to *identity*: scanning a local gem under a stranger's name isn't caution, it's a wrong answer. |
| C. Scan `GEM` only | Safest, but drops real forks of real gems — a common way to run a patched (or unpatched!) dependency. |

**Chosen: A.** The same rule is applied to Rust in the sibling PR (crates with no `source` are
workspace-local and aren't scanned, though their dependency edges still mark what's direct).

**Status:** B — `rejected — conflates identity with scope`. C — `rejected — drops real forks`.

**Revisit hook:** `parseGemfileLock` in `packages/core/src/lockfiles.ts` (`GEM_SOURCE_SECTIONS` and
the `section === 'PATH'` skip).
