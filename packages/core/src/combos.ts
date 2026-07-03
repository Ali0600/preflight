import type { RuntimeMeta } from './runtimes';
import {
  compareSemver,
  isPrereleaseSemver,
  parseSemver,
  rangeAdmitsSeries,
  satisfies,
  type SemVer,
} from './semver';
import type { Ecosystem, RuntimeTarget } from './types';

// Known-bad version *pairs*: combinations that install fine — the upstream peer range
// admits them — but break together at runtime. No metadata check can catch these,
// because the whole problem is that the declared peer range is WRONG. Like the
// lockstep registry this is data-driven and evidence-based: an entry is a documented
// breakage, never a heuristic — a false "incompatible" is bad advice (cf. semver.ts's
// undefined-means-compatible contract).

export interface KnownBadCombo {
  ecosystem: Ecosystem;
  /** The package `plan` holds back when the pair matches. */
  subject: string;
  /** Subject versions known broken alongside `with` (must match strictly — see findComboHolds). */
  subjectBroken: string;
  /** Where the known-good fallback lives (the complement of subjectBroken). */
  subjectFallback: string;
  /** The other half of the pair, at the versions that break. */
  with: string;
  withRange: string;
  /** Why — rendered verbatim in the plan note. */
  reason: string;
}

export const KNOWN_BAD_COMBOS: KnownBadCombo[] = [
  {
    // Dogfood T5 / issue #31: crashes at lint time (`contextOrFilename.getFilename is
    // not a function`) — eslint-config-next ≤16's vendored eslint-plugin-react calls an
    // API ESLint 10 removed, and its `eslint >=9` peer range wrongly admits 10. `<17`
    // assumes the next major fixes it: revisit when eslint-config-next 17 ships.
    ecosystem: 'npm',
    subject: 'eslint',
    subjectBroken: '>=10',
    subjectFallback: '<10',
    with: 'eslint-config-next',
    withRange: '<17',
    reason:
      "eslint-config-next ≤16's vendored plugin calls an API ESLint 10 removed (crashes at lint time; the upstream eslint peer range doesn't exclude 10)",
  },
];

export interface ComboHold {
  combo: KnownBadCombo;
  /** The pair member (at its recommended version) that triggered the hold. */
  withVersion: string;
  /** Newest known-good subject release that installs on the target (undefined = none found). */
  fallback?: string;
  /** Lowest broken subject release — the auto-updater ignore boundary. */
  firstBad: string;
}

/** Ascending non-prerelease releases (npm only — a PyPI combo would need the pep440 twin). */
function orderedNpmReleases(
  meta: RuntimeMeta,
): { version: string; constraint: string | null; key: SemVer }[] {
  const out: { version: string; constraint: string | null; key: SemVer }[] = [];
  for (const [version, constraint] of Object.entries(meta.constraints)) {
    const v = parseSemver(version);
    if (!v || isPrereleaseSemver(v)) continue;
    out.push({ version, constraint, key: v });
  }
  out.sort((a, b) => compareSemver(a.key, b.key));
  return out;
}

/**
 * Which planned packages must be held back because a known-bad pair is present?
 * Conservative on purpose: a combo fires only when BOTH recommended versions *provably*
 * sit in the broken ranges — `satisfies` must return `true`; its `undefined` "can't
 * tell" answer never triggers a hold. The fallback must still install on the plan's
 * target runtime; when no fallback exists the hold is reported without one (the caller
 * warns instead of downgrading blindly).
 */
export function findComboHolds(
  recommendations: ReadonlyMap<string, string | undefined>,
  metaFor: (name: string) => RuntimeMeta | undefined,
  target: RuntimeTarget,
  ecosystem: Ecosystem,
): Map<string, ComboHold> {
  const holds = new Map<string, ComboHold>();
  for (const combo of KNOWN_BAD_COMBOS) {
    if (combo.ecosystem !== ecosystem || ecosystem !== 'npm') continue;
    if (holds.has(combo.subject)) continue; // first matching combo wins
    const subjectRec = recommendations.get(combo.subject);
    const withRec = recommendations.get(combo.with);
    if (!subjectRec || !withRec) continue;
    if (satisfies(subjectRec, combo.subjectBroken) !== true) continue;
    if (satisfies(withRec, combo.withRange) !== true) continue;

    const releases = orderedNpmReleases(metaFor(combo.subject) ?? { constraints: {} });
    const firstBad = releases.find((r) => satisfies(r.version, combo.subjectBroken) === true)?.version;
    if (!firstBad) continue; // no version list to reason about — do nothing rather than guess

    let fallback: string | undefined;
    for (const r of releases) {
      if (satisfies(r.version, combo.subjectFallback) !== true) continue;
      if (r.constraint !== null && rangeAdmitsSeries(r.constraint, target.version) === false) continue;
      fallback = r.version; // ascending order → ends at the newest qualifying release
    }
    holds.set(combo.subject, { combo, withVersion: withRec, fallback, firstBad });
  }
  return holds;
}
