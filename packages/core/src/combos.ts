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
  {
    // `@types/react@19` declares `peerDependencies: {}` — verified 2026-08-18 — so NOTHING ties
    // it to a React version and npm/Dependabot see no conflict when it is bumped alone. But the
    // v19 types removed the global JSX namespace, made `useRef` require an initial argument, and
    // deleted `React.VFC`/`ReactText`/`ReactChild` (DefinitelyTyped discussion #64451), so a
    // React 18 codebase stops type-checking. The purest form of what this registry is for: no
    // metadata anywhere in the ecosystem can express it.
    ecosystem: 'npm',
    subject: '@types/react',
    subjectBroken: '>=19',
    subjectFallback: '<19',
    with: 'react',
    withRange: '<19',
    reason:
      '@types/react 19 dropped the global JSX namespace and requires a useRef argument — React 18 code stops compiling (the types package declares no peer range, so nothing blocks the bump)',
  },
  {
    // Same story for the DOM types, which are bumped as a pair with @types/react.
    ecosystem: 'npm',
    subject: '@types/react-dom',
    subjectBroken: '>=19',
    subjectFallback: '<19',
    with: 'react-dom',
    withRange: '<19',
    reason:
      '@types/react-dom 19 targets the React 19 client/server APIs — React 18 code stops compiling (the types package declares no peer range, so nothing blocks the bump)',
  },
];

/** A known-bad pair found in a manifest that is already installed (as opposed to `plan`, which
 * reasons about versions it is about to recommend). */
export interface ComboConflict {
  /** The other half of the pair, `name@version`. */
  with: string;
  reason: string;
}

/**
 * Which installed packages sit in a known-bad pair? Strict on purpose, exactly like
 * `findComboHolds`: BOTH halves must *provably* satisfy their broken ranges (`satisfies === true`),
 * so an unparseable version — which returns `undefined`, "can't tell" — never raises a conflict.
 *
 * Takes resolved versions only. A range like `^18.0.0` is not a fact about what is installed, and
 * guessing from it would fire on trees that resolved to something safe.
 */
export function findComboConflicts(
  deps: readonly { name: string; version?: string; direct?: boolean }[],
  ecosystem: Ecosystem,
): Map<string, ComboConflict> {
  const found = new Map<string, ComboConflict>();
  // Fast path today (every entry below is npm) AND the reason the per-combo `ecosystem` filter
  // is currently unexercised — a test pins that assumption, so adding a non-npm entry fails
  // loudly here rather than silently skipping it.
  if (ecosystem !== 'npm') return found;
  // Only packages a human chose: you cannot fix a known-bad pair buried in someone else's
  // transitive tree by editing your manifest, so reporting it there is noise.
  const versionOf = new Map<string, string>();
  for (const d of deps) {
    if (d.direct === false || !d.version) continue;
    if (!versionOf.has(d.name)) versionOf.set(d.name, d.version);
  }
  for (const combo of KNOWN_BAD_COMBOS) {
    if (combo.ecosystem !== ecosystem) continue;
    if (found.has(combo.subject)) continue; // first matching combo wins
    const subjectVersion = versionOf.get(combo.subject);
    const withVersion = versionOf.get(combo.with);
    if (!subjectVersion || !withVersion) continue;
    if (satisfies(subjectVersion, combo.subjectBroken) !== true) continue;
    if (satisfies(withVersion, combo.withRange) !== true) continue;
    found.set(combo.subject, { with: `${combo.with}@${withVersion}`, reason: combo.reason });
  }
  return found;
}

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
