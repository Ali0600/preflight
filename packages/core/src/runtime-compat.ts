import {
  comparePep440,
  isPrereleasePep440,
  parsePep440,
  specifierAdmits,
  specifierAdmitsSeries,
} from './pep440';
import type { RuntimeMeta } from './runtimes';
import {
  compareSemver,
  isPrereleaseSemver,
  parseSemver,
  rangeAdmitsSeries,
  satisfies,
} from './semver';
import type { Ecosystem, RuntimeCompat, RuntimeTarget } from './types';

// The shared computation behind both the scan-time runtime check and `preflight plan`:
// given a package's per-version runtime constraints and a target runtime, work out
// whether the declared range / locked version / latest release still install there,
// and where the compatibility boundary sits (for floors and auto-updater ignores).

interface Ordered {
  version: string;
  constraint: string | null;
}

/** Versions ordered ascending, prereleases excluded (a floor of "0.49.0b1" helps no one). */
function orderedReleases(meta: RuntimeMeta, ecosystem: Ecosystem): Ordered[] {
  const out: { version: string; constraint: string | null; key: unknown }[] = [];
  for (const [version, constraint] of Object.entries(meta.constraints)) {
    if (ecosystem === 'npm') {
      const v = parseSemver(version);
      if (!v || isPrereleaseSemver(v)) continue;
      out.push({ version, constraint, key: v });
    } else {
      const v = parsePep440(version);
      if (!v || isPrereleasePep440(v)) continue;
      out.push({ version, constraint, key: v });
    }
  }
  out.sort((a, b) =>
    ecosystem === 'npm'
      ? compareSemver(a.key as never, b.key as never)
      : comparePep440(a.key as never, b.key as never),
  );
  return out.map(({ version, constraint }) => ({ version, constraint }));
}

/** Does this version's constraint admit the target series? Unknown/unparseable -> true. */
function admits(constraint: string | null, target: RuntimeTarget, ecosystem: Ecosystem): boolean {
  if (constraint === null) return true;
  const r =
    ecosystem === 'npm'
      ? rangeAdmitsSeries(constraint, target.version)
      : specifierAdmitsSeries(constraint, target.version);
  return r !== false;
}

/** Does this version satisfy the manifest's declared range? Unknown -> true. */
function inRange(version: string, range: string, ecosystem: Ecosystem): boolean {
  const r = range.trim();
  if (r === '' || r === '*' || r === 'latest') return true;
  const result = ecosystem === 'npm' ? satisfies(version, r) : specifierAdmits(r, version);
  return result !== false;
}

/**
 * Compute how a dependency relates to a target runtime. Returns `undefined` when
 * everything is compatible (keeps findings clean) or when there is no usable metadata.
 */
export function computeRuntimeCompat(
  dep: { range: string; version?: string },
  meta: RuntimeMeta,
  target: RuntimeTarget,
  ecosystem: Ecosystem,
): RuntimeCompat | undefined {
  const releases = orderedReleases(meta, ecosystem);
  if (releases.length === 0) return undefined;

  let maxCompatible: string | undefined;
  for (const r of releases) {
    if (admits(r.constraint, target, ecosystem)) maxCompatible = r.version;
  }

  // The boundary: the first release above maxCompatible (everything above it is
  // incompatible, since maxCompatible is the *highest* compatible release).
  let firstIncompatible: string | undefined;
  let constraint: string | undefined;
  if (maxCompatible !== undefined) {
    const idx = releases.findIndex((r) => r.version === maxCompatible);
    const next = releases[idx + 1];
    if (next) {
      firstIncompatible = next.version;
      constraint = next.constraint ?? undefined;
    }
  } else {
    // Nothing installs on this target at all — report the oldest release's constraint.
    firstIncompatible = releases[0].version;
    constraint = releases[0].constraint ?? undefined;
  }

  const inRangeReleases = releases.filter((r) => inRange(r.version, dep.range, ecosystem));
  const rangeUnsatisfiable =
    inRangeReleases.length > 0 &&
    !inRangeReleases.some((r) => admits(r.constraint, target, ecosystem));

  const resolved = dep.version ? releases.find((r) => r.version === dep.version) : undefined;
  const resolvedIncompatible =
    resolved !== undefined && !admits(resolved.constraint, target, ecosystem);

  const latest = meta.latest ?? releases[releases.length - 1]?.version;
  const latestRelease = releases.find((r) => r.version === latest);
  const latestIncompatible =
    latestRelease !== undefined && !admits(latestRelease.constraint, target, ecosystem);

  if (!rangeUnsatisfiable && !resolvedIncompatible && !latestIncompatible) return undefined;
  return {
    target,
    rangeUnsatisfiable,
    resolvedIncompatible,
    latestIncompatible,
    maxCompatible,
    firstIncompatible,
    constraint,
  };
}
