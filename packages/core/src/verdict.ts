import type { Finding, RuntimeCompat, RuntimeTarget, Severity, Vuln } from './types';

const RANK: Record<Severity, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** A dep is "stale" only when it's both behind by a major *and* hasn't shipped in this long. */
const STALE_AGE_MS = 365 * 24 * 60 * 60 * 1000;

function worst(vulns: Vuln[]): Severity {
  return vulns.reduce<Severity>((acc, v) => (RANK[v.severity] > RANK[acc] ? v.severity : acc), 'unknown');
}

/** A short exploitability note for a CVE reason: confirmed-exploited (KEV) beats predicted (EPSS). */
function exploitTail(vulns: Vuln[]): string {
  if (vulns.some((v) => v.kev)) return ' · actively exploited (KEV)';
  const maxEpss = Math.max(0, ...vulns.map((v) => v.epss ?? 0));
  return maxEpss >= 0.1 ? ` · EPSS ${maxEpss.toFixed(2)}` : '';
}

/** Leading major version from a resolved version or a range (e.g. "^1.2.0" -> 1, "0.85.3" -> 0). */
function majorOf(spec: string | undefined): number | undefined {
  const m = spec?.match(/\d+/);
  return m ? Number(m[0]) : undefined;
}

/** Whole years since an ISO timestamp, for human-readable reasons. */
function yearsSince(iso: string): number {
  return (Date.now() - new Date(iso).getTime()) / (365 * 24 * 60 * 60 * 1000);
}

/** "Node 18" / "Python 3.9", with where the target came from when it was auto-detected. */
export function runtimeLabel(t: RuntimeTarget, withSource = false): string {
  const name = t.runtime === 'node' ? 'Node' : 'Python';
  const src = withSource && !t.explicit ? ` (${t.source})` : '';
  return `${name} ${t.version}${src}`;
}

/** Why the boundary version excludes the target: pip's Requires-Python is a hard install
 * failure; npm engines is advisory (enforced only under engine-strict), so word it softer. */
function constraintPhrase(rc: RuntimeCompat): string {
  if (!rc.firstIncompatible || !rc.constraint) return '';
  const verb = rc.target.runtime === 'python' ? 'requires Python' : 'declares engines node';
  return ` (${rc.firstIncompatible}+ ${verb} ${rc.constraint})`;
}

function incompatibleReason(f: Omit<Finding, 'verdict' | 'reason'>, rc: RuntimeCompat): string {
  const max = rc.maxCompatible ? ` — max compatible ${rc.maxCompatible}` : '';
  const tail = f.lockstep.pinned
    ? ` · framework-pinned (${f.lockstep.framework}) — fix via ${f.lockstep.tool}`
    : '';
  if (rc.rangeUnsatisfiable) {
    return `No version in "${f.range}" installs on ${runtimeLabel(rc.target, true)}${constraintPhrase(rc)}${max}${tail}`;
  }
  return `Locked ${f.version} does not install on ${runtimeLabel(rc.target, true)}${constraintPhrase(rc)}${max}${tail}`;
}

/** True when the dep is ≥1 major behind `latest` and its last publish is older than the cutoff. */
function isStale(f: Omit<Finding, 'verdict' | 'reason'>): boolean {
  if (!f.latest || !f.lastPublish) return false;
  const current = majorOf(f.version ?? f.range);
  const latest = majorOf(f.latest);
  if (current === undefined || latest === undefined || latest <= current) return false;
  const published = new Date(f.lastPublish).getTime();
  return Number.isFinite(published) && Date.now() - published > STALE_AGE_MS;
}

/** Decide the auto-update verdict for one dependency from its CVEs + lockstep + freshness. */
export function decideVerdict(f: Omit<Finding, 'verdict' | 'reason'>): {
  verdict: Finding['verdict'];
  reason: string;
} {
  if (f.vulns.some((v) => v.malicious)) {
    return {
      verdict: 'malware',
      reason: 'Known-malicious package (OSV MAL advisory) — remove immediately',
    };
  }
  if (f.vulns.length > 0) {
    const tail = f.lockstep.pinned
      ? ` · framework-pinned (${f.lockstep.framework}) — fix via ${f.lockstep.tool}`
      : '';
    return {
      verdict: 'cve',
      reason: `${f.vulns.length} advisory · ${worst(f.vulns)}${exploitTail(f.vulns)}${tail}`,
    };
  }
  // An uninstallable dep outranks lockstep/staleness: it is primarily broken. Only the
  // range/locked cases decide the verdict — `latestIncompatible` alone is a warning line
  // in the renderers, not a verdict (today's install still works).
  if (f.runtimeCompat?.rangeUnsatisfiable || f.runtimeCompat?.resolvedIncompatible) {
    return { verdict: 'incompatible', reason: incompatibleReason(f, f.runtimeCompat) };
  }
  if (f.lockstep.pinned) {
    return {
      verdict: 'pinned',
      reason: `Framework-pinned (${f.lockstep.framework}) — update via ${f.lockstep.tool}`,
    };
  }
  if (isStale(f)) {
    const behind = majorOf(f.latest)! - majorOf(f.version ?? f.range)!;
    const age = yearsSince(f.lastPublish!).toFixed(1);
    return {
      verdict: 'stale',
      reason: `${behind} major behind latest (${f.latest}) · last published ${age}y ago`,
    };
  }
  return { verdict: 'safe', reason: 'Independent — safe to auto-update (CI-gated)' };
}
