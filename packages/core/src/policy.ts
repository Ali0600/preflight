import { existsSync, readFileSync } from 'node:fs';

import { licenseRisk } from './license';
import { runtimeLabel } from './verdict';
import type { Finding, RuntimeName } from './types';

// A policy turns Preflight's signals into a configurable gate. It's the same engine the CLI
// (`--policy`) and the Action (`policy-file`) share — so "what fails the build" lives in one place.

export interface Policy {
  failOn?: {
    /** Vulnerability threshold: 'cve' (any), 'kev' (confirmed-exploited), 'epss:<0-1>'. Malware always fails. */
    vuln?: string;
    /** Fail if a dependency runs an install script. */
    installScript?: boolean;
    /** Fail if a dependency's name looks like a typosquat of a popular package. */
    suspiciousName?: boolean;
    /** Fail on these license ids, or the buckets "copyleft" / "unknown". */
    license?: string[];
    /** Fail if a direct dependency's OpenSSF health score is below this (0–10). */
    minHealth?: number;
    /** Fail on runtime incompatibility: 'incompatible' = the range/locked version cannot
     * install on the target runtime; 'latest-dropped' also fails when the newest release
     * dropped it (the next auto-bump would break). */
    runtime?: 'incompatible' | 'latest-dropped';
  };
  /** Adjudicated exemptions from `failOn`: a package name ("esbuild" — any version), an exact
   * pin ("esbuild@0.28.1" — stops applying on the next bump), or an advisory id ("GHSA-…",
   * "CVE-…" — that advisory stops counting toward the vuln rule). Lets a strict gate stay on
   * for everything else instead of being red forever on findings nobody can act on (e.g.
   * legitimate native-binary install scripts, a CVE vendored by the framework).
   * Malicious packages are NEVER exempt. */
  allow?: string[];
  /** Target runtimes the manifest must install on, e.g. { "python": "3.9", "node": "18" }.
   * Shared config-file home for the CLI/Action (flags override). */
  runtimes?: Partial<Record<RuntimeName, string>>;
}

export interface Violation {
  rule: string;
  dep: string;
  detail: string;
}

/** Whether a finding's vulnerabilities meet the threshold. Malware always qualifies; shared with
 * the Action's PR gate so "cve/kev/epss:x" means the same thing everywhere. */
export function meetsVulnLevel(f: Finding, level: string): boolean {
  if (f.verdict === 'malware') return true;
  if (f.verdict !== 'cve') return false;
  if (level === 'kev') return f.vulns.some((v) => v.kev);
  if (level.startsWith('epss:')) {
    const t = Number(level.slice(5)) || 0;
    return f.vulns.some((v) => v.kev || (v.epss ?? 0) >= t);
  }
  return true; // 'cve' (default)
}

function licenseDenied(license: string, deny: string[]): boolean {
  const risk = licenseRisk(license);
  return deny.some((d) => {
    const dl = d.toLowerCase();
    if (dl === 'copyleft' || dl === 'unknown') return risk === dl;
    return license.toLowerCase() === dl;
  });
}

/** Advisory-id shapes an `allow` entry can name (a bare "MAL-…" is deliberately NOT allowable). */
const ADVISORY_ID = /^(GHSA|CVE|PYSEC|OSV|RUSTSEC|GO)-/i;

/** All violations of `rules` for one finding, judging the vuln rule against `vulns`
 * (the caller may have filtered allow-listed advisories out of it). */
function ruleViolations(f: Finding, rules: NonNullable<Policy['failOn']>, vulns: Finding['vulns']): Violation[] {
  const at = `${f.name}@${f.version ?? f.range}`;
  const out: Violation[] = [];
  if (rules.vuln && vulns.length > 0 && meetsVulnLevel({ ...f, vulns }, rules.vuln)) {
    out.push({ rule: 'vuln', dep: at, detail: f.reason });
  }
  if (rules.installScript && f.installScript) {
    out.push({ rule: 'install-script', dep: at, detail: 'runs an install script' });
  }
  if (rules.suspiciousName && f.suspiciousName) {
    out.push({ rule: 'suspicious-name', dep: at, detail: `resembles ${f.suspiciousName.similarTo}` });
  }
  if (rules.license && f.license && licenseDenied(f.license, rules.license)) {
    out.push({ rule: 'license', dep: at, detail: f.license });
  }
  if (
    rules.minHealth !== undefined &&
    f.direct !== false &&
    f.health !== undefined &&
    f.health < rules.minHealth
  ) {
    out.push({ rule: 'min-health', dep: at, detail: `health ${f.health.toFixed(1)} < ${rules.minHealth}` });
  }
  if (rules.runtime && f.runtimeCompat) {
    const rc = f.runtimeCompat;
    const broken = rc.rangeUnsatisfiable || rc.resolvedIncompatible;
    if (broken) {
      out.push({ rule: 'runtime', dep: at, detail: f.reason });
    } else if (rules.runtime === 'latest-dropped' && rc.latestIncompatible) {
      out.push({
        rule: 'runtime',
        dep: at,
        detail: `newest release drops ${runtimeLabel(rc.target)} — the next bump breaks (ignore ${rc.firstIncompatible ?? 'newer versions'}+)`,
      });
    }
  }
  return out;
}

/** Evaluate a policy against findings → violations, whether the gate should fail, and how many
 * would-be violations the `allow` list suppressed (so an exemption is visible, never silent). */
export function evaluatePolicy(
  findings: Finding[],
  policy: Policy,
): { violations: Violation[]; fail: boolean; suppressed: number } {
  const rules = policy.failOn ?? {};
  const allowPkgs = new Set<string>();
  const allowAdvisories = new Set<string>();
  for (const raw of policy.allow ?? []) {
    const entry = raw.trim();
    if (!entry) continue;
    if (ADVISORY_ID.test(entry)) allowAdvisories.add(entry.toUpperCase());
    else allowPkgs.add(entry);
  }

  const violations: Violation[] = [];
  let suppressed = 0;
  for (const f of findings) {
    const at = `${f.name}@${f.version ?? f.range}`;
    // Malware fails unconditionally — independent of failOn rules and immune to `allow`.
    if (f.verdict === 'malware') {
      violations.push({ rule: 'malware', dep: at, detail: f.reason });
      continue;
    }
    const wouldFire = ruleViolations(f, rules, f.vulns);
    if (allowPkgs.has(f.name) || allowPkgs.has(at)) {
      suppressed += wouldFire.length;
      continue;
    }
    const liveVulns = f.vulns.filter(
      (v) => !(allowAdvisories.has(v.id.toUpperCase()) || (v.cve && allowAdvisories.has(v.cve.toUpperCase()))),
    );
    const fired = liveVulns.length === f.vulns.length ? wouldFire : ruleViolations(f, rules, liveVulns);
    suppressed += wouldFire.length - fired.length;
    violations.push(...fired);
  }
  return { violations, fail: violations.length > 0, suppressed };
}

/** Does this policy need latest-version / health / runtime data to be evaluated? (drives fetches) */
export function policyNeeds(policy: Policy): { latest: boolean; health: boolean; runtime: boolean } {
  const r = policy.failOn ?? {};
  return {
    latest: Boolean(r.license),
    health: r.minHealth !== undefined,
    runtime: r.runtime !== undefined,
  };
}

/** Load a JSON policy file, or an empty policy when the file is absent. */
export function loadPolicy(path: string): Policy {
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, 'utf8')) as Policy;
}
